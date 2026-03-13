"""
Investigation Pipeline

Single entry point that ties everything together:
  BlockchainAdapter → ConfidenceEngine → AttributionLookup → InvestigationChain

Replaces the ad-hoc orchestration that was spread across the API endpoint
and the test scripts. All callers (API, CLI, test harness) use this.

Usage:
    # With live Blockstream API
    pipeline = InvestigationPipeline(
        adapter=BlockstreamAdapter(),
        attribution=AttributionLookup(repo),
    )
    result = pipeline.run("fraud_txid_here", "1FraudAddress", max_hops=5)

    # With fixtures (offline)
    pipeline = InvestigationPipeline(
        adapter=FixtureAdapter("eval/fixtures/"),
        attribution=AttributionLookup(repo),
    )
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from src.investigation.adapters import BlockchainAdapter, TxData
from src.investigation.attribution_db import AttributionLookup, EntityType
from src.investigation.confidence_engine import (
    ConfidenceLevel,
    InvestigationChain,
    TracingHop,
    build_direct_utxo_hop,
    build_exchange_hop,
    build_temporal_hop,
    MINER_FEE_TOLERANCE_BTC,
    THRESHOLD_HIGH_CONF_SEC,
)
from src.investigation.peeling_chain import (
    PeelingChainDetector,
    PeelingChainResult,
    TxStructure,
    analyse_chain_for_peeling,
)
from src.investigation.report_generator import generate_report
from src.investigation.cio_engine import CioEngine, AddressAttribution

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class InvestigationResult:
    chain: InvestigationChain
    peeling: PeelingChainResult
    report_hash: Optional[str] = None
    pdf_path: Optional[str] = None

    @property
    def summary(self) -> dict:
        return {
            "case_id":              self.chain.case_id,
            "fraud_txid":           self.chain.fraud_txid,
            "fraud_address":        self.chain.fraud_address,
            "fraud_amount_btc":     str(self.chain.fraud_amount_btc),
            "total_hops":           len(self.chain.hops),
            "official_hops":        len(self.chain.official_report_hops),
            "exchange_hits":        [h.exchange_name for h in self.chain.exchange_hits],
            "is_sanctioned":        any(h.is_sanctioned for h in self.chain.hops
                                        if hasattr(h, "is_sanctioned")),
            "peeling_detected":     self.peeling.detected,
            "peeling_hops":         self.peeling.chain_length if self.peeling.detected else 0,
            "chain_confidence":     self.chain.minimum_confidence.name
                                    if self.chain.minimum_confidence else "NONE",
            "report_hash":          self.report_hash,
            "pdf_path":             self.pdf_path,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class InvestigationPipeline:
    """
    Orchestrates the full investigation from a fraud TXID to a signed report.
    Adapter-agnostic: works with Blockstream, Fixtures, or PostgreSQL.
    """

    def __init__(
        self,
        adapter: BlockchainAdapter,
        attribution: AttributionLookup,
        cio_engine: Optional[CioEngine] = None,
    ):
        self._adapter    = adapter
        self._attr       = attribution
        self._peeling    = PeelingChainDetector()
        self._cio        = cio_engine   # None = CIO deaktiviert

    def run(
        self,
        fraud_txid: str,
        fraud_address: str,
        max_hops: int = 5,
        case_id: Optional[str] = None,
        pdf_output_path: Optional[str] = None,
    ) -> InvestigationResult:
        """
        Full pipeline:
          1. Fetch TX chain via adapter
          2. Classify each hop (confidence engine)
          3. Auto-lookup every address against attribution DB
          4. Detect peeling chain pattern
          5. Optionally generate PDF report
        """
        import uuid
        if not case_id:
            case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

        # ── Step 1: Fetch TX chain ───────────────────────────────────────
        logger.info(f"[{case_id}] Tracing from {fraud_txid[:16]}...")
        tx_chain = self._adapter.trace_hops(fraud_txid, max_hops=max_hops)

        if not tx_chain:
            raise ValueError(f"Transaction {fraud_txid} not found. "
                             "Ensure it has been ingested or is accessible via adapter.")

        # ── Step 2: Build InvestigationChain ────────────────────────────
        fraud_tx = tx_chain[0]
        fraud_amount_btc = Decimal(
            fraud_tx.dominant_output["value_sat"]
        ) / Decimal("100000000") if fraud_tx.dominant_output else Decimal("0")

        chain = InvestigationChain(
            case_id=case_id,
            fraud_txid=fraud_txid,
            fraud_address=fraud_address,
            fraud_amount_btc=fraud_amount_btc,
            fraud_timestamp=fraud_tx.timestamp or datetime.now(timezone.utc),
        )

        # ── Step 3a: CIO-Cluster-Analyse aller TX im Chain ─────────────
        # Läuft vor dem Hop-Aufbau damit Exchange-Attributionen via CIO
        # bereits verfügbar sind wenn _build_hop sie braucht.
        if self._cio is not None:
            for tx in tx_chain:
                input_addrs   = [i.get("address") for i in tx.inputs if i.get("address")]
                output_values = [o.get("value_sat", 0) for o in tx.outputs]
                if len(input_addrs) >= 1:
                    self._cio.process_tx_with_addresses(
                        txid=tx.txid,
                        input_addresses=input_addrs,
                        output_values=output_values,
                    )

        # ── Step 3b: Build hops with attribution auto-lookup ────────────
        tx_structures = []  # for peeling analysis
        for i in range(len(tx_chain) - 1):
            src = tx_chain[i]
            dst = tx_chain[i + 1]
            hop = self._build_hop(i + 1, src, dst, chain)
            if hop:
                chain.add_hop(hop)

            # Collect TxStructure for peeling detector
            tx_structures.append(self._to_tx_structure(src))

        # Include last TX in peeling analysis
        if len(tx_chain) > 0:
            tx_structures.append(self._to_tx_structure(tx_chain[-1]))

        logger.info(f"[{case_id}] Built {len(chain.hops)} hops, "
                    f"{len(chain.official_report_hops)} report-eligible.")

        # ── Step 4: Peeling chain detection ─────────────────────────────
        peeling = self._peeling.analyse(tx_structures, fraud_amount_btc)
        if peeling.detected:
            logger.info(f"[{case_id}] Peeling chain detected: "
                        f"{peeling.chain_length} hops, signals: "
                        f"{[s.value for s in peeling.signals_summary]}")

        # ── Step 5: Generate PDF if path given ──────────────────────────
        report_hash = None
        if pdf_output_path:
            report_hash = generate_report(
                chain, pdf_output_path,
                peeling_result=peeling if peeling.detected else None,
            )
            logger.info(f"[{case_id}] PDF saved: {pdf_output_path} (hash: {report_hash[:16]}...)")

        # ── Step 6: CIO Flywheel — bestätigte Exchange-Hits speichern ──
        if self._cio is not None:
            for hit in chain.exchange_hits:
                if hit.to_address and hit.exchange_name:
                    self._cio.confirm_exchange_hit(
                        address=hit.to_address,
                        entity_name=hit.exchange_name,
                        entity_type="EXCHANGE",
                        case_id=case_id,
                        txid=hit.to_txid,
                    )
            if chain.exchange_hits:
                logger.info(
                    f"[{case_id}] CIO Flywheel: {len(chain.exchange_hits)} "
                    f"Exchange-Hit(s) gespeichert und auf Cluster propagiert"
                )

        return InvestigationResult(
            chain=chain,
            peeling=peeling,
            report_hash=report_hash,
            pdf_path=pdf_output_path,
        )

    # -----------------------------------------------------------------------
    # Hop builder — attribution auto-lookup wired in here
    # -----------------------------------------------------------------------

    def _build_hop(
        self,
        hop_index: int,
        src: TxData,
        dst: TxData,
        chain: InvestigationChain,
    ) -> Optional[TracingHop]:

        dominant = src.dominant_output
        if not dominant:
            return None

        amount_btc   = Decimal(dominant["value_sat"]) / Decimal("100000000")
        from_address = src.inputs[0].get("address") if src.inputs else None

        # The destination address is the receiving address of the NEXT TX
        # (i.e. where the dominant output of src lands in dst)
        dst_dominant = dst.dominant_output
        to_address   = dst_dominant.get("address") if dst_dominant else dominant.get("address")

        ts_from = src.timestamp or datetime.now(timezone.utc)
        ts_to   = dst.timestamp or datetime.now(timezone.utc)
        bh_from = src.block_height or 0
        bh_to   = dst.block_height or 0

        # ── Attribution auto-lookup (direkte DB + CIO-Cluster) ─────────
        attr      = self._attr.lookup(to_address) if to_address else None
        cio_attr  = None

        # CIO-Attribution als Ergänzung wenn CIO-Engine aktiv
        if self._cio is not None and to_address:
            cio_result = self._cio.attribute_address(to_address)
            if cio_result.found:
                cio_attr = cio_result

        # Bestes Ergebnis: direkte DB-Attribution hat Vorrang vor CIO
        entity_name   = None
        entity_type   = None
        entity_source = None

        if attr:
            entity_name   = attr.entity_name
            entity_type   = attr.entity_type.value
            entity_source = f"{attr.source_display_name} ({attr.source_key})"
            logger.info(f"  Hop {hop_index}: {(to_address or '')[:20]}... → {entity_name} "
                        f"(direkt, {attr.source_key})")
        elif cio_attr and cio_attr.best_entity:
            entity_name   = cio_attr.best_entity
            entity_type   = cio_attr.best_entity_type
            entity_source = f"CIO-Cluster ({cio_attr.attribution_method})"
            logger.info(f"  Hop {hop_index}: {(to_address or '')[:20]}... → {entity_name} "
                        f"(CIO-Cluster, Konfidenz L{cio_attr.best_confidence})")

        EXCHANGE_TYPES = {"EXCHANGE", "SANCTIONED", "DARKNET", "MIXER"}
        if entity_name and entity_type and entity_type.upper() in EXCHANGE_TYPES:
            prev = chain.hops[-1] if chain.hops else _dummy_prev_hop(
                src.txid, from_address, ts_from, bh_from
            )
            return build_exchange_hop(
                hop_index=hop_index,
                txid=dst.txid,
                address=to_address,
                amount_btc=amount_btc,
                exchange_name=entity_name,
                exchange_source=entity_source,
                block_height=bh_to,
                timestamp=ts_to,
                previous_hop=prev,
            )

        # ── Direct UTXO link ─────────────────────────────────────────────
        # Verify: dst actually spends src's dominant output
        spent_by = dominant.get("spent_by_txid")
        if spent_by and spent_by == dst.txid:
            return build_direct_utxo_hop(
                hop_index=hop_index,
                from_txid=src.txid,
                to_txid=dst.txid,
                from_address=from_address,
                to_address=to_address,
                amount_btc=amount_btc,
                block_height_from=bh_from,
                block_height_to=bh_to,
                timestamp_from=ts_from,
                timestamp_to=ts_to,
            )

        # ── Temporal amount match ─────────────────────────────────────────
        dst_dominant = dst.dominant_output
        if dst_dominant:
            dst_amount = Decimal(dst_dominant["value_sat"]) / Decimal("100000000")
            time_delta = int((ts_to - ts_from).total_seconds())
            amount_diff = abs(amount_btc - dst_amount)

            if amount_diff <= MINER_FEE_TOLERANCE_BTC:
                return build_temporal_hop(
                    hop_index=hop_index,
                    from_txid=src.txid,
                    to_txid=dst.txid,
                    from_address=from_address,
                    to_address=dst_dominant.get("address"),
                    amount_in=amount_btc,
                    amounts_out=[dst_amount],
                    block_height_from=bh_from,
                    block_height_to=bh_to,
                    timestamp_from=ts_from,
                    timestamp_to=ts_to,
                )

        logger.debug(f"  Hop {hop_index}: no matching strategy — skipped.")
        return None

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _to_tx_structure(tx: TxData) -> TxStructure:
        dominant = tx.dominant_output
        change   = min(tx.outputs, key=lambda o: o["value_sat"]) if tx.outputs else None
        return TxStructure(
            txid=tx.txid,
            input_count=tx.input_count,
            output_count=tx.output_count,
            total_input_sat=sum(i.get("value_sat", 0) for i in tx.inputs),
            outputs=tx.outputs,
            block_height=tx.block_height or 0,
            timestamp=tx.timestamp or datetime.now(timezone.utc),
            dominant_output_sat=dominant["value_sat"] if dominant else 0,
            change_output_sat=change["value_sat"] if change else 0,
        )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _dummy_prev_hop(txid, address, timestamp, block_height) -> TracingHop:
    from src.investigation.confidence_engine import TracingMethod
    return TracingHop(
        hop_index=0,
        from_txid=txid, to_txid=txid,
        from_address=address, to_address=address,
        amount_btc=Decimal("0"),
        method=TracingMethod.UTXO_DIRECT,
        confidence=ConfidenceLevel.L1_VERIFIED_FACT,
        block_height_from=block_height, block_height_to=block_height,
        timestamp_from=timestamp, timestamp_to=timestamp,
    )
