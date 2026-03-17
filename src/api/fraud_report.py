"""
Fraud Investigation API — Core Tracing Engine + FastAPI Endpoint

Pipeline:
  1. Request kommt rein (fraud_txid + fraud_address)
  2. TraceEngine lädt TX-Daten aus PostgreSQL (bereits ingested)
  3. Für jeden Hop: Confidence Engine klassifiziert
  4. Attribution DB schlägt jede Adresse nach
  5. InvestigationChain wird aufgebaut
  6. Report Generator erzeugt PDF
  7. Response: JSON-Summary + PDF-Download-Link

Integration:
  - Füge den Router in deine bestehende main.py ein:
      from src.api.fraud_report import router as fraud_router
      app.include_router(fraud_router)
  - Nutzt deine bestehende get_db() Dependency
"""

from __future__ import annotations

import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from src.investigation.confidence_engine import (
    ConfidenceLevel,
    InvestigationChain,
    TracingHop,
    build_direct_utxo_hop,
    build_exchange_hop,
    build_temporal_hop,
)
from src.investigation.attribution_db import AttributionLookup, AttributionRepository
from src.investigation.report_generator import generate_report

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/intel", tags=["fraud-investigation"])

# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class FraudReportRequest(BaseModel):
    fraud_txid: str = Field(..., description="TXID der Fraud-Transaktion")
    fraud_address: str = Field(..., description="Absender-Adresse der Fraud-TX")
    max_hops: int = Field(default=5, ge=1, le=10, description="Maximale Hop-Tiefe")
    case_id: Optional[str] = Field(default=None, description="Optionale Fall-ID (auto-generiert wenn leer)")
    persist: bool = Field(default=False, description="Report in DB persistieren")


class HopSummary(BaseModel):
    hop_index: int
    from_address: Optional[str]
    to_address: Optional[str]
    amount_btc: str
    method: str
    confidence_level: int
    confidence_label: str
    time_delta_seconds: Optional[int]
    exchange_name: Optional[str]
    is_official_report_eligible: bool
    caveat: Optional[str]


class FraudReportResponse(BaseModel):
    case_id: str
    fraud_txid: str
    fraud_address: str
    fraud_amount_btc: str
    fraud_timestamp: str
    total_hops_analysed: int
    official_report_hops: int
    chain_confidence: str          # weakest link in official chain
    exchange_hits: list[str]
    is_sanctioned_address: bool
    report_hash: str
    pdf_download_url: str
    hops: list[HopSummary]
    generated_at: str


# ---------------------------------------------------------------------------
# Trace Engine — queries your existing PostgreSQL schema
# ---------------------------------------------------------------------------

class TraceEngine:
    """
    Queries the existing blockchain tables to trace UTXO flows.

    Expected schema (from your 001_init.sql):
      - transactions (txid, block_height, first_seen, ...)
      - tx_inputs    (txid, prev_txid, prev_vout, address, value_sat)
      - tx_outputs   (txid, vout, address, value_sat, spent_by_txid)
    """

    # Direct UTXO: find TXs that spend outputs of a given TX
    DIRECT_SPEND_SQL = """
        SELECT
            o.txid          AS from_txid,
            o.address       AS from_address,
            o.amount_sats     AS value_sat,
            o.spent_by_txid AS to_txid,
            i.address       AS to_address,
            t_to.block_height AS to_block,
            t_to.first_seen   AS to_time,
            t_from.block_height AS from_block,
            t_from.first_seen   AS from_time
        FROM tx_outputs o
        JOIN transactions t_from ON t_from.txid = o.txid
        JOIN transactions t_to   ON t_to.txid = o.spent_by_txid
        LEFT JOIN tx_inputs i    ON i.txid = o.spent_by_txid
                                 AND i.prev_txid = o.txid
                                 AND i.prev_vout = o.vout
        WHERE o.txid = %s
          AND o.spent_by_txid IS NOT NULL
        LIMIT %s;
    """

    # Amount match: find TXs in a time window with matching output amounts
    TEMPORAL_MATCH_SQL = """
        WITH incoming AS (
            SELECT
                o.txid, o.address, o.amount_sats,
                t.block_height, t.first_seen
            FROM tx_outputs o
            JOIN transactions t ON t.txid = o.txid
            WHERE o.address = %s
              AND t.first_seen BETWEEN %s AND %s
        )
        SELECT
            inc.txid          AS from_txid,
            inc.address       AS from_address,
            inc.value_sat     AS from_value_sat,
            inc.block_height  AS from_block,
            inc.first_seen    AS from_time,
            out2.txid         AS to_txid,
            out2.address      AS to_address,
            out2.value_sat    AS to_value_sat,
            t2.block_height   AS to_block,
            t2.first_seen     AS to_time
        FROM incoming inc
        JOIN tx_inputs inp2  ON inp2.prev_txid = inc.txid
        JOIN tx_outputs out2 ON out2.txid = inp2.txid
        JOIN transactions t2 ON t2.txid = inp2.txid
        WHERE ABS(inc.value_sat - out2.value_sat) <= 100000  -- 0.001 BTC tolerance
          AND t2.first_seen >= inc.first_seen
        ORDER BY ABS(inc.value_sat - out2.value_sat) ASC,
                 t2.first_seen ASC
        LIMIT %s;
    """

    # Fetch TX metadata
    TX_META_SQL = """
        SELECT t.txid, t.block_height, t.first_seen, COALESCE(SUM(o.amount_sats), 0) AS value_sat
        FROM transactions t LEFT JOIN tx_outputs o ON o.txid = t.txid
        WHERE t.txid = %s GROUP BY t.txid, t.block_height, t.first_seen;
    """

    # Fetch outputs of a TX
    TX_OUTPUTS_SQL = """
        SELECT vout, address, amount_sats, spent_by_txid
        FROM tx_outputs
        WHERE txid = %s
        ORDER BY vout;
    """

    def __init__(self, conn):
        self._conn = conn

    def get_tx_meta(self, txid: str) -> Optional[dict]:
        with self._conn.cursor() as cur:
            cur.execute(self.TX_META_SQL, (txid,))
            row = cur.fetchone()
            if not row:
                return None
            return {
                "txid": row[0],
                "block_height": row[1],
                "first_seen": row[2],
                "value_sat": row[3],
            }

    def get_tx_outputs(self, txid: str) -> list[dict]:
        with self._conn.cursor() as cur:
            cur.execute(self.TX_OUTPUTS_SQL, (txid,))
            return [
                {"vout": r[0], "address": r[1], "value_sat": r[2], "spent_by_txid": r[3]}
                for r in cur.fetchall()
            ]

    def find_direct_spends(self, txid: str, limit: int = 20) -> list[dict]:
        with self._conn.cursor() as cur:
            cur.execute(self.DIRECT_SPEND_SQL, (txid, limit))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def find_temporal_matches(
        self,
        address: str,
        from_time: datetime,
        window_seconds: int = 21600,  # 6h
        limit: int = 5,
    ) -> list[dict]:
        to_time = from_time.timestamp() + window_seconds
        with self._conn.cursor() as cur:
            cur.execute(self.TEMPORAL_MATCH_SQL, (
                address,
                int(from_time.timestamp()),
                int(to_time),
                limit,
            ))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Investigation Orchestrator — ties everything together
# ---------------------------------------------------------------------------

class InvestigationOrchestrator:
    """
    Drives the full tracing pipeline:
      TraceEngine → ConfidenceEngine → AttributionLookup → InvestigationChain
    """

    def __init__(self, conn, attribution_lookup: AttributionLookup):
        self._trace = TraceEngine(conn)
        self._attr = attribution_lookup

    def run(
        self,
        case_id: str,
        fraud_txid: str,
        fraud_address: str,
        max_hops: int = 5,
    ) -> InvestigationChain:

        # 1. Load fraud TX metadata
        tx_meta = self._trace.get_tx_meta(fraud_txid)
        if not tx_meta:
            raise ValueError(f"Transaction {fraud_txid} not found in database. "
                             "Ensure the block containing this TX has been ingested.")

        fraud_amount = Decimal(tx_meta["value_sat"]) / Decimal("100000000")
        fraud_time = datetime.fromtimestamp(tx_meta["first_seen"], tz=timezone.utc)

        chain = InvestigationChain(
            case_id=case_id,
            fraud_txid=fraud_txid,
            fraud_address=fraud_address,
            fraud_amount_btc=fraud_amount,
            fraud_timestamp=fraud_time,
        )

        # 2. Check fraud address itself against attribution DB
        fraud_attr = self._attr.lookup(fraud_address)
        if fraud_attr and fraud_attr.is_sanctioned:
            logger.warning(f"Fraud address {fraud_address} is OFAC sanctioned!")

        # 3. Trace hops
        current_txids = [fraud_txid]
        visited = set()

        for hop_idx in range(1, max_hops + 1):
            next_txids = []

            for txid in current_txids:
                if txid in visited:
                    continue
                visited.add(txid)

                hop = self._trace_one_hop(txid, hop_idx, chain)
                if hop:
                    chain.add_hop(hop)
                    if hop.to_txid:
                        next_txids.append(hop.to_txid)

            if not next_txids:
                break
            current_txids = next_txids

        return chain

    def _trace_one_hop(
        self,
        from_txid: str,
        hop_idx: int,
        chain: InvestigationChain,
    ) -> Optional[TracingHop]:
        """
        Try tracing strategies in priority order:
        1. Direct UTXO spend (L1)
        2. Temporal amount match (L2/L3)
        Returns first successful hop or None.
        """

        # Strategy 1: Direct UTXO
        spends = self._trace.find_direct_spends(from_txid, limit=5)
        if spends:
            best = spends[0]
            value_sat = best.get("value_sat") or 0
            amount_btc = Decimal(value_sat) / Decimal("100000000")

            from_time = _ts(best.get("from_time"))
            to_time   = _ts(best.get("to_time"))
            to_address = best.get("to_address") or best.get("from_address")

            # Attribution check on destination address
            attr = self._attr.lookup(to_address) if to_address else None

            if attr:
                # Build exchange hop
                return build_exchange_hop(
                    hop_index=hop_idx,
                    txid=best["to_txid"],
                    address=to_address,
                    amount_btc=amount_btc,
                    exchange_name=attr.entity_name,
                    exchange_source=attr.source_display_name,
                    block_height=best.get("to_block", 0),
                    timestamp=to_time,
                    previous_hop=chain.hops[-1] if chain.hops else _dummy_hop(
                        from_txid, best.get("from_address"), from_time,
                        best.get("from_block", 0)
                    ),
                )

            return build_direct_utxo_hop(
                hop_index=hop_idx,
                from_txid=from_txid,
                to_txid=best["to_txid"],
                from_address=best.get("from_address"),
                to_address=to_address,
                amount_btc=amount_btc,
                block_height_from=best.get("from_block", 0),
                block_height_to=best.get("to_block", 0),
                timestamp_from=from_time,
                timestamp_to=to_time,
            )

        # Strategy 2: Temporal match (only if we have a previous hop with address)
        if chain.hops:
            last_hop = chain.hops[-1]
            if last_hop.to_address and last_hop.timestamp_to:
                matches = self._trace.find_temporal_matches(
                    last_hop.to_address,
                    last_hop.timestamp_to,
                    window_seconds=21600,
                    limit=3,
                )
                if matches:
                    m = matches[0]
                    from_val = m.get("from_value_sat", 0)
                    to_val   = m.get("to_value_sat", 0)
                    to_addr  = m.get("to_address")
                    attr = self._attr.lookup(to_addr) if to_addr else None

                    if attr:
                        return build_exchange_hop(
                            hop_index=hop_idx,
                            txid=m["to_txid"],
                            address=to_addr,
                            amount_btc=Decimal(to_val) / Decimal("100000000"),
                            exchange_name=attr.entity_name,
                            exchange_source=attr.source_display_name,
                            block_height=m.get("to_block", 0),
                            timestamp=_ts(m.get("to_time")),
                            previous_hop=last_hop,
                        )

                    return build_temporal_hop(
                        hop_index=hop_idx,
                        from_txid=m["from_txid"],
                        to_txid=m["to_txid"],
                        from_address=m.get("from_address"),
                        to_address=to_addr,
                        amount_in=Decimal(from_val) / Decimal("100000000"),
                        amounts_out=[Decimal(to_val) / Decimal("100000000")],
                        block_height_from=m.get("from_block", 0),
                        block_height_to=m.get("to_block", 0),
                        timestamp_from=_ts(m.get("from_time")),
                        timestamp_to=_ts(m.get("to_time")),
                    )

        return None


# ---------------------------------------------------------------------------
# FastAPI Endpoint
# ---------------------------------------------------------------------------

# In-memory PDF store (replace with S3/filesystem in production)
_pdf_store: dict[str, str] = {}


def get_db():
    """
    Dependency — replace with your existing get_db() implementation.
    Expected: yields a psycopg2 connection.
    """
    import psycopg2
    dsn = os.environ["POSTGRES_DSN"]
    conn = psycopg2.connect(dsn)
    try:
        yield conn
    finally:
        conn.close()


@router.post("/fraud-report", response_model=FraudReportResponse)
async def create_fraud_report(
    req: FraudReportRequest,
    conn=Depends(get_db),
):
    """
    Führt eine vollständige Fraud-Investigation durch und generiert einen
    gerichtsfesten PDF-Report.

    - Traced UTXO-Flüsse bis max_hops Tiefen
    - Klassifiziert jeden Hop mit Confidence Level (L1-L4)
    - Schlägt jede Adresse gegen Attribution DB ab (OFAC, Exchange, etc.)
    - Generiert PDF-Report mit Chain of Custody
    - Gibt JSON-Summary + PDF-Download zurück
    """
    case_id = req.case_id or f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

    try:
        repo = AttributionRepository(conn)
        lookup = AttributionLookup(repo)
        orchestrator = InvestigationOrchestrator(conn, lookup)

        chain = orchestrator.run(
            case_id=case_id,
            fraud_txid=req.fraud_txid,
            fraud_address=req.fraud_address,
            max_hops=req.max_hops,
        )

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception(f"Investigation failed for {req.fraud_txid}")
        raise HTTPException(status_code=500, detail=f"Investigation error: {str(e)}")

    # Generate PDF
    pdf_path = os.path.join(tempfile.gettempdir(), f"{case_id}.pdf")
    try:
        report_hash = generate_report(chain, pdf_path)
    except Exception as e:
        logger.exception("PDF generation failed")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

    _pdf_store[case_id] = pdf_path

    # Persist if requested
    if req.persist:
        _persist_chain(conn, chain, report_hash)

    # Build response
    official_hops = chain.official_report_hops
    min_conf = chain.minimum_confidence
    conf_label = min_conf.name if min_conf else "NO_ELIGIBLE_HOPS"

    is_sanctioned = any(
        lookup.is_sanctioned(h.to_address)
        for h in chain.hops if h.to_address
    )

    hop_summaries = [
        HopSummary(
            hop_index=h.hop_index,
            from_address=h.from_address,
            to_address=h.to_address,
            amount_btc=str(h.amount_btc),
            method=h.method.value,
            confidence_level=h.confidence.value,
            confidence_label=h.confidence.name,
            time_delta_seconds=h.time_delta_seconds,
            exchange_name=h.exchange_name,
            is_official_report_eligible=h.is_official_report_eligible,
            caveat=h.caveat,
        )
        for h in chain.hops
    ]

    return FraudReportResponse(
        case_id=case_id,
        fraud_txid=req.fraud_txid,
        fraud_address=req.fraud_address,
        fraud_amount_btc=str(chain.fraud_amount_btc),
        fraud_timestamp=chain.fraud_timestamp.isoformat(),
        total_hops_analysed=len(chain.hops),
        official_report_hops=len(official_hops),
        chain_confidence=conf_label,
        exchange_hits=list(set(h.exchange_name for h in chain.exchange_hits)),
        is_sanctioned_address=is_sanctioned,
        report_hash=report_hash,
        pdf_download_url=f"/intel/fraud-report/{case_id}/pdf",
        hops=hop_summaries,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/fraud-report/{case_id}/pdf")
async def download_fraud_report(case_id: str):
    """PDF-Report herunterladen."""
    pdf_path = _pdf_store.get(case_id)
    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="Report nicht gefunden oder abgelaufen.")
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"forensic_report_{case_id}.pdf",
    )


@router.get("/fraud-report/{case_id}/status")
async def get_report_status(case_id: str):
    """Prüft ob ein Report für diese Fall-ID vorliegt."""
    exists = case_id in _pdf_store and os.path.exists(_pdf_store[case_id])
    return {"case_id": case_id, "report_available": exists}


# ---------------------------------------------------------------------------
# Persistence helper
# ---------------------------------------------------------------------------

PERSIST_SQL = """
    INSERT INTO fraud_investigations
        (case_id, fraud_txid, fraud_address, fraud_amount_btc,
         fraud_timestamp, hop_count, official_hop_count,
         exchange_hits, report_hash, chain_data, created_at)
    VALUES
        (%(case_id)s, %(fraud_txid)s, %(fraud_address)s, %(fraud_amount_btc)s,
         %(fraud_timestamp)s, %(hop_count)s, %(official_hop_count)s,
         %(exchange_hits)s, %(report_hash)s, %(chain_data)s, NOW())
    ON CONFLICT (case_id) DO UPDATE SET
        report_hash      = EXCLUDED.report_hash,
        chain_data       = EXCLUDED.chain_data,
        updated_at       = NOW();
"""


def _persist_chain(conn, chain: InvestigationChain, report_hash: str):
    import json
    try:
        with conn.cursor() as cur:
            cur.execute(PERSIST_SQL, {
                "case_id":           chain.case_id,
                "fraud_txid":        chain.fraud_txid,
                "fraud_address":     chain.fraud_address,
                "fraud_amount_btc":  str(chain.fraud_amount_btc),
                "fraud_timestamp":   chain.fraud_timestamp,
                "hop_count":         len(chain.hops),
                "official_hop_count": len(chain.official_report_hops),
                "exchange_hits":     [h.exchange_name for h in chain.exchange_hits],
                "report_hash":       report_hash,
                "chain_data":        json.dumps(chain.to_dict(), default=str),
            })
        conn.commit()
    except Exception as e:
        logger.warning(f"Persist failed for {chain.case_id}: {e}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(unix_ts) -> datetime:
    if unix_ts is None:
        return datetime.now(timezone.utc)
    if isinstance(unix_ts, datetime):
        return unix_ts.replace(tzinfo=timezone.utc) if unix_ts.tzinfo is None else unix_ts
    return datetime.fromtimestamp(int(unix_ts), tz=timezone.utc)


def _dummy_hop(txid, address, timestamp, block_height) -> TracingHop:
    """Placeholder previous hop for exchange_hop builder when chain is empty."""
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
