"""
AIFinancialCrime — Investigation Pipeline v3
=============================================
Vollständig integrierte Pipeline mit allen Forensik-Engines:

  v1: Basis-Pipeline (Confidence, Attribution, Peeling v1)
  v2: + Serial Actor, Victim-Params, Exchange Contacts
  v3: + Graph Engine, Change Heuristics, Temporal Engine, Peeling Chain v2
      + Structured Logging mit Correlation-IDs
      + Prometheus Metrics
      + Confidence-Adjustment aus Temporal-Analyse

InvestigationResult v3 enthält:
  - hop_chain          (wie bisher)
  - peeling_result     (PeelingChainV2Result — neu)
  - graph_result       (GraphAnalysisResult — neu)
  - temporal_result    (TemporalAnalysisResult — neu)
  - serial_matches     (wie v2)
  - confidence_summary (neu — aggregierte Confidence über alle Engines)
  - summary            (erweiterter Text-Summary)
"""

from __future__ import annotations

import time
import uuid
import asyncio
from dataclasses import dataclass, field
from typing import Optional

from src.core.logging_config import get_logger, bind_investigation
from src.core.metrics import metrics

from src.investigation.confidence_engine import ConfidenceEngine
from src.investigation.attribution_db import AttributionDB
from src.investigation.adapter import BlockstreamAdapter
from src.investigation.peeling_chain_v2 import PeelingChainV2, PeelingChainV2Result, build_from_hop_chain
from src.investigation.graph_engine import TransactionGraphEngine, GraphAnalysisResult, extract_attribution_map
from src.investigation.change_heuristics import ChangeOutputHeuristics
from src.investigation.temporal_engine import TemporalPatternEngine, TemporalAnalysisResult, hops_from_chain
from src.investigation.serial_actor import SerialActorEngine, SerialMatch
from src.investigation.exchange_contacts import ExchangeContactDB

logger = get_logger("aifc.pipeline_v3")


# ---------------------------------------------------------------------------
# Result Types
# ---------------------------------------------------------------------------

@dataclass
class ConfidenceSummary:
    """Aggregierte Confidence-Aussage über alle Engines."""
    overall_label: str              # L1 | L2 | L3 | L4
    overall_score: float            # 0.0–1.0 (intern)
    hop_distribution: dict[str, int]
    temporal_adjustment: float      # aus Temporal Engine
    graph_patterns: list[str]       # erkannte Graph-Muster
    weakest_link: str               # Adresse/Hop mit niedrigster Confidence
    court_readiness: str            # "high" | "medium" | "low"
    notes: list[str]


@dataclass
class InvestigationResultV3:
    """Vollständiges Ergebnis einer Investigation — Pipeline v3."""

    # Identifikation
    investigation_id: str
    txid: str
    victim_address: str
    victim_name: str
    victim_contact: str
    language: str

    # Timing
    started_at: float
    completed_at: float

    # Kern-Ergebnisse
    hop_chain: list                         # Raw HopResult Liste (v1 kompatibel)
    attribution_map: dict[str, str]         # address → label

    # v2 Engines
    peeling_result: Optional[PeelingChainV2Result]
    serial_matches: list[SerialMatch]

    # v3 Engines (neu)
    graph_result: Optional[GraphAnalysisResult]
    temporal_result: Optional[TemporalAnalysisResult]
    confidence_summary: Optional[ConfidenceSummary]

    # Outputs
    freeze_requests: list[dict]
    exchange_endpoints: list[str]           # Exchange-Adressen am Kettenende

    # Meta
    errors: list[str]
    warnings: list[str]

    @property
    def duration_seconds(self) -> float:
        return self.completed_at - self.started_at

    @property
    def summary(self) -> dict:
        return {
            "investigation_id": self.investigation_id,
            "txid": self.txid,
            "victim": self.victim_name or "Unbekannt",
            "hops_traced": len(self.hop_chain),
            "total_btc": sum(getattr(h, "amount_btc", 0) for h in self.hop_chain[:1]),
            "exchange_endpoints": self.exchange_endpoints,
            "graph_patterns": [p.pattern for p in (self.graph_result.patterns if self.graph_result else [])],
            "temporal_tz": (self.temporal_result.timezone_estimate.region
                           if self.temporal_result and self.temporal_result.timezone_estimate else None),
            "serial_actor_hits": len(self.serial_matches),
            "court_readiness": self.confidence_summary.court_readiness if self.confidence_summary else "unknown",
            "duration_s": round(self.duration_seconds, 1),
        }


# ---------------------------------------------------------------------------
# Pipeline v3
# ---------------------------------------------------------------------------

class InvestigationPipelineV3:
    """
    Haupt-Pipeline — orchestriert alle Forensik-Engines.

    Usage:
        pipeline = InvestigationPipelineV3(
            attribution_db=db,
            serial_engine=serial_engine,  # optional
        )
        result = await pipeline.run(
            txid="abc...",
            victim_address="1ABC...",
            victim_name="Max Mustermann",
            victim_contact="max@example.com",
            max_hops=15,
            language="de",
        )
    """

    def __init__(
        self,
        attribution_db: Optional[AttributionDB] = None,
        serial_engine: Optional[SerialActorEngine] = None,
        known_chains: Optional[list] = None,
    ):
        self.attribution_db = attribution_db
        self.serial_engine = serial_engine
        self.known_chains = known_chains or []

        # Engine-Instanzen
        self._confidence_engine = ConfidenceEngine()
        self._adapter = BlockstreamAdapter()
        self._graph_engine = TransactionGraphEngine()
        self._change_engine = ChangeOutputHeuristics()
        self._temporal_engine = TemporalPatternEngine()
        self._exchange_db = ExchangeContactDB()

        logger.info("pipeline_v3_initialized",
                    has_attribution_db=attribution_db is not None,
                    has_serial_engine=serial_engine is not None)

    async def run(
        self,
        txid: str,
        victim_address: str,
        victim_name: str = "",
        victim_contact: str = "",
        max_hops: int = 15,
        language: str = "de",
        investigation_id: str = "",
    ) -> InvestigationResultV3:
        """
        Führt eine vollständige Untersuchung durch.
        """
        investigation_id = investigation_id or f"INV-{str(uuid.uuid4())[:8].upper()}"
        started_at = time.monotonic()
        errors: list[str] = []
        warnings: list[str] = []

        with bind_investigation(investigation_id):
            logger.info("investigation_started",
                        txid=txid[:16], victim=victim_name, max_hops=max_hops)
            metrics.investigation_started()

            # ------------------------------------------------------------------
            # Schritt 1: Hop-Chain abrufen (Adapter Layer)
            # ------------------------------------------------------------------
            logger.info("step_1_hop_chain_fetch")
            hop_chain = []
            attribution_map = {}
            try:
                hop_chain = await self._fetch_hop_chain(txid, victim_address, max_hops)
                attribution_map = self._build_attribution_map(hop_chain)
                logger.info("hop_chain_fetched", hops=len(hop_chain))
            except Exception as e:
                errors.append(f"Hop-Chain-Fehler: {e}")
                logger.error("hop_chain_fetch_failed", error=str(e))

            # ------------------------------------------------------------------
            # Schritt 2: Peeling Chain v2
            # ------------------------------------------------------------------
            logger.info("step_2_peeling_chain_v2")
            peeling_result: Optional[PeelingChainV2Result] = None
            try:
                if hop_chain:
                    peeling_result = build_from_hop_chain(hop_chain)
                    logger.info("peeling_chain_complete",
                                hops=peeling_result.total_hops,
                                segments=len(peeling_result.segments),
                                suspicious=len(peeling_result.suspicious_segments))
                    if peeling_result.suspicious_segments:
                        metrics.peeling_chain_detected(
                            depth=max(s.hop_count for s in peeling_result.suspicious_segments)
                        )
            except Exception as e:
                warnings.append(f"Peeling Chain v2 Fehler: {e}")
                logger.warning("peeling_chain_failed", error=str(e))

            # ------------------------------------------------------------------
            # Schritt 3: Transaction Graph Engine
            # ------------------------------------------------------------------
            logger.info("step_3_graph_engine")
            graph_result: Optional[GraphAnalysisResult] = None
            try:
                if hop_chain:
                    graph_result = self._graph_engine.analyse(
                        hop_chain=hop_chain,
                        attribution_map=attribution_map,
                        victim_address=victim_address,
                    )
                    logger.info("graph_analysis_complete",
                                nodes=graph_result.node_count,
                                edges=graph_result.edge_count,
                                patterns=len(graph_result.patterns))
            except Exception as e:
                warnings.append(f"Graph Engine Fehler: {e}")
                logger.warning("graph_engine_failed", error=str(e))

            # ------------------------------------------------------------------
            # Schritt 4: Temporal Pattern Engine
            # ------------------------------------------------------------------
            logger.info("step_4_temporal_engine")
            temporal_result: Optional[TemporalAnalysisResult] = None
            try:
                if hop_chain:
                    temporal_hops = hops_from_chain(hop_chain)
                    if temporal_hops:
                        temporal_result = self._temporal_engine.analyse(temporal_hops)
                        logger.info("temporal_analysis_complete",
                                    patterns=len(temporal_result.patterns),
                                    tz=temporal_result.timezone_estimate.region
                                       if temporal_result.timezone_estimate else "unknown",
                                    confidence_delta=temporal_result.confidence_adjustment)
                    else:
                        warnings.append("Keine Zeitstempel in Hop-Chain — Temporal-Analyse übersprungen.")
            except Exception as e:
                warnings.append(f"Temporal Engine Fehler: {e}")
                logger.warning("temporal_engine_failed", error=str(e))

            # ------------------------------------------------------------------
            # Schritt 5: Attribution Metrics
            # ------------------------------------------------------------------
            exchange_endpoints = []
            if graph_result:
                exchange_endpoints = [
                    self._graph_engine._nodes[a].attribution_label or a
                    for a in graph_result.exchange_endpoints
                    if a in self._graph_engine._nodes
                ]
                for addr in graph_result.exchange_endpoints:
                    label = attribution_map.get(addr, "")
                    metrics.attribution_lookup(hit=bool(label), source="local_db")

            # ------------------------------------------------------------------
            # Schritt 6: Serial Actor Check
            # ------------------------------------------------------------------
            logger.info("step_6_serial_actor")
            serial_matches: list[SerialMatch] = []
            try:
                if self.serial_engine and hop_chain and self.known_chains:
                    serial_matches = self.serial_engine.check_offline(
                        hop_chain, self.known_chains
                    )
                    if serial_matches:
                        logger.warning("serial_actor_matches_found",
                                       count=len(serial_matches))
            except Exception as e:
                warnings.append(f"Serial Actor Fehler: {e}")
                logger.warning("serial_actor_failed", error=str(e))

            # ------------------------------------------------------------------
            # Schritt 7: Confidence Summary
            # ------------------------------------------------------------------
            confidence_summary = self._build_confidence_summary(
                hop_chain=hop_chain,
                temporal_result=temporal_result,
                graph_result=graph_result,
                peeling_result=peeling_result,
            )

            # ------------------------------------------------------------------
            # Schritt 8: Freeze Requests
            # ------------------------------------------------------------------
            freeze_requests = []
            for exchange_label in exchange_endpoints:
                contact = self._exchange_db.get_contact(exchange_label)
                if contact:
                    freeze_requests.append({
                        "exchange": contact.name,
                        "portal": contact.law_enforcement_portal,
                        "email": contact.email,
                        "response_days": contact.response_days_typical,
                    })
                    metrics.freeze_request_sent(exchange=contact.name)

            # ------------------------------------------------------------------
            # Abschluss
            # ------------------------------------------------------------------
            completed_at = time.monotonic()
            duration = completed_at - started_at

            # Metrics
            hop_confidences = [getattr(h, "confidence_label", "L4") for h in hop_chain]
            metrics.investigation_completed(
                duration_s=duration,
                hop_count=len(hop_chain),
                attribution_hits=len(exchange_endpoints),
                confidence_levels=hop_confidences,
                serial_matches=len(serial_matches),
            )

            logger.info("investigation_completed",
                        duration_s=round(duration, 1),
                        hops=len(hop_chain),
                        graph_patterns=len(graph_result.patterns) if graph_result else 0,
                        serial_matches=len(serial_matches),
                        errors=len(errors),
                        warnings=len(warnings))

            return InvestigationResultV3(
                investigation_id=investigation_id,
                txid=txid,
                victim_address=victim_address,
                victim_name=victim_name,
                victim_contact=victim_contact,
                language=language,
                started_at=started_at,
                completed_at=completed_at,
                hop_chain=hop_chain,
                attribution_map=attribution_map,
                peeling_result=peeling_result,
                serial_matches=serial_matches,
                graph_result=graph_result,
                temporal_result=temporal_result,
                confidence_summary=confidence_summary,
                freeze_requests=freeze_requests,
                exchange_endpoints=exchange_endpoints,
                errors=errors,
                warnings=warnings,
            )

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    async def _fetch_hop_chain(
        self, txid: str, victim_address: str, max_hops: int
    ) -> list:
        """Ruft Hop-Chain über Adapter ab."""
        # Adapter-Integration — kompatibel mit v1/v2
        try:
            chain = await self._adapter.trace_chain(
                start_txid=txid,
                start_address=victim_address,
                max_hops=max_hops,
            )
            return chain
        except AttributeError:
            # Fallback für ältere Adapter ohne async trace_chain
            return []

    def _build_attribution_map(self, hop_chain: list) -> dict[str, str]:
        """Baut Address→Label Map aus Attribution DB."""
        result = {}
        if not self.attribution_db:
            return result
        for hop in hop_chain:
            for addr in [getattr(hop, "from_address", ""), getattr(hop, "to_address", "")]:
                if addr and addr not in result:
                    label = self.attribution_db.lookup(addr)
                    if label:
                        result[addr] = label
                        metrics.attribution_lookup(hit=True, source="local_db")
                    else:
                        metrics.attribution_lookup(hit=False, source="local_db")
        return result

    def _build_confidence_summary(
        self,
        hop_chain: list,
        temporal_result: Optional[TemporalAnalysisResult],
        graph_result: Optional[GraphAnalysisResult],
        peeling_result: Optional[PeelingChainV2Result],
    ) -> ConfidenceSummary:
        """Aggregiert Confidence über alle Engines."""
        # Hop-Distribution
        dist: dict[str, int] = {"L1": 0, "L2": 0, "L3": 0, "L4": 0}
        weakest = "L1"
        weakest_addr = ""
        level_order = {"L1": 0, "L2": 1, "L3": 2, "L4": 3}

        for hop in hop_chain:
            lvl = getattr(hop, "confidence_label", "L4")
            dist[lvl] = dist.get(lvl, 0) + 1
            if level_order.get(lvl, 0) > level_order.get(weakest, 0):
                weakest = lvl
                weakest_addr = getattr(hop, "to_address", "")

        # Temporal Adjustment
        temp_adj = temporal_result.confidence_adjustment if temporal_result else 0.0

        # Graph Patterns
        graph_patterns = [p.pattern for p in (graph_result.patterns if graph_result else [])]

        # Gesamt-Score (vereinfacht)
        total_hops = sum(dist.values())
        if total_hops == 0:
            overall_label = "L4"
            score = 0.0
        else:
            weighted = (dist["L1"] * 1.0 + dist["L2"] * 0.7 +
                       dist["L3"] * 0.4 + dist["L4"] * 0.1)
            score = weighted / total_hops + temp_adj
            score = max(0.0, min(1.0, score))
            if score >= 0.8:
                overall_label = "L1"
            elif score >= 0.6:
                overall_label = "L2"
            elif score >= 0.35:
                overall_label = "L3"
            else:
                overall_label = "L4"

        # Court Readiness
        notes = []
        if dist["L1"] > 0:
            notes.append(f"{dist['L1']} direkte UTXO-Verbindung(en) — gerichtsverwertbar.")
        if temporal_result and temporal_result.timezone_estimate:
            tz = temporal_result.timezone_estimate
            notes.append(f"Täter-Timezone: {tz.region} (Konfidenz {tz.confidence:.0%}).")
        if graph_patterns:
            notes.append(f"Graph-Muster: {', '.join(set(graph_patterns))}.")

        if overall_label in ("L1", "L2") and dist["L1"] > 0:
            court_readiness = "high"
        elif overall_label in ("L2", "L3"):
            court_readiness = "medium"
        else:
            court_readiness = "low"

        return ConfidenceSummary(
            overall_label=overall_label,
            overall_score=round(score, 3),
            hop_distribution=dist,
            temporal_adjustment=temp_adj,
            graph_patterns=graph_patterns,
            weakest_link=weakest_addr or weakest,
            court_readiness=court_readiness,
            notes=notes,
        )
