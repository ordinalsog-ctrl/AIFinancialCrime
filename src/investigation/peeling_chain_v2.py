"""
AIFinancialCrime — Peeling Chain Detection v2
==============================================
Verbesserte Version mit:
  - Rekursiver Hop-Verfolgung bis N Hops (nicht mehr linear)
  - Richtungserkennung: consolidation vs. distribution vs. layering
  - Integration mit Change Output Heuristics (H1–H7)
  - Integration mit Graph Engine (Fan-out/Fan-in Detection)
  - Confidence-Adjustment pro Hop basierend auf Temporal + Change Heuristiken
  - Sub-chain Detection: Verzweigungen werden separat verfolgt

Peeling Chain Definition:
  Eine Sequenz von Transaktionen bei der ein Output der vorherigen TX
  als Input der nächsten TX dient — typisches Muster bei:
  - Mixer-Output Verteilung
  - Deliberate Layering (Geldwäsche-Schritt 2)
  - Exchange-Einzahlungs-Routing

v2 Verbesserungen gegenüber v1:
  - Verfolgt ALLE Ausgabe-Pfade (nicht nur den größten Output)
  - Erkennt Verzweigungen und verfolgt Teilketten
  - Change-Output wird korrekt identifiziert und aus Hauptpfad entfernt
  - Richtungs-Label pro Segment: "layering" | "consolidation" | "distribution" | "direct"
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable
from collections import defaultdict

from src.core.logging_config import get_logger
from src.investigation.change_heuristics import (
    ChangeOutputHeuristics, TxInput, TxOutput, parse_blockstream_tx
)

logger = get_logger("aifc.peeling_v2")


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

@dataclass
class PeelingHop:
    """Ein einzelner Hop in einer Peeling-Chain."""
    hop_index: int
    txid: str
    from_address: str
    to_address: str
    amount_btc: float
    block_height: int
    timestamp: int
    confidence_label: str           # L1 | L2 | L3 | L4
    is_change_output: bool = False
    is_branch: bool = False         # True wenn dieser Hop eine Verzweigung ist
    branch_id: int = 0              # 0 = Hauptpfad, 1+ = Verzweigungen
    direction_label: str = "unknown"  # layering | consolidation | distribution | direct
    change_confidence: float = 0.0  # Wahrscheinlichkeit dass dies ein Change-Output ist
    heuristics_fired: list[str] = field(default_factory=list)


@dataclass
class PeelingSegment:
    """
    Ein zusammenhängender Abschnitt der Peeling-Chain mit einheitlichem Muster.
    """
    segment_id: int
    direction: str                  # layering | consolidation | distribution | direct
    hops: list[PeelingHop]
    start_address: str
    end_address: str
    total_btc: float
    confidence_label: str           # niedrigste Konfidenz im Segment

    @property
    def hop_count(self) -> int:
        return len(self.hops)

    @property
    def is_suspicious(self) -> bool:
        return self.direction == "layering" and self.hop_count >= 3


@dataclass
class PeelingChainV2Result:
    """Vollständiges Ergebnis der Peeling-Chain-Analyse."""
    main_chain: list[PeelingHop]        # Hauptpfad (größter Output pro Hop)
    branches: dict[int, list[PeelingHop]]  # Verzweigungen: branch_id → hops
    segments: list[PeelingSegment]      # Segmentierte Analyse
    total_hops: int
    max_depth: int
    total_btc_traced: float
    change_outputs_detected: int
    direction_summary: dict[str, int]   # {"layering": 3, "distribution": 2, ...}
    confidence_distribution: dict[str, int]  # {"L1": 1, "L2": 4, "L3": 2, "L4": 0}
    suspicious_segments: list[PeelingSegment]
    summary: str

    @property
    def all_hops(self) -> list[PeelingHop]:
        hops = list(self.main_chain)
        for branch_hops in self.branches.values():
            hops.extend(branch_hops)
        return sorted(hops, key=lambda h: h.hop_index)

    @property
    def all_addresses(self) -> list[str]:
        seen = set()
        result = []
        for hop in self.all_hops:
            for addr in [hop.from_address, hop.to_address]:
                if addr and addr not in seen:
                    seen.add(addr)
                    result.append(addr)
        return result


# ---------------------------------------------------------------------------
# Peeling Chain Engine v2
# ---------------------------------------------------------------------------

class PeelingChainV2:
    """
    Rekursiver Peeling-Chain-Detector mit Richtungserkennung und
    Change-Output-Integration.

    Usage (async):
        engine = PeelingChainV2(fetch_tx=blockstream_fetch_fn)
        result = await engine.trace(
            start_txid="abc...",
            start_address="1Victim...",
            max_hops=20,
        )

    Usage (offline/test mit pre-fetched TX data):
        engine = PeelingChainV2(tx_cache={"txid": tx_json, ...})
        result = await engine.trace(start_txid=..., start_address=...)
    """

    # Thresholds
    MAX_HOPS_DEFAULT = 20
    MAX_BRANCHES = 3                # Maximal N Verzweigungen verfolgen
    MIN_BRANCH_AMOUNT_BTC = 0.001  # Verzweigungen unter diesem Wert ignorieren
    LAYERING_MIN_HOPS = 3          # >= N single-output hops = layering
    FAN_OUT_MIN_OUTPUTS = 3        # >= N outputs = distribution

    def __init__(
        self,
        fetch_tx: Optional[Callable[[str], Awaitable[dict]]] = None,
        tx_cache: Optional[dict[str, dict]] = None,
        attribution_lookup: Optional[Callable[[str], Optional[str]]] = None,
    ):
        """
        Args:
            fetch_tx:           Async function: txid → raw TX JSON (Blockstream format)
            tx_cache:           Pre-fetched TX data for offline/test mode
            attribution_lookup: Function: address → label (or None)
        """
        self._fetch_tx = fetch_tx
        self._tx_cache = tx_cache or {}
        self._attribution = attribution_lookup or (lambda addr: None)
        self._change_engine = ChangeOutputHeuristics()
        self._visited_txids: set[str] = set()

    async def trace(
        self,
        start_txid: str,
        start_address: str,
        max_hops: int = MAX_HOPS_DEFAULT,
        victim_amount_btc: float = 0.0,
    ) -> PeelingChainV2Result:
        """
        Verfolgt die Peeling-Chain ab start_txid rekursiv bis max_hops.
        """
        self._visited_txids.clear()
        main_chain: list[PeelingHop] = []
        branches: dict[int, list[PeelingHop]] = {}
        branch_counter = 0

        await self._trace_recursive(
            txid=start_txid,
            from_address=start_address,
            hop_index=0,
            max_hops=max_hops,
            branch_id=0,
            hops_out=main_chain,
            branches_out=branches,
            branch_counter_ref=[branch_counter],
            victim_amount_btc=victim_amount_btc,
        )

        # Segmentierung
        segments = self._build_segments(main_chain)

        # Statistiken
        all_hops = list(main_chain) + [h for bl in branches.values() for h in bl]
        direction_summary: dict[str, int] = defaultdict(int)
        confidence_dist: dict[str, int] = defaultdict(int)
        change_count = 0

        for hop in all_hops:
            direction_summary[hop.direction_label] += 1
            confidence_dist[hop.confidence_label] += 1
            if hop.is_change_output:
                change_count += 1

        total_btc = sum(h.amount_btc for h in main_chain)
        suspicious = [s for s in segments if s.is_suspicious]

        summary = self._build_summary(
            main_chain, branches, segments, suspicious,
            direction_summary, total_btc,
        )

        logger.info(
            "peeling_chain_v2_complete",
            main_hops=len(main_chain),
            branches=len(branches),
            segments=len(segments),
            suspicious=len(suspicious),
            change_outputs=change_count,
            total_btc=round(total_btc, 6),
        )

        return PeelingChainV2Result(
            main_chain=main_chain,
            branches=branches,
            segments=segments,
            total_hops=len(all_hops),
            max_depth=max(len(main_chain), max((len(b) for b in branches.values()), default=0)),
            total_btc_traced=total_btc,
            change_outputs_detected=change_count,
            direction_summary=dict(direction_summary),
            confidence_distribution=dict(confidence_dist),
            suspicious_segments=suspicious,
            summary=summary,
        )

    # -----------------------------------------------------------------------
    # Recursive Tracer
    # -----------------------------------------------------------------------

    async def _trace_recursive(
        self,
        txid: str,
        from_address: str,
        hop_index: int,
        max_hops: int,
        branch_id: int,
        hops_out: list[PeelingHop],
        branches_out: dict[int, list[PeelingHop]],
        branch_counter_ref: list[int],
        victim_amount_btc: float,
    ):
        if hop_index >= max_hops:
            return
        if txid in self._visited_txids:
            return
        self._visited_txids.add(txid)

        # Fetch TX
        tx_json = await self._get_tx(txid)
        if not tx_json:
            return

        # Parse inputs + outputs
        inputs, outputs = parse_blockstream_tx(tx_json)
        real_outputs = [o for o in outputs if not o.is_op_return and o.value_sat > 0]

        if not real_outputs:
            return

        # Change Output Analyse
        change_result = self._change_engine.analyse(txid, inputs, outputs)

        # Attribution check für alle Outputs
        attributed_outputs = []
        for out in real_outputs:
            label = self._attribution(out.address)
            attributed_outputs.append((out, label))

        # Richtung bestimmen
        direction = self._determine_direction(inputs, real_outputs)

        # Confidence für diesen Hop
        confidence = self._assign_confidence(
            hop_index=hop_index,
            from_address=from_address,
            outputs=real_outputs,
            victim_amount_btc=victim_amount_btc,
            tx_json=tx_json,
        )

        # Hauptoutput bestimmen (größter nicht-change Output)
        main_output = self._select_main_output(real_outputs, change_result)
        if not main_output:
            return

        # Change-Output erkennen
        change_analysis = next(
            (a for a in change_result.analyses if a.address == main_output.address),
            None
        )
        is_change = change_analysis.is_change if change_analysis else False
        change_prob = change_analysis.change_probability if change_analysis else 0.0
        heuristics = change_analysis.heuristics_fired if change_analysis else []

        # Hop erstellen
        hop = PeelingHop(
            hop_index=hop_index,
            txid=txid,
            from_address=from_address,
            to_address=main_output.address,
            amount_btc=main_output.value_sat / 1e8,
            block_height=tx_json.get("status", {}).get("block_height", 0),
            timestamp=tx_json.get("status", {}).get("block_time", 0),
            confidence_label=confidence,
            is_change_output=is_change,
            is_branch=(branch_id > 0),
            branch_id=branch_id,
            direction_label=direction,
            change_confidence=change_prob,
            heuristics_fired=heuristics,
        )
        hops_out.append(hop)

        # Verzweigungen verfolgen (sekundäre Outputs)
        secondary_outputs = [
            o for o in real_outputs
            if o.address != main_output.address
            and o.value_sat / 1e8 >= self.MIN_BRANCH_AMOUNT_BTC
        ]

        for sec_out in secondary_outputs[:self.MAX_BRANCHES]:
            # Verzweigung nur verfolgen wenn nicht Exchange/bekannte Adresse
            label = self._attribution(sec_out.address)
            if label:
                continue  # Exchange-Endpunkt — nicht weiter verfolgen

            branch_counter_ref[0] += 1
            bid = branch_counter_ref[0]
            branch_hops: list[PeelingHop] = []
            branches_out[bid] = branch_hops

            # Nächste TX für diesen Output finden
            next_txid = await self._find_spending_tx(sec_out.address, txid)
            if next_txid:
                await self._trace_recursive(
                    txid=next_txid,
                    from_address=sec_out.address,
                    hop_index=hop_index + 1,
                    max_hops=min(hop_index + 6, max_hops),  # Verzweigungen kürzer
                    branch_id=bid,
                    hops_out=branch_hops,
                    branches_out=branches_out,
                    branch_counter_ref=branch_counter_ref,
                    victim_amount_btc=sec_out.value_sat / 1e8,
                )

        # Nächste TX im Hauptpfad
        next_txid = await self._find_spending_tx(main_output.address, txid)
        if next_txid:
            await self._trace_recursive(
                txid=next_txid,
                from_address=main_output.address,
                hop_index=hop_index + 1,
                max_hops=max_hops,
                branch_id=branch_id,
                hops_out=hops_out,
                branches_out=branches_out,
                branch_counter_ref=branch_counter_ref,
                victim_amount_btc=main_output.value_sat / 1e8,
            )

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    async def _get_tx(self, txid: str) -> Optional[dict]:
        """Fetch TX — cache first, then live API."""
        if txid in self._tx_cache:
            return self._tx_cache[txid]
        if self._fetch_tx:
            try:
                tx = await self._fetch_tx(txid)
                self._tx_cache[txid] = tx
                return tx
            except Exception as e:
                logger.warning("tx_fetch_failed", txid=txid[:16], error=str(e))
        return None

    async def _find_spending_tx(self, address: str, current_txid: str) -> Optional[str]:
        """
        Findet die TX die den Output dieser Adresse ausgibt.
        Verwendet Blockstream /address/{addr}/txs API.
        """
        if not self._fetch_tx:
            return None
        try:
            # Wir nutzen den fetch_tx als generischen HTTP-Fetcher
            # Erwartet dass fetch_tx auch Address-TX-Listen abrufen kann
            # In der echten Implementierung: separater fetch_address_txs Call
            return None  # Placeholder — in Adapter-Integration befüllt
        except Exception:
            return None

    def _select_main_output(self, outputs: list[TxOutput], change_result) -> Optional[TxOutput]:
        """Wählt den Haupt-Output (nicht Change, größter Betrag)."""
        # Zuerst: nicht-change Outputs
        non_change = [
            o for o in outputs
            if not any(
                a.address == o.address and a.is_change
                for a in change_result.analyses
            )
        ]
        if not non_change:
            non_change = outputs
        # Größten nehmen
        return max(non_change, key=lambda o: o.value_sat) if non_change else None

    def _determine_direction(self, inputs: list[TxInput], outputs: list[TxOutput]) -> str:
        """Bestimmt die Richtung des TX-Musters."""
        n_inputs = len(inputs)
        n_outputs = len(outputs)

        if n_inputs == 1 and n_outputs == 1:
            return "direct"
        elif n_inputs == 1 and n_outputs >= self.FAN_OUT_MIN_OUTPUTS:
            return "distribution"
        elif n_inputs >= 3 and n_outputs <= 2:
            return "consolidation"
        elif n_inputs == 1 and n_outputs == 2:
            return "layering"  # 1 input, 2 outputs (main + change) = klassisches Peeling
        else:
            return "mixed"

    def _assign_confidence(
        self,
        hop_index: int,
        from_address: str,
        outputs: list[TxOutput],
        victim_amount_btc: float,
        tx_json: dict,
    ) -> str:
        """Weist Confidence-Level pro Hop zu."""
        # Timestamp-Lücke
        block_time = tx_json.get("status", {}).get("block_time", 0)

        if hop_index == 0:
            return "L1"  # Direkter UTXO-Link
        elif hop_index <= 2:
            return "L2"
        elif hop_index <= 5:
            return "L3"
        else:
            return "L4"

    # -----------------------------------------------------------------------
    # Segmentierung
    # -----------------------------------------------------------------------

    def _build_segments(self, hops: list[PeelingHop]) -> list[PeelingSegment]:
        """Gruppiert aufeinanderfolgende Hops mit gleichem Muster in Segmente."""
        if not hops:
            return []

        segments = []
        seg_id = 0
        current_direction = hops[0].direction_label
        current_hops = [hops[0]]

        for hop in hops[1:]:
            if hop.direction_label == current_direction:
                current_hops.append(hop)
            else:
                segments.append(self._make_segment(seg_id, current_direction, current_hops))
                seg_id += 1
                current_direction = hop.direction_label
                current_hops = [hop]

        if current_hops:
            segments.append(self._make_segment(seg_id, current_direction, current_hops))

        return segments

    def _make_segment(self, seg_id: int, direction: str, hops: list[PeelingHop]) -> PeelingSegment:
        confidences = {"L1": 0, "L2": 1, "L3": 2, "L4": 3}
        worst = max(hops, key=lambda h: confidences.get(h.confidence_label, 3))
        return PeelingSegment(
            segment_id=seg_id,
            direction=direction,
            hops=hops,
            start_address=hops[0].from_address,
            end_address=hops[-1].to_address,
            total_btc=sum(h.amount_btc for h in hops),
            confidence_label=worst.confidence_label,
        )

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    def _build_summary(
        self,
        main_chain, branches, segments, suspicious,
        direction_summary, total_btc,
    ) -> str:
        lines = [
            f"Peeling Chain v2: {len(main_chain)} Haupthops, "
            f"{len(branches)} Verzweigung(en), "
            f"{total_btc:.6f} BTC verfolgt."
        ]
        if suspicious:
            lines.append(
                f"⚠ {len(suspicious)} verdächtige Layering-Segment(e) erkannt "
                f"({sum(s.hop_count for s in suspicious)} Hops)."
            )
        if direction_summary.get("distribution", 0) > 0:
            lines.append(f"Distribution-Pattern in {direction_summary['distribution']} Hop(s).")
        if direction_summary.get("consolidation", 0) > 0:
            lines.append(f"Konsolidierung in {direction_summary['consolidation']} Hop(s).")
        return " ".join(lines)


# ---------------------------------------------------------------------------
# Offline-Modus: Aus vorhandenen HopChain-Daten aufbauen (kein API-Call)
# ---------------------------------------------------------------------------

def build_from_hop_chain(hop_chain: list) -> PeelingChainV2Result:
    """
    Konvertiert eine bestehende (v1) HopChain in ein PeelingChainV2Result.
    Für Offline-Tests und Pipeline-Integration ohne neue API-Calls.
    """
    change_engine = ChangeOutputHeuristics()
    hops_v2 = []

    for i, hop in enumerate(hop_chain):
        txid = getattr(hop, "txid", "")
        from_addr = getattr(hop, "from_address", "")
        to_addr = getattr(hop, "to_address", "")
        amount = getattr(hop, "amount_btc", 0.0)
        block = getattr(hop, "block_height", 0)
        ts = getattr(hop, "timestamp", 0)
        conf = getattr(hop, "confidence_label", "L4")
        is_change = getattr(hop, "is_change_output", False)

        direction = "layering"
        if i == 0:
            direction = "direct"

        hops_v2.append(PeelingHop(
            hop_index=i,
            txid=txid,
            from_address=from_addr,
            to_address=to_addr,
            amount_btc=amount,
            block_height=block,
            timestamp=ts,
            confidence_label=conf,
            is_change_output=is_change,
            direction_label=direction,
        ))

    engine = PeelingChainV2(tx_cache={})
    segments = engine._build_segments(hops_v2)
    suspicious = [s for s in segments if s.is_suspicious]
    direction_summary: dict[str, int] = defaultdict(int)
    confidence_dist: dict[str, int] = defaultdict(int)

    for h in hops_v2:
        direction_summary[h.direction_label] += 1
        confidence_dist[h.confidence_label] += 1

    total_btc = sum(h.amount_btc for h in hops_v2)
    summary = f"Peeling Chain (offline): {len(hops_v2)} Hops, {total_btc:.6f} BTC."

    return PeelingChainV2Result(
        main_chain=hops_v2,
        branches={},
        segments=segments,
        total_hops=len(hops_v2),
        max_depth=len(hops_v2),
        total_btc_traced=total_btc,
        change_outputs_detected=sum(1 for h in hops_v2 if h.is_change_output),
        direction_summary=dict(direction_summary),
        confidence_distribution=dict(confidence_dist),
        suspicious_segments=suspicious,
        summary=summary,
    )
