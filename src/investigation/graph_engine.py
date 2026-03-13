"""
AIFinancialCrime — Transaction Graph Engine
============================================
Builds a directed graph of Bitcoin transactions for forensic analysis.
Goes beyond linear hop tracing to detect:

  - Fan-out patterns (1 sender → N recipients, e.g. exchange payout, mixer output)
  - Fan-in / Consolidation (N inputs → 1 output, wallet consolidation or coinjoin prep)
  - Layering (deliberate chain of hops to obscure origin)
  - Dead-end addresses (UTXOs never spent — dust, lost funds, or holding wallets)
  - Re-convergence (funds split then recombined at a later address)

Graph structure:
  Nodes = Bitcoin addresses
  Edges = Transactions (directed: sender → receiver, weighted by BTC amount)

All graph operations are local (no external API calls — uses data already
fetched by the investigation pipeline via adapter layer).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict, deque
from enum import Enum

from src.core.logging_config import get_logger

logger = get_logger("aifc.graph")


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

class NodeType(str, Enum):
    UNKNOWN = "unknown"
    VICTIM = "victim"           # Starting address (victim's wallet)
    EXCHANGE = "exchange"       # Attributed to a known exchange
    MIXER = "mixer"             # Identified mixer/coinjoin service
    CHANGE = "change"           # Identified change output
    HOLDING = "holding"         # UTXO unspent (dust or long-term hold)
    CONSOLIDATION = "consolidation"  # Fan-in node
    DISTRIBUTION = "distribution"   # Fan-out node
    CONVERGENCE = "convergence"      # Previously split funds reunited


@dataclass
class GraphNode:
    address: str
    node_type: NodeType = NodeType.UNKNOWN
    attribution_label: Optional[str] = None
    total_received_btc: float = 0.0
    total_sent_btc: float = 0.0
    hop_distance: int = -1          # hops from victim address
    is_unspent: bool = False        # UTXO still unspent
    tx_count: int = 0

    @property
    def balance_btc(self) -> float:
        return self.total_received_btc - self.total_sent_btc

    @property
    def short(self) -> str:
        return f"{self.address[:8]}…{self.address[-4:]}"


@dataclass
class GraphEdge:
    txid: str
    from_address: str
    to_address: str
    amount_btc: float
    block_height: int
    timestamp: int              # Unix epoch
    is_change_output: bool = False
    confidence_label: str = "L4"

    @property
    def amount_sat(self) -> int:
        return round(self.amount_btc * 1e8)


@dataclass
class PatternMatch:
    pattern: str                # "fan_out" | "fan_in" | "layering" | "convergence" | "dead_end"
    severity: str               # "low" | "medium" | "high"
    addresses: list[str]
    txids: list[str]
    description: str
    btc_involved: float = 0.0


@dataclass
class GraphAnalysisResult:
    nodes: dict[str, GraphNode]
    edges: list[GraphEdge]
    patterns: list[PatternMatch]
    max_depth: int
    total_btc_traced: float
    dead_end_addresses: list[str]
    exchange_endpoints: list[str]
    summary: str

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)


# ---------------------------------------------------------------------------
# Graph Builder
# ---------------------------------------------------------------------------

class TransactionGraphEngine:
    """
    Builds and analyses a directed transaction graph from raw chain data.

    Input: HopChain from investigation pipeline (list of HopResult)
    Output: GraphAnalysisResult with pattern detections

    Usage:
        engine = TransactionGraphEngine()
        result = engine.analyse(hop_chain, attribution_map)
    """

    # Thresholds
    FAN_OUT_MIN_OUTPUTS = 4       # >= N outputs = fan-out pattern
    FAN_IN_MIN_INPUTS = 4         # >= N inputs = consolidation
    LAYERING_MIN_HOPS = 5         # >= N consecutive single-output hops
    ROUND_AMOUNT_THRESHOLD = 0.001  # BTC — amounts rounded to this are suspicious
    CONVERGENCE_WINDOW_BLOCKS = 1000  # blocks within which re-convergence counts

    def __init__(self):
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        self._adj: dict[str, list[GraphEdge]] = defaultdict(list)   # from → edges
        self._rev: dict[str, list[GraphEdge]] = defaultdict(list)   # to → edges

    def analyse(
        self,
        hop_chain: list,                          # list of HopResult from pipeline
        attribution_map: dict[str, str] = None,   # address → label
        victim_address: str = "",
    ) -> GraphAnalysisResult:
        """
        Main entry point. Build graph from hop_chain, then run all detectors.
        """
        attribution_map = attribution_map or {}
        self._reset()

        # Build graph
        self._build_from_hop_chain(hop_chain, attribution_map, victim_address)

        # Run pattern detectors
        patterns: list[PatternMatch] = []
        patterns.extend(self._detect_fan_out())
        patterns.extend(self._detect_fan_in())
        patterns.extend(self._detect_layering())
        patterns.extend(self._detect_convergence())
        dead_ends = self._detect_dead_ends()

        # Endpoints
        exchange_nodes = [
            addr for addr, n in self._nodes.items()
            if n.node_type == NodeType.EXCHANGE
        ]
        dead_end_addrs = [n.address for n in dead_ends]

        total_btc = sum(e.amount_btc for e in self._edges
                        if self._nodes.get(e.from_address, GraphNode("")).hop_distance == 0)

        max_depth = max((n.hop_distance for n in self._nodes.values()
                         if n.hop_distance >= 0), default=0)

        summary = self._build_summary(patterns, dead_ends, exchange_nodes, max_depth)

        logger.info(
            "graph_analysis_complete",
            nodes=len(self._nodes),
            edges=len(self._edges),
            patterns=len(patterns),
            dead_ends=len(dead_ends),
            exchanges=len(exchange_nodes),
            max_depth=max_depth,
        )

        return GraphAnalysisResult(
            nodes=dict(self._nodes),
            edges=list(self._edges),
            patterns=patterns,
            max_depth=max_depth,
            total_btc_traced=total_btc,
            dead_end_addresses=dead_end_addrs,
            exchange_endpoints=exchange_nodes,
            summary=summary,
        )

    # -----------------------------------------------------------------------
    # Graph Construction
    # -----------------------------------------------------------------------

    def _reset(self):
        self._nodes.clear()
        self._edges.clear()
        self._adj.clear()
        self._rev.clear()

    def _get_or_create_node(self, address: str, hop: int = -1) -> GraphNode:
        if address not in self._nodes:
            self._nodes[address] = GraphNode(address=address, hop_distance=hop)
        node = self._nodes[address]
        if hop >= 0 and (node.hop_distance < 0 or hop < node.hop_distance):
            node.hop_distance = hop
        return node

    def _build_from_hop_chain(
        self,
        hop_chain: list,
        attribution_map: dict[str, str],
        victim_address: str,
    ):
        """Convert linear HopChain into a graph."""
        for hop_idx, hop in enumerate(hop_chain):
            # Extract fields — compatible with HopResult dataclass
            txid = getattr(hop, "txid", "")
            from_addr = getattr(hop, "from_address", "")
            to_addr = getattr(hop, "to_address", "")
            amount = getattr(hop, "amount_btc", 0.0)
            block = getattr(hop, "block_height", 0)
            ts = getattr(hop, "timestamp", 0)
            confidence = getattr(hop, "confidence_label", "L4")
            is_change = getattr(hop, "is_change_output", False)

            # Inputs list (if available from multi-input TX detection)
            inputs = getattr(hop, "all_inputs", [from_addr]) or [from_addr]
            outputs = getattr(hop, "all_outputs", [(to_addr, amount)]) or [(to_addr, amount)]

            # Create nodes
            from_node = self._get_or_create_node(from_addr, hop_idx)
            to_node = self._get_or_create_node(to_addr, hop_idx + 1)

            # Set victim node
            if from_addr == victim_address:
                from_node.node_type = NodeType.VICTIM

            # Attribution
            for addr in [from_addr, to_addr]:
                if addr in attribution_map:
                    n = self._nodes[addr]
                    n.attribution_label = attribution_map[addr]
                    if any(ex in attribution_map[addr].lower()
                           for ex in ["binance", "coinbase", "kraken", "bybit", "okx",
                                      "kucoin", "bitfinex", "crypto.com", "gemini", "huobi"]):
                        n.node_type = NodeType.EXCHANGE

            # Update node stats
            from_node.total_sent_btc += amount
            from_node.tx_count += 1
            to_node.total_received_btc += amount
            to_node.tx_count += 1

            if is_change:
                to_node.node_type = NodeType.CHANGE

            # Create edge
            edge = GraphEdge(
                txid=txid,
                from_address=from_addr,
                to_address=to_addr,
                amount_btc=amount,
                block_height=block,
                timestamp=ts,
                is_change_output=is_change,
                confidence_label=confidence,
            )
            self._edges.append(edge)
            self._adj[from_addr].append(edge)
            self._rev[to_addr].append(edge)

    # -----------------------------------------------------------------------
    # Pattern Detectors
    # -----------------------------------------------------------------------

    def _detect_fan_out(self) -> list[PatternMatch]:
        """
        Detect addresses that send to many distinct recipients in one TX.
        Typical: exchange hot wallet payouts, mixer outputs, batch payments.
        """
        patterns = []
        # Group edges by txid
        tx_edges: dict[str, list[GraphEdge]] = defaultdict(list)
        for e in self._edges:
            tx_edges[e.txid].append(e)

        for txid, edges in tx_edges.items():
            unique_outputs = {e.to_address for e in edges}
            if len(unique_outputs) >= self.FAN_OUT_MIN_OUTPUTS:
                from_addr = edges[0].from_address
                total_btc = sum(e.amount_btc for e in edges)
                node = self._nodes.get(from_addr)
                if node:
                    node.node_type = NodeType.DISTRIBUTION
                patterns.append(PatternMatch(
                    pattern="fan_out",
                    severity="high" if len(unique_outputs) >= 10 else "medium",
                    addresses=[from_addr] + list(unique_outputs),
                    txids=[txid],
                    description=(
                        f"Fan-out: {from_addr[:10]}… sendet in einer TX an "
                        f"{len(unique_outputs)} Empfänger ({total_btc:.6f} BTC). "
                        f"Typisch für Exchange-Auszahlungen oder Mixer-Output."
                    ),
                    btc_involved=total_btc,
                ))
        return patterns

    def _detect_fan_in(self) -> list[PatternMatch]:
        """
        Detect transactions with many inputs (consolidation / coinjoin prep).
        """
        patterns = []
        tx_inputs: dict[str, list[GraphEdge]] = defaultdict(list)
        for e in self._edges:
            tx_inputs[e.txid].append(e)

        for txid, edges in tx_inputs.items():
            unique_inputs = {e.from_address for e in edges}
            if len(unique_inputs) >= self.FAN_IN_MIN_INPUTS:
                to_addrs = {e.to_address for e in edges}
                total_btc = sum(e.amount_btc for e in edges)
                for addr in to_addrs:
                    n = self._nodes.get(addr)
                    if n and n.node_type == NodeType.UNKNOWN:
                        n.node_type = NodeType.CONSOLIDATION
                patterns.append(PatternMatch(
                    pattern="fan_in",
                    severity="medium",
                    addresses=list(unique_inputs) + list(to_addrs),
                    txids=[txid],
                    description=(
                        f"Konsolidierung: {len(unique_inputs)} Eingaben in einer TX "
                        f"({total_btc:.6f} BTC). Typisch für Wallet-Zusammenführung "
                        f"vor Exchange-Einzahlung oder CoinJoin-Vorbereitung."
                    ),
                    btc_involved=total_btc,
                ))
        return patterns

    def _detect_layering(self) -> list[PatternMatch]:
        """
        Detect consecutive hops where each TX has exactly 1 output (peeling chain / layering).
        Sequence of ≥ LAYERING_MIN_HOPS single-output TXs = deliberate obfuscation.
        """
        patterns = []
        # Walk from each node, count consecutive single-output hops
        visited = set()

        for start_addr in list(self._nodes.keys()):
            if start_addr in visited:
                continue
            chain = [start_addr]
            current = start_addr
            while True:
                out_edges = self._adj.get(current, [])
                unique_txids = {e.txid for e in out_edges}
                if len(unique_txids) != 1:
                    break
                txid = next(iter(unique_txids))
                tx_out = [e for e in out_edges if e.txid == txid and not e.is_change_output]
                if len(tx_out) != 1:
                    break
                next_addr = tx_out[0].to_address
                if next_addr in chain:
                    break  # cycle guard
                chain.append(next_addr)
                current = next_addr

            if len(chain) >= self.LAYERING_MIN_HOPS:
                visited.update(chain)
                btc = sum(
                    e.amount_btc for e in self._edges
                    if e.from_address == chain[0] and e.to_address == chain[1]
                ) if len(chain) > 1 else 0
                patterns.append(PatternMatch(
                    pattern="layering",
                    severity="high",
                    addresses=chain,
                    txids=[e.txid for e in self._edges
                           if e.from_address in set(chain) and e.to_address in set(chain)],
                    description=(
                        f"Layering-Kette: {len(chain)} aufeinanderfolgende Einzelhops "
                        f"({chain[0][:8]}… → {chain[-1][:8]}…). "
                        f"Deliberate Verschleierung des Transaktionspfads."
                    ),
                    btc_involved=btc,
                ))
        return patterns

    def _detect_convergence(self) -> list[PatternMatch]:
        """
        Detect re-convergence: funds that were split (fan-out) later arrive
        at the same address from multiple paths.
        """
        patterns = []
        # Find addresses with multiple incoming edges from different paths
        for addr, in_edges in self._rev.items():
            unique_senders = {e.from_address for e in in_edges}
            if len(unique_senders) < 2:
                continue
            # Check if senders had a common ancestor (split → recombine)
            # Simplified: flag if total incoming > 1 distinct path
            node = self._nodes.get(addr)
            if node and node.node_type in (NodeType.UNKNOWN, NodeType.CONSOLIDATION):
                node.node_type = NodeType.CONVERGENCE
                total_btc = sum(e.amount_btc for e in in_edges)
                patterns.append(PatternMatch(
                    pattern="convergence",
                    severity="medium",
                    addresses=list(unique_senders) + [addr],
                    txids=list({e.txid for e in in_edges}),
                    description=(
                        f"Re-Konvergenz: {len(unique_senders)} Quellen vereinen sich "
                        f"bei {addr[:10]}… ({total_btc:.6f} BTC). "
                        f"Möglicherweise absichtliche Wiedervereinigung zuvor aufgeteilter Gelder."
                    ),
                    btc_involved=total_btc,
                ))
        return patterns

    def _detect_dead_ends(self) -> list[GraphNode]:
        """
        Addresses that received BTC but have no outgoing edges in our graph.
        Could be: unspent UTXOs, dust, lost wallets, or exchange cold storage.
        """
        dead_ends = []
        for addr, node in self._nodes.items():
            if node.hop_distance == 0:
                continue  # skip victim
            has_outgoing = bool(self._adj.get(addr))
            if not has_outgoing and node.total_received_btc > 0:
                node.is_unspent = True
                if node.node_type == NodeType.UNKNOWN:
                    node.node_type = NodeType.HOLDING
                dead_ends.append(node)
        return dead_ends

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    def _build_summary(
        self,
        patterns: list[PatternMatch],
        dead_ends: list[GraphNode],
        exchanges: list[str],
        max_depth: int,
    ) -> str:
        lines = [f"Transaktionsgraph: {len(self._nodes)} Adressen, {len(self._edges)} Kanten, Tiefe {max_depth}."]

        by_pattern = defaultdict(list)
        for p in patterns:
            by_pattern[p.pattern].append(p)

        if by_pattern["layering"]:
            lines.append(f"⚠ Layering erkannt: {len(by_pattern['layering'])} Kette(n) mit absichtlicher Hop-Verschachtelung.")
        if by_pattern["fan_out"]:
            lines.append(f"Fan-out erkannt: {len(by_pattern['fan_out'])} TX(s) mit breiter Ausgabe-Streuung.")
        if by_pattern["fan_in"]:
            lines.append(f"Konsolidierung erkannt: {len(by_pattern['fan_in'])} TX(s) bündeln mehrere Eingaben.")
        if by_pattern["convergence"]:
            lines.append(f"Re-Konvergenz erkannt: {len(by_pattern['convergence'])} Adresse(n) empfangen Gelder aus mehreren Pfaden.")
        if dead_ends:
            btc_held = sum(n.total_received_btc - n.total_sent_btc for n in dead_ends)
            lines.append(f"{len(dead_ends)} unausgegebene UTXO(s) ({btc_held:.6f} BTC) am Ende der Kette.")
        if exchanges:
            labels = [self._nodes[a].attribution_label or a[:10] for a in exchanges[:3]]
            lines.append(f"Exchange-Endpunkte: {', '.join(labels)}.")

        return " ".join(lines)


# ---------------------------------------------------------------------------
# Convenience: build attribution map from HopChain
# ---------------------------------------------------------------------------

def extract_attribution_map(hop_chain: list, attribution_db=None) -> dict[str, str]:
    """
    Build address → label map from hop chain + optional attribution DB lookup.
    """
    result = {}
    for hop in hop_chain:
        for addr in [getattr(hop, "from_address", ""), getattr(hop, "to_address", "")]:
            if addr and addr not in result and attribution_db:
                label = attribution_db.lookup(addr)
                if label:
                    result[addr] = label
    return result
