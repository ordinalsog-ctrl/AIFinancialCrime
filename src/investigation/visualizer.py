"""
UTXO Chain Visualizer — v3 (Spacious + Copy-enabled)

Changes vs v2:
  - Nodes significantly larger, more breathing room
  - HTML: click-to-copy on every address, TXID, block height
  - SVG: <a href> links to blockstream.info for each TXID
  - Edge labels spread vertically (no overlap)
  - Confidence badge, amount, TX hash on separate lines
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Optional

from src.investigation.confidence_engine import (
    ConfidenceLevel, InvestigationChain, TracingMethod,
)
from src.investigation.peeling_chain import PeelingChainResult

# ---------------------------------------------------------------------------
# Visual constants
# ---------------------------------------------------------------------------

CONF_COLOR = {
    ConfidenceLevel.L1_VERIFIED_FACT:   "#1A7F4B",
    ConfidenceLevel.L2_HIGH_CONFIDENCE: "#1A5FAF",
    ConfidenceLevel.L3_INDICATIVE:      "#B8860B",
    ConfidenceLevel.L4_SPECULATIVE:     "#888888",
}
CONF_LABEL = {
    ConfidenceLevel.L1_VERIFIED_FACT:   "L1  Verified Fact",
    ConfidenceLevel.L2_HIGH_CONFIDENCE: "L2  High Confidence",
    ConfidenceLevel.L3_INDICATIVE:      "L3  Indicative",
    ConfidenceLevel.L4_SPECULATIVE:     "L4  Speculative",
}
CONF_DASH_SVG = {
    ConfidenceLevel.L1_VERIFIED_FACT:   "",
    ConfidenceLevel.L2_HIGH_CONFIDENCE: "",
    ConfidenceLevel.L3_INDICATIVE:      "stroke-dasharray='8 5'",
    ConfidenceLevel.L4_SPECULATIVE:     "stroke-dasharray='3 6'",
}

# Layout — generous spacing
NW_SVG, NH_SVG = 240, 108   # SVG node size
HGAP_SVG       = 140        # gap between nodes
PAD_X_SVG      = 60
PAD_Y_SVG      = 80
LEGEND_H_SVG   = 52

# HTML canvas layout
NW_H, NH_H    = 260, 116
HGAP_H        = 160
PADX_H        = 72
PADY_H        = 90
EDGE_LABEL_Y  = -46   # amount label offset from edge centre
BADGE_Y       = -28   # confidence badge
TXID_Y        = +18   # tx hash below edge


def _short(addr: Optional[str], front=10, back=8) -> str:
    if not addr:
        return "—"
    return addr if len(addr) <= front + back + 3 else f"{addr[:front]}…{addr[-back:]}"


def _ts(ts: Optional[datetime]) -> str:
    return ts.strftime("%Y-%m-%d  %H:%M UTC") if ts else ""


# ---------------------------------------------------------------------------
# Shared data model
# ---------------------------------------------------------------------------

@dataclass
class GNode:
    nid: str
    address: str
    short_addr: str
    is_fraud: bool = False
    is_exchange: bool = False
    exchange_name: Optional[str] = None
    amount_btc: Optional[Decimal] = None
    block_height: Optional[int] = None
    timestamp: Optional[datetime] = None
    col: int = 0
    row: int = 0

    VGAP_SVG: int = 140   # vertical gap between rows (SVG)
    VGAP_H:   int = 160   # vertical gap between rows (HTML)

    def svg_x(self) -> float:
        return PAD_X_SVG + self.col * (NW_SVG + HGAP_SVG)

    def svg_y(self) -> float:
        return PAD_Y_SVG + self.row * (NH_SVG + 140)

    def html_x(self) -> float:
        return PADX_H + self.col * (NW_H + HGAP_H)

    def html_y(self) -> float:
        return PADY_H + self.row * (NH_H + 160)


@dataclass
class GEdge:
    src: GNode
    dst: GNode
    hop_index: int
    confidence: ConfidenceLevel
    method: str
    amount_btc: Decimal
    to_txid: str
    is_peeling: bool = False


@dataclass
class GraphData:
    nodes: list[GNode]
    edges: list[GEdge]
    chain: InvestigationChain
    peeling: Optional[PeelingChainResult]

    def svg_w(self) -> int:
        return int(len(self.nodes) * (NW_SVG + HGAP_SVG) - HGAP_SVG + 2 * PAD_X_SVG)

    def svg_h(self) -> int:
        max_row = max((n.row for n in self.nodes), default=0)
        return (max_row + 1) * (NH_SVG + 140) + 2 * PAD_Y_SVG + LEGEND_H_SVG

    def to_json(self) -> str:
        return json.dumps({
            "case_id":   self.chain.case_id,
            "fraud_btc": str(self.chain.fraud_amount_btc),
            "peeling":   self.peeling.detected if self.peeling else False,
            "nodes": [{
                "id": n.nid, "address": n.address, "short": n.short_addr,
                "is_fraud": n.is_fraud, "is_exchange": n.is_exchange,
                "exchange": n.exchange_name,
                "btc":   str(n.amount_btc) if n.amount_btc else None,
                "block": n.block_height,
                "ts":    n.timestamp.isoformat() if n.timestamp else None,
                "col":   n.col,
                "row":   n.row,
            } for n in self.nodes],
            "edges": [{
                "from": e.src.nid, "to": e.dst.nid,
                "hop":  e.hop_index, "conf": e.confidence.name,
                "color": CONF_COLOR[e.confidence],
                "label": CONF_LABEL[e.confidence],
                "method": e.method,
                "btc":  str(e.amount_btc),
                "txid": e.to_txid,
                "peeling": e.is_peeling,
            } for e in self.edges],
        }, indent=2)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def build_graph(
    chain: InvestigationChain,
    peeling: Optional[PeelingChainResult] = None,
    web_mode: bool = False,
) -> GraphData:
    hops = chain.hops if web_mode else chain.official_report_hops
    peeling_hops = set()
    if peeling and peeling.detected:
        peeling_hops = set(range(1, peeling.chain_length + 1))

    node_map: dict[str, GNode] = {}
    edges: list[GEdge] = []

    def _node(addr: Optional[str], **kw) -> GNode:
        key = addr or "unknown"
        if key not in node_map:
            node_map[key] = GNode(nid=key, address=key, short_addr=_short(addr), **kw)
        else:
            for k, v in kw.items():
                if v is not None:
                    setattr(node_map[key], k, v)
        return node_map[key]

    _node(chain.fraud_address, is_fraud=True,
          amount_btc=chain.fraud_amount_btc, timestamp=chain.fraud_timestamp)

    for hop in hops:
        src = _node(hop.from_address, block_height=hop.block_height_from, timestamp=hop.timestamp_from)
        dst = _node(hop.to_address,
                    is_exchange=bool(getattr(hop, "exchange_name", None)),
                    exchange_name=getattr(hop, "exchange_name", None),
                    block_height=hop.block_height_to, timestamp=hop.timestamp_to,
                    amount_btc=hop.amount_btc)
        edges.append(GEdge(
            src=src, dst=dst, hop_index=hop.hop_index,
            confidence=hop.confidence, method=hop.method.value,
            amount_btc=hop.amount_btc,
            to_txid=hop.to_txid or "",
            is_peeling=hop.hop_index in peeling_hops,
        ))

    # ── Smart layout: detect splits and assign (col, row) ─────────────────
    # Count how many outgoing edges each node has
    from collections import defaultdict, deque
    out_count: dict[str, int] = defaultdict(int)
    for e in edges:
        out_count[e.src.nid] += 1

    # BFS from fraud origin to assign columns; splits get same col, different rows
    col_map: dict[str, int] = {}
    row_map: dict[str, int] = {}
    visited: set[str] = set()
    queue: deque[tuple[str, int, int]] = deque()
    queue.append((chain.fraud_address or "unknown", 0, 0))

    # Track how many rows are used per column (for row assignment)
    col_row_cursor: dict[int, int] = defaultdict(int)

    while queue:
        nid, col, row = queue.popleft()
        if nid in visited:
            continue
        visited.add(nid)
        col_map[nid] = col
        row_map[nid] = row
        col_row_cursor[col] = max(col_row_cursor[col], row + 1)

        children = [e.dst.nid for e in edges if e.src.nid == nid]
        for i, child_nid in enumerate(children):
            if child_nid not in visited:
                child_row = row_map.get(nid, 0) if i == 0 else col_row_cursor.get(col + 1, 0) + i - 1
                queue.append((child_nid, col + 1, child_row if i == 0 else i))

    # Apply layout to nodes
    for n in node_map.values():
        nid = n.nid
        n.col = col_map.get(nid, 0)
        n.row = row_map.get(nid, 0)

    return GraphData(nodes=list(node_map.values()), edges=edges, chain=chain, peeling=peeling)


# ---------------------------------------------------------------------------
# SVG — light theme, court-ready, links to blockstream
# ---------------------------------------------------------------------------

def generate_svg(chain: InvestigationChain, peeling: Optional[PeelingChainResult] = None) -> str:
    g = build_graph(chain, peeling, web_mode=False)
    W, H = g.svg_w(), g.svg_h()
    o = []

    o.append(f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" '
             f'xmlns:xlink="http://www.w3.org/1999/xlink" '
             f'font-family="Arial, Helvetica, sans-serif">')
    o.append("<defs>")
    for lv, col in CONF_COLOR.items():
        o.append(f'<marker id="arr_{lv.name}" markerWidth="10" markerHeight="10" '
                 f'refX="8" refY="4" orient="auto">'
                 f'<path d="M0,0 L0,8 L10,4 z" fill="{col}"/></marker>')
    o.append('<filter id="sh"><feDropShadow dx="0" dy="1.5" stdDeviation="2.5" '
             'flood-color="#00000015"/></filter>')
    o.append("</defs>")
    o.append(f'<rect width="{W}" height="{H}" fill="white"/>')
    # header
    o.append(f'<rect x="0" y="0" width="{W}" height="36" fill="#1C2B3A"/>')
    o.append(f'<text x="16" y="23" font-size="12" font-weight="bold" fill="white" '
             f'letter-spacing="0.08em">TRANSACTION CHAIN OF CUSTODY</text>')
    o.append(f'<text x="{W-16}" y="23" font-size="10" fill="#8BA0B5" text-anchor="end">'
             f'Case: {chain.case_id}   ·   {chain.fraud_amount_btc} BTC</text>')

    nmap = {n.nid: n for n in g.nodes}

    # Edges
    for e in g.edges:
        s, d = e.src, e.dst
        col  = CONF_COLOR[e.confidence]
        dash = CONF_DASH_SVG[e.confidence]
        x1 = s.svg_x() + NW_SVG + 3
        y1 = s.svg_y() + NH_SVG // 2
        x2 = d.svg_x() - 3
        y2 = d.svg_y() + NH_SVG // 2
        mx = (x1 + x2) / 2
        my = y1

        o.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                 f'stroke="{col}" stroke-width="2" {dash} '
                 f'marker-end="url(#arr_{e.confidence.name})"/>')

        # Amount (top)
        o.append(f'<text x="{mx}" y="{my-46}" text-anchor="middle" '
                 f'font-size="10.5" fill="#1C2B3A" font-weight="bold">'
                 f'{e.amount_btc} BTC</text>')
        # Confidence badge
        bw = 126
        o.append(f'<rect x="{mx-bw/2}" y="{my-38}" width="{bw}" height="16" '
                 f'rx="8" fill="{col}" opacity="0.12" stroke="{col}" stroke-width="0.8"/>')
        o.append(f'<text x="{mx}" y="{my-27}" text-anchor="middle" '
                 f'font-size="8" fill="{col}" font-weight="bold" letter-spacing="0.04em">'
                 f'{CONF_LABEL[e.confidence]}</text>')
        # TX hash — linked
        txid_short = e.to_txid[:14] + "…" if e.to_txid else ""
        o.append(f'<a xlink:href="https://blockstream.info/tx/{e.to_txid}" target="_blank">')
        o.append(f'<text x="{mx}" y="{my+18}" text-anchor="middle" '
                 f'font-size="8" fill="#2980B9" font-family="Courier New, monospace" '
                 f'text-decoration="underline">tx: {txid_short}</text>')
        o.append('</a>')

        # Peeling bracket
        if e.is_peeling:
            by   = s.svg_y() + NH_SVG + 18
            bx1  = s.svg_x() + 6
            bx2  = d.svg_x() + NW_SVG - 6
            bmx  = (bx1 + bx2) / 2
            o.append(f'<line x1="{bx1}" y1="{by}" x2="{bx2}" y2="{by}" '
                     f'stroke="#B8860B" stroke-width="1.2" stroke-dasharray="5 3"/>')
            o.append(f'<line x1="{bx1}" y1="{by}" x2="{bx1}" y2="{by-8}" stroke="#B8860B" stroke-width="1.2"/>')
            o.append(f'<line x1="{bx2}" y1="{by}" x2="{bx2}" y2="{by-8}" stroke="#B8860B" stroke-width="1.2"/>')
            o.append(f'<rect x="{bmx-34}" y="{by+4}" width="68" height="15" '
                     f'rx="3" fill="#FFFBEA" stroke="#B8860B" stroke-width="0.8"/>')
            o.append(f'<text x="{bmx}" y="{by+14}" text-anchor="middle" '
                     f'font-size="8" fill="#7A5C00" font-weight="bold" letter-spacing="0.05em">'
                     f'PEELING CHAIN</text>')

    # Nodes
    for n in g.nodes:
        x, y = n.svg_x(), n.svg_y()
        if n.is_fraud:
            bg, bdr, bdw = "#FFF0F0", "#C0392B", 2.5
            hdr_fill, hdr_text = "#C0392B", "FRAUD ORIGIN"
        elif n.is_exchange:
            bg, bdr, bdw = "#FFF8F8", "#C0392B", 2.5
            hdr_fill = "#C0392B"
            hdr_text = f"⚑  {n.exchange_name or 'EXCHANGE'}"
        else:
            bg, bdr, bdw = "#FAFBFC", "#C5CDD8", 1.2
            hdr_fill, hdr_text = "#1C2B3A", f"HOP {n.col}"

        o.append(f'<rect x="{x}" y="{y}" width="{NW_SVG}" height="{NH_SVG}" '
                 f'rx="6" fill="{bg}" stroke="{bdr}" stroke-width="{bdw}" filter="url(#sh)"/>')
        # header strip
        o.append(f'<rect x="{x}" y="{y}" width="{NW_SVG}" height="20" rx="6" fill="{hdr_fill}"/>')
        o.append(f'<rect x="{x}" y="{y+14}" width="{NW_SVG}" height="6" fill="{hdr_fill}"/>')
        o.append(f'<text x="{x+NW_SVG/2}" y="{y+14}" text-anchor="middle" '
                 f'font-size="8.5" font-weight="bold" fill="white" letter-spacing="0.06em">'
                 f'{hdr_text}</text>')

        # Address — linked to blockstream
        o.append(f'<a xlink:href="https://blockstream.info/address/{n.address}" target="_blank">')
        o.append(f'<text x="{x+NW_SVG/2}" y="{y+38}" text-anchor="middle" '
                 f'font-size="8.5" fill="#1A5FAF" font-family="Courier New, monospace" '
                 f'font-weight="bold" text-decoration="underline">{n.short_addr}</text>')
        o.append('</a>')

        # Block + timestamp
        if n.block_height:
            o.append(f'<text x="{x+10}" y="{y+56}" font-size="8" fill="#555">'
                     f'Block  {n.block_height:,}</text>')
        if n.timestamp:
            o.append(f'<text x="{x+NW_SVG/2}" y="{y+72}" text-anchor="middle" '
                     f'font-size="7.5" fill="#777">{_ts(n.timestamp)}</text>')
        # Amount
        if n.amount_btc and not n.is_fraud:
            o.append(f'<text x="{x+NW_SVG-10}" y="{y+56}" text-anchor="end" '
                     f'font-size="8" fill="#1A7F4B" font-weight="bold">'
                     f'{n.amount_btc} BTC</text>')
        # Freeze notice
        if n.is_exchange:
            o.append(f'<rect x="{x+8}" y="{y+NH_SVG-20}" width="{NW_SVG-16}" height="14" '
                     f'rx="3" fill="#FEE2E2" stroke="#C0392B" stroke-width="0.7"/>')
            o.append(f'<text x="{x+NW_SVG/2}" y="{y+NH_SVG-10}" text-anchor="middle" '
                     f'font-size="7.5" fill="#C0392B" font-weight="bold" letter-spacing="0.05em">'
                     f'FREEZE REQUEST REQUIRED</text>')

    # Legend
    ly = NH_SVG + 2 * PAD_Y_SVG + 10
    o.append(f'<rect x="0" y="{ly-6}" width="{W}" height="{LEGEND_H_SVG}" fill="#F6F8FA"/>')
    o.append(f'<line x1="0" y1="{ly-6}" x2="{W}" y2="{ly-6}" stroke="#DDE2E8" stroke-width="0.8"/>')
    lx = 16
    o.append(f'<text x="{lx}" y="{ly+14}" font-size="8" fill="#555" font-weight="bold" '
             f'letter-spacing="0.05em">CONFIDENCE LEVELS:</text>')
    lx += 114
    for lv in [ConfidenceLevel.L1_VERIFIED_FACT, ConfidenceLevel.L2_HIGH_CONFIDENCE]:
        c = CONF_COLOR[lv]
        o.append(f'<rect x="{lx}" y="{ly+5}" width="12" height="12" rx="2" fill="{c}"/>')
        o.append(f'<text x="{lx+16}" y="{ly+15}" font-size="8.5" fill="{c}" font-weight="bold">'
                 f'{CONF_LABEL[lv]}</text>')
        lx += 152
    if g.peeling and g.peeling.detected:
        o.append(f'<rect x="{lx}" y="{ly+5}" width="12" height="12" rx="2" fill="#B8860B" opacity="0.5"/>')
        o.append(f'<text x="{lx+16}" y="{ly+15}" font-size="8.5" fill="#7A5C00" font-weight="bold">'
                 f'Peeling Chain Detected</text>')
    o.append(f'<text x="{W-16}" y="{ly+32}" text-anchor="end" font-size="7.5" fill="#AAA">'
             f'AIFinancialCrime Forensik-System  ·  {chain.case_id}</text>')
    o.append("</svg>")
    return "\n".join(o)


# ---------------------------------------------------------------------------
# HTML — dark professional, full copy UI
# ---------------------------------------------------------------------------

def generate_html(
    chain: InvestigationChain,
    peeling: Optional[PeelingChainResult] = None,
    title: str = "Transaction Chain Visualizer",
) -> str:
    g    = build_graph(chain, peeling, web_mode=True)
    gj   = g.to_json()
    cc   = json.dumps({k.name: v for k, v in CONF_COLOR.items()})
    cl   = json.dumps({k.name: v for k, v in CONF_LABEL.items()})

    return textwrap.dedent(f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
:root {{
  --bg:#111318; --surface:#1A1D24; --card:#1E2229; --border:#2E3340;
  --text:#D4DAE8; --muted:#6B7590; --green:#1A7F4B; --blue:#1A5FAF;
  --red:#C0392B; --amber:#B8860B; --hdr:#0E1116;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;
     display:flex;flex-direction:column;height:100vh;overflow:hidden}}

/* Header */
header{{background:var(--hdr);border-bottom:1px solid var(--border);
        padding:0 20px;height:52px;display:flex;align-items:center;
        justify-content:space-between;flex-shrink:0}}
.hd-left{{display:flex;align-items:center;gap:14px}}
.logo{{width:32px;height:32px;border-radius:7px;background:var(--red);display:flex;
       align-items:center;justify-content:center;font-size:13px;font-weight:900;
       color:white;letter-spacing:-1px;flex-shrink:0}}
.hd-title{{font-size:13px;font-weight:600;letter-spacing:.02em}}
.hd-sub{{font-size:10px;color:var(--muted);font-family:'Courier New',monospace;margin-top:1px}}
.stats{{display:flex;gap:24px}}
.stat{{display:flex;flex-direction:column;align-items:flex-end}}
.stat-val{{font-size:13px;font-weight:700}}
.stat-key{{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em}}

/* Toolbar */
.toolbar{{background:var(--surface);border-bottom:1px solid var(--border);
          padding:8px 20px;display:flex;gap:8px;align-items:center;flex-shrink:0}}
.sep{{width:1px;height:20px;background:var(--border);margin:0 4px}}
.lbl{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em}}
.btn{{padding:5px 14px;border-radius:5px;border:1px solid var(--border);
      background:transparent;color:var(--muted);font-size:11px;
      cursor:pointer;font-family:inherit;transition:all .15s;white-space:nowrap}}
.btn:hover{{border-color:var(--blue);color:var(--text)}}
.btn.on{{border-color:var(--green);color:var(--green);background:#0D2A1A}}

/* Canvas */
#wrap{{flex:1;overflow:hidden;position:relative}}
canvas{{position:absolute;inset:0;cursor:grab}}
canvas.drag{{cursor:grabbing}}

/* Tooltip */
#tip{{position:absolute;display:none;background:var(--card);border:1px solid var(--border);
     border-radius:8px;padding:14px 16px;font-size:11px;line-height:2;
     pointer-events:none;max-width:340px;z-index:20;
     box-shadow:0 6px 32px #00000060}}
.tr{{display:flex;gap:8px;align-items:baseline}}
.tk{{color:var(--muted);min-width:80px;flex-shrink:0;font-size:10px;
     text-transform:uppercase;letter-spacing:.05em}}
.tv{{color:var(--text);font-weight:500;word-break:break-all}}
.tv.mono{{font-family:'Courier New',monospace;font-size:10px}}
.tv.green{{color:#2ECC71}}
.tv.red{{color:#E74C3C}}
.tv.amber{{color:#F39C12}}

/* Copy button */
.copy-btn{{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;
           border-radius:4px;border:1px solid var(--border);background:transparent;
           color:var(--muted);font-size:9px;cursor:pointer;font-family:inherit;
           transition:all .12s;pointer-events:all;margin-left:6px;vertical-align:middle}}
.copy-btn:hover{{border-color:var(--blue);color:var(--text)}}
.copy-btn.copied{{border-color:var(--green);color:var(--green)}}

/* Toast */
#toast{{position:fixed;bottom:40px;left:50%;transform:translateX(-50%) translateY(20px);
        background:var(--card);border:1px solid var(--green);border-radius:6px;
        padding:8px 18px;font-size:11px;color:var(--green);
        opacity:0;transition:all .2s;pointer-events:none;z-index:99}}
#toast.show{{opacity:1;transform:translateX(-50%) translateY(0)}}

/* Legend */
#legend{{position:absolute;bottom:16px;left:16px;background:var(--card);
         border:1px solid var(--border);border-radius:8px;padding:12px 16px;
         font-size:10px;line-height:2.1}}
.lg{{display:flex;align-items:center;gap:9px;color:var(--muted)}}
.sw{{width:28px;height:3px;border-radius:2px;flex-shrink:0}}
.sw.d{{background:repeating-linear-gradient(90deg,#B8860B 0 7px,transparent 7px 12px)}}
.nd{{width:13px;height:13px;border-radius:3px;flex-shrink:0}}

/* Status bar */
#sb{{background:var(--hdr);border-top:1px solid var(--border);padding:5px 20px;
     font-size:10px;color:var(--muted);flex-shrink:0;display:flex;
     justify-content:space-between}}
</style>
</head>
<body>

<header>
  <div class="hd-left">
    <div class="logo">AFC</div>
    <div>
      <div class="hd-title">Transaction Chain of Custody</div>
      <div class="hd-sub">{chain.case_id}</div>
    </div>
  </div>
  <div class="stats">
    <div class="stat">
      <div class="stat-val">{chain.fraud_amount_btc} BTC</div>
      <div class="stat-key">Fraud Amount</div>
    </div>
    <div class="stat">
      <div class="stat-val">{len(chain.hops)}</div>
      <div class="stat-key">Traced Hops</div>
    </div>
    <div class="stat">
      <div class="stat-val" style="color:{'#E74C3C' if chain.exchange_hits else 'inherit'}">{len(chain.exchange_hits)}</div>
      <div class="stat-key">Exchange Hits</div>
    </div>
    <div class="stat">
      <div class="stat-val" style="color:{'#F39C12' if (peeling and peeling.detected) else 'inherit'}">
        {'Yes' if (peeling and peeling.detected) else 'No'}</div>
      <div class="stat-key">Peeling Chain</div>
    </div>
  </div>
</header>

<div class="toolbar">
  <span class="lbl">Show</span>
  <button class="btn on" id="btn-l12">L1 + L2 only</button>
  <button class="btn" id="btn-all">All levels</button>
  <div class="sep"></div>
  <button class="btn on" id="btn-peel">Peeling overlay</button>
  <div class="sep"></div>
  <button class="btn" id="btn-reset">⟲  Reset view</button>
  <span style="margin-left:auto;font-size:10px;color:var(--muted)">
    Scroll to zoom · Drag to pan · Hover for details · Click fields to copy
  </span>
</div>

<div id="wrap">
  <canvas id="c"></canvas>
  <div id="tip"></div>
  <div id="legend">
    <div class="lg"><div class="sw" style="background:#1A7F4B;height:2.5px"></div> L1 · Verified Fact</div>
    <div class="lg"><div class="sw" style="background:#1A5FAF;height:2.5px"></div> L2 · High Confidence</div>
    <div class="lg"><div class="sw d"></div> L3 · Indicative</div>
    <div style="margin-top:7px">
    <div class="lg"><div class="nd" style="background:#5C1010;border:1.5px solid #C0392B"></div> Fraud Origin</div>
    <div class="lg"><div class="nd" style="background:#200D0D;border:1.5px solid #C0392B"></div> Exchange Hit</div>
    </div>
  </div>
</div>

<div id="sb">
  <span id="sb-l">Hover a node to inspect · Click any field in the tooltip to copy</span>
  <span>AIFinancialCrime Forensik-System</span>
</div>
<div id="toast">Copied to clipboard</div>

<script>
const G={gj};
const CC={cc};
const CL={cl};

// Layout
const NW={NW_H},NH={NH_H},HGAP={HGAP_H},PX={PADX_H},PY={PADY_H};
let showAll=false,showPeel=true,scale=1,ox=0,oy=0,drag=false,lx=0,ly=0;

const canvas=document.getElementById('c');
const ctx=canvas.getContext('2d');
const wrap=document.getElementById('wrap');
const tip=document.getElementById('tip');
const sb=document.getElementById('sb-l');
const toast=document.getElementById('toast');

// Assign layout coords
const VGAP=160;
const nmap={{}};
G.nodes.forEach(n=>{{
  n._x=PX+n.col*(NW+HGAP);
  n._y=PY+(n.row||0)*(NH+VGAP);
  nmap[n.id]=n;
}});
const maxCol=Math.max(...G.nodes.map(n=>n.col),0);
const maxRow=Math.max(...G.nodes.map(n=>n.row||0),0);
const totW=(maxCol+1)*(NW+HGAP)-HGAP+2*PX;
const totH=(maxRow+1)*(NH+VGAP)+2*PY+60;

function resize(){{canvas.width=wrap.clientWidth;canvas.height=wrap.clientHeight;draw();}}
window.addEventListener('resize',resize);

function visEdges(){{
  return G.edges.filter(e=>showAll||e.conf==='L1_VERIFIED_FACT'||e.conf==='L2_HIGH_CONFIDENCE');
}}

function rrect(c,x,y,w,h,r){{
  c.beginPath();
  c.moveTo(x+r,y);c.lineTo(x+w-r,y);c.arcTo(x+w,y,x+w,y+r,r);
  c.lineTo(x+w,y+h-r);c.arcTo(x+w,y+h,x+w-r,y+h,r);
  c.lineTo(x+r,y+h);c.arcTo(x,y+h,x,y+h-r,r);
  c.lineTo(x,y+r);c.arcTo(x,y,x+r,y,r);
  c.closePath();
}}

function arrow(c,x,y,col){{
  c.fillStyle=col;c.beginPath();
  c.moveTo(x,y);c.lineTo(x-12,y-5.5);c.lineTo(x-12,y+5.5);
  c.closePath();c.fill();
}}

function draw(){{
  const W=canvas.width,H=canvas.height,c=ctx;
  c.clearRect(0,0,W,H);
  c.save();
  c.translate(ox+W/2,oy+H/2);
  c.scale(scale,scale);
  c.translate(-totW/2,-totH/2);

  visEdges().forEach(e=>{{
    const s=nmap[e.from],d=nmap[e.to];
    if(!s||!d)return;
    const col=CC[e.conf]||'#888';
    const alpha=e.conf==='L3_INDICATIVE'?.55:e.conf==='L4_SPECULATIVE'?.28:1;
    const lw=e.conf==='L1_VERIFIED_FACT'?2.5:2;
    const x1=s._x+NW+3,y1=s._y+NH/2,x2=d._x-3,y2=d._y+NH/2;
    const mx=(x1+x2)/2,my=y1;

    c.save();c.globalAlpha=alpha;c.strokeStyle=col;c.lineWidth=lw;
    if(e.conf==='L3_INDICATIVE')c.setLineDash([9,6]);
    else if(e.conf==='L4_SPECULATIVE')c.setLineDash([3,7]);
    else c.setLineDash([]);
    c.beginPath();c.moveTo(x1,y1);c.lineTo(x2-12,y2);c.stroke();
    c.setLineDash([]);arrow(c,x2,y2,col);

    // Amount
    c.globalAlpha=1;c.fillStyle='#D4DAE8';
    c.font='bold 11px Segoe UI';c.textAlign='center';
    c.fillText(e.btc+' BTC',mx,my-48);

    // Confidence badge
    const bw=130,bh=17;
    c.globalAlpha=.12;c.fillStyle=col;rrect(c,mx-bw/2,my-41,bw,bh,8);c.fill();
    c.globalAlpha=1;c.strokeStyle=col;c.lineWidth=.7;
    rrect(c,mx-bw/2,my-41,bw,bh,8);c.stroke();
    c.fillStyle=col;c.font='bold 8.5px Segoe UI';c.textAlign='center';
    c.fillText(CL[e.conf]||e.conf,mx,my-28);

    // TX hash
    c.fillStyle='#5B6880';c.font='8.5px Courier New';c.textAlign='center';
    c.fillText('tx: '+(e.txid||'').substring(0,14)+'…',mx,my+20);

    // Peeling bracket
    if(showPeel&&e.peeling){{
      const by=d._y+NH+18,bx1=s._x+6,bx2=d._x+NW-6,bmx=(bx1+bx2)/2;
      c.strokeStyle='#B8860B';c.lineWidth=1.2;c.setLineDash([6,4]);
      c.beginPath();c.moveTo(bx1,by);c.lineTo(bx2,by);c.stroke();
      c.setLineDash([]);
      c.beginPath();c.moveTo(bx1,by);c.lineTo(bx1,by-8);c.stroke();
      c.beginPath();c.moveTo(bx2,by);c.lineTo(bx2,by-8);c.stroke();
      c.globalAlpha=.92;rrect(c,bmx-36,by+4,72,16,3);
      c.fillStyle='#2A1E00';c.fill();
      c.strokeStyle='#B8860B';c.lineWidth=.7;rrect(c,bmx-36,by+4,72,16,3);c.stroke();
      c.fillStyle='#D4A017';c.font='bold 8px Segoe UI';c.textAlign='center';
      c.fillText('PEELING CHAIN',bmx,by+15);
    }}
    c.restore();
  }});

  G.nodes.forEach(n=>{{
    const x=n._x,y=n._y,c=ctx;
    c.save();
    if(n.is_fraud||n.is_exchange){{c.shadowColor='#C0392B';c.shadowBlur=12;}}

    const bg=n.is_fraud?'#2A0D0D':n.is_exchange?'#200D0D':'#1E2229';
    const bdr=n.is_fraud||n.is_exchange?'#C0392B':'#2E3340';
    c.fillStyle=bg;c.strokeStyle=bdr;c.lineWidth=n.is_fraud||n.is_exchange?2:1;
    rrect(c,x,y,NW,NH,7);c.fill();c.stroke();c.shadowBlur=0;

    // Header strip
    const hbg=n.is_fraud||n.is_exchange?'#C0392B':'#0E1116';
    c.fillStyle=hbg;rrect(c,x,y,NW,22,7);c.fill();
    c.fillStyle=hbg;c.fillRect(x,y+16,NW,6);

    const hl=n.is_fraud?'FRAUD ORIGIN':n.is_exchange?'⚑  '+(n.exchange||'EXCHANGE'):'HOP '+n.col;
    c.fillStyle='white';c.font='bold 9px Segoe UI';c.textAlign='center';
    c.fillText(hl,x+NW/2,y+15);

    // Address
    c.fillStyle=n.is_fraud?'#FF8080':n.is_exchange?'#FF9999':'#7EB5E0';
    c.font='9px Courier New';c.textAlign='center';
    c.fillText(n.short,x+NW/2,y+38);

    // Block
    if(n.block){{
      c.fillStyle='#5B6880';c.font='8.5px Segoe UI';c.textAlign='left';
      c.fillText('Block  '+n.block.toLocaleString(),x+10,y+56);
    }}
    // Amount
    if(n.btc&&!n.is_fraud){{
      c.fillStyle='#2ECC71';c.font='bold 8.5px Segoe UI';c.textAlign='right';
      c.fillText(n.btc+' BTC',x+NW-10,y+56);
    }}
    // Timestamp
    if(n.ts){{
      const ts=n.ts.substring(0,16).replace('T','  ');
      c.fillStyle='#434B5E';c.font='8px Segoe UI';c.textAlign='center';
      c.fillText(ts+' UTC',x+NW/2,y+72);
    }}
    // Freeze notice
    if(n.is_exchange){{
      rrect(c,x+7,y+NH-20,NW-14,14,3);
      c.fillStyle='#3D0A0A';c.fill();
      c.strokeStyle='#C0392B';c.lineWidth=.6;rrect(c,x+7,y+NH-20,NW-14,14,3);c.stroke();
      c.fillStyle='#E06060';c.font='bold 7.5px Segoe UI';c.textAlign='center';
      c.fillText('FREEZE REQUEST REQUIRED',x+NW/2,y+NH-10);
    }}
    c.restore();
  }});

  c.restore();
}}

// ── Hit test ──
function hitNode(mx,my){{
  const W=canvas.width,H=canvas.height;
  const wx=(mx-ox-W/2)/scale+totW/2;
  const wy=(my-oy-H/2)/scale+totH/2;
  return G.nodes.find(n=>wx>=n._x&&wx<=n._x+NW&&wy>=n._y&&wy<=n._y+NH)||null;
}}

function hitEdge(mx,my){{
  const W=canvas.width,H=canvas.height;
  const wx=(mx-ox-W/2)/scale+totW/2;
  const wy=(my-oy-H/2)/scale+totH/2;
  // Check if pointer is near the edge label zone (centre between nodes, ±30px vertical)
  return visEdges().find(e=>{{
    const s=nmap[e.from],d=nmap[e.to];
    if(!s||!d)return false;
    const x1=s._x+NW, x2=d._x;
    const mx2=(x1+x2)/2, my2=s._y+NH/2;
    return wx>=(mx2-66)&&wx<=(mx2+66)&&wy>=(my2-56)&&wy<=(my2+26);
  }})||null;
}}

// ── Copy ──
let toastTimer;
function copyText(text){{
  navigator.clipboard.writeText(text).then(()=>{{
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer=setTimeout(()=>toast.classList.remove('show'),1800);
  }});
}}

function copyBtn(text,label){{
  return `<button class="copy-btn" onclick="copyText('${{text.replace(/'/g,"\\'")}}');this.textContent='✓ Copied';this.classList.add('copied');setTimeout(()=>{{this.textContent='⎘ Copy';this.classList.remove('copied')}},1500)">⎘ ${{label||'Copy'}}</button>`;
}}

// ── Tooltip ──
canvas.addEventListener('mousemove',ev=>{{
  const r=canvas.getBoundingClientRect();
  const mx=ev.clientX-r.left,my=ev.clientY-r.top;
  if(drag){{ox+=mx-lx;oy+=my-ly;lx=mx;ly=my;draw();return;}}
  const n=hitNode(mx,my);
  if(n){{
    canvas.style.cursor='default';
    const tipX=Math.min(mx+18,canvas.width-360);
    const tipY=Math.max(my-16,8);
    tip.style.display='block';tip.style.left=tipX+'px';tip.style.top=tipY+'px';
    tip.style.pointerEvents='all';

    const confLabel=n.is_fraud?'<span style="color:#E74C3C;font-weight:700">FRAUD ORIGIN</span>':
                    n.is_exchange?`<span style="color:#E74C3C;font-weight:700">Exchange Hit</span>`:
                    'Intermediate';

    tip.innerHTML=`
      <div class="tr">
        <span class="tk">Address</span>
        <span class="tv mono">${{n.short}}${{copyBtn(n.address,'Full Address')}}</span>
      </div>
      <div class="tr"><span class="tk">Type</span><span class="tv">${{confLabel}}</span></div>
      ${{n.exchange?`<div class="tr"><span class="tk">Exchange</span>
        <span class="tv" style="color:#E74C3C">⚑ ${{n.exchange}}${{copyBtn(n.exchange,'Name')}}</span></div>`:''}}
      ${{n.btc?`<div class="tr"><span class="tk">Amount</span>
        <span class="tv green">${{n.btc}} BTC${{copyBtn(n.btc,'Amount')}}</span></div>`:''}}
      ${{n.block?`<div class="tr"><span class="tk">Block</span>
        <span class="tv">${{n.block.toLocaleString()}}${{copyBtn(String(n.block),'Block')}}</span></div>`:''}}
      ${{n.ts?`<div class="tr"><span class="tk">Timestamp</span>
        <span class="tv">${{n.ts.substring(0,19).replace('T','  ')}} UTC</span></div>`:''}}
      <div class="tr" style="margin-top:6px">
        <span class="tk"></span>
        <a href="https://blockstream.info/address/${{n.address}}" target="_blank"
           style="color:var(--blue);font-size:10px;text-decoration:none">
          ↗ View on Blockstream</a>
      </div>
    `;
    sb.textContent=n.is_exchange?`Exchange: ${{n.exchange}} — click fields to copy`:
                  n.is_fraud?'Fraud origin — click fields to copy':
                  `Hop ${{n.col}} — click fields to copy`;
  }} else {{
    tip.style.pointerEvents='none';
    const edge=hitEdge(mx,my);
    if(edge){{
      canvas.style.cursor='default';
      const tipX=Math.min(mx+18,canvas.width-340);
      const tipY=Math.max(my-16,8);
      tip.style.display='block';tip.style.left=tipX+'px';tip.style.top=tipY+'px';
      tip.style.pointerEvents='all';
      const confCol=CC[edge.conf]||'#888';
      tip.innerHTML=`
        <div class="tr">
          <span class="tk">TX Hash</span>
          <span class="tv mono" style="font-size:10px">${{edge.txid.substring(0,16)}}…${{copyBtn(edge.txid,'Full TXID')}}</span>
        </div>
        <div class="tr">
          <span class="tk">Confidence</span>
          <span class="tv" style="color:${{confCol}};font-weight:700">${{CL[edge.conf]||edge.conf}}</span>
        </div>
        <div class="tr">
          <span class="tk">Amount</span>
          <span class="tv green">${{edge.btc}} BTC${{copyBtn(edge.btc,'Amount')}}</span>
        </div>
        <div class="tr">
          <span class="tk">Method</span>
          <span class="tv">${{edge.method.replace(/_/g,' ').toLowerCase()}}</span>
        </div>
        <div class="tr" style="margin-top:6px">
          <span class="tk"></span>
          <a href="https://blockstream.info/tx/${{edge.txid}}" target="_blank"
             style="color:var(--blue);font-size:10px;text-decoration:none">
            ↗ View transaction on Blockstream</a>
        </div>
      `;
      sb.textContent=`Hop ${{edge.hop}}: ${{edge.btc}} BTC — click TXID to copy`;
    }} else {{
      // Hide tip only if not hovering it
      const tr=tip.getBoundingClientRect();
      const overTip=ev.clientX>=tr.left&&ev.clientX<=tr.right&&ev.clientY>=tr.top&&ev.clientY<=tr.bottom;
      if(!overTip){{tip.style.display='none';canvas.style.cursor=drag?'grabbing':'grab';}}
      sb.textContent='Hover a node or edge to inspect · Click any field to copy';
    }}
  }}
}});
tip.addEventListener('mouseleave',()=>{{tip.style.display='none';}});

canvas.addEventListener('mousedown',e=>{{
  drag=true;canvas.classList.add('drag');
  const r=canvas.getBoundingClientRect();lx=e.clientX-r.left;ly=e.clientY-r.top;
}});
canvas.addEventListener('mouseup',()=>{{drag=false;canvas.classList.remove('drag');}});
canvas.addEventListener('mouseleave',()=>{{drag=false;}});
canvas.addEventListener('wheel',e=>{{
  e.preventDefault();
  scale=Math.min(3.5,Math.max(0.12,scale*(e.deltaY<0?1.1:.91)));
  draw();
}},{{passive:false}});

document.getElementById('btn-l12').addEventListener('click',function(){{
  showAll=false;this.classList.add('on');
  document.getElementById('btn-all').classList.remove('on');draw();
}});
document.getElementById('btn-all').addEventListener('click',function(){{
  showAll=true;this.classList.add('on');
  document.getElementById('btn-l12').classList.remove('on');draw();
}});
document.getElementById('btn-peel').addEventListener('click',function(){{
  showPeel=!showPeel;this.classList.toggle('on');draw();
}});
document.getElementById('btn-reset').addEventListener('click',()=>{{scale=1;ox=0;oy=0;draw();}});

resize();
</script>
</body>
</html>""")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save_svg(chain, output_path, peeling=None):
    with open(output_path, "w") as f:
        f.write(generate_svg(chain, peeling))
    return output_path


def save_html(chain, output_path, peeling=None, title="Transaction Chain Visualizer"):
    with open(output_path, "w") as f:
        f.write(generate_html(chain, peeling, title))
    return output_path
