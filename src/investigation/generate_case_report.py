#!/usr/bin/env python3
"""
AIFinancialCrime - report generator
===================================
This module is intended to be used by report_endpoint.py.
All runtime data (CASE, HOPS, EXCHANGES_IDENTIFIED) is injected before PDF
generation. The defaults in this module are placeholders only.
"""

import hashlib
import io
import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak,
    Paragraph, SimpleDocTemplate, Spacer,
    Table, TableStyle,
)

# ---------------------------------------------------------------------------
# Falldaten
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Laufzeit-Daten — werden von report_endpoint.py VOR der PDF-Generierung gesetzt
# Nie direkt hier ändern. Kein Hardcoding. Nur leere Vorlage.
# ---------------------------------------------------------------------------

CASE: dict = {}
HOPS: list = []
EXCHANGES_IDENTIFIED: list = []

# ---------------------------------------------------------------------------
# Farben & Styles
# ---------------------------------------------------------------------------

C_DARK       = colors.HexColor("#1A1A2E")
C_PRIMARY    = colors.HexColor("#16213E")
C_ACCENT     = colors.HexColor("#0F3460")
C_ALERT      = colors.HexColor("#C0392B")
C_WARNING    = colors.HexColor("#E67E22")
C_SUCCESS    = colors.HexColor("#1E8449")
C_LIGHT      = colors.HexColor("#F4F6F7")
C_BORDER     = colors.HexColor("#D5D8DC")
C_WHITE      = colors.white
C_GREY       = colors.HexColor("#AEB6BF")

CONF_COLORS = {
    "L1": C_SUCCESS,
    "L2": C_ACCENT,
    "L3": C_WARNING,
    "L4": C_ALERT,
}

MARGIN = 18 * mm
PAGE_W = A4[0]
PAGE_H = A4[1]


def _case_text(key: str, fallback: str = "—") -> str:
    value = CASE.get(key)
    if value is None:
        return fallback
    text = str(value).strip()
    return text or fallback


def _wallet_label() -> str:
    wallet = _case_text("wallet_type", "")
    return wallet or "Wallet"


def _btc_label(value) -> str:
    text = str(value or "").strip()
    if not text:
        return "—"
    return text if "BTC" in text.upper() else f"{text} BTC"


def _amount_label() -> str:
    btc = _btc_label(CASE.get("fraud_amount"))
    eur = _case_text("fraud_amount_eur", "")
    if eur and eur != "—":
        return f"{btc} ({eur})"
    return btc


def _freeze_summary_rows(exchange_data: dict) -> list[list[str]]:
    all_addresses = exchange_data.get("all_addresses") or [
        (exchange_data["address"], exchange_data["btc_involved"])
    ]
    address_count = len(all_addresses)
    rows = [
        ["Exchange", exchange_data["name"]],
        ["Attributed address count", str(address_count)],
        ["Confidence", f"{exchange_data['confidence']} - Forensically corroborated exchange attribution"],
        ["Total BTC involved", f"{exchange_data['btc_involved']:.8f} BTC"],
        ["Attribution basis", exchange_data.get("note", "See attached forensic report.")],
        ["Wallet ID", exchange_data.get("wallet_id") or "—"],
    ]
    if address_count == 1:
        rows.insert(1, ["Attributed deposit address", all_addresses[0][0]])
    return rows


def _freeze_summary_table(rows: list[list[str]], styles) -> Table:
    table_rows = []
    label_style = ParagraphStyle(
        "freeze_label",
        parent=styles["body_bold"],
        fontSize=8.3,
        leading=11,
        textColor=C_PRIMARY,
    )
    value_style = ParagraphStyle(
        "freeze_value",
        parent=styles["body"],
        fontSize=8.3,
        leading=11,
        textColor=C_DARK,
    )
    for label, value in rows:
        table_rows.append([
            Paragraph(str(label), label_style),
            Paragraph(str(value).replace("\n", "<br/>"), value_style),
        ])

    tbl = Table(table_rows, colWidths=[48 * mm, PAGE_W - 2 * MARGIN - 48 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FDF2F2")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#FEF7F7"), colors.HexColor("#FDEEEE")]),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("BOX", (0, 0), (-1, -1), 1.4, C_ALERT),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEAFTER", (0, 0), (0, -1), 0.4, colors.HexColor("#E3C9C9")),
    ]))
    return tbl


def _freeze_endpoint_paths(exchange_data: dict, victim_addresses: list[str], recipient_address: str, hops: list[dict]) -> list[list[dict]]:
    from src.api.report_helpers import _build_flow_graph

    def _short(address: str, left: int = 12, right: int = 8) -> str:
        if not address:
            return "—"
        if len(address) <= left + right + 1:
            return address
        return f"{address[:left]}…{address[-right:]}"

    def _node_title(node: dict) -> str:
        kind = node.get("kind")
        if kind == "recipient":
            return "Recipient"
        if kind == "exchange":
            return node.get("exchange") or "Exchange"
        if kind == "victim":
            return "Victim inputs"
        return "Traced address"

    def _node_amount(node: dict) -> float:
        if node.get("kind") == "exchange":
            return float(node.get("display_in_btc") or node.get("total_in_btc") or 0.0)
        return float(
            max(
                node.get("display_in_btc") or 0.0,
                node.get("display_out_btc") or 0.0,
                node.get("total_in_btc") or 0.0,
                node.get("total_out_btc") or 0.0,
            )
        )

    graph = _build_flow_graph(victim_addresses, recipient_address, hops)
    node_by_id = {node["id"]: node for node in graph.get("nodes", [])}
    incoming: dict[str, list[dict]] = {}
    for edge in graph.get("edges", []):
        incoming.setdefault(edge.get("to", ""), []).append(edge)

    target_addresses = [addr for addr, _ in (exchange_data.get("all_addresses") or [(exchange_data["address"], exchange_data["btc_involved"])])]
    paths: list[list[dict]] = []
    for target in target_addresses:
        if target not in node_by_id:
            continue
        current = target
        visited: set[str] = set()
        sequence: list[dict] = []
        while current and current not in visited and current in node_by_id:
            visited.add(current)
            node = node_by_id[current]
            sequence.append({
                "kind": node.get("kind", "address"),
                "title": _node_title(node),
                "subtitle": _short(node.get("address", "")),
                "amount_btc": _node_amount(node),
            })
            in_edges = [edge for edge in incoming.get(current, []) if edge.get("from") != current]
            if not in_edges:
                break
            if len(in_edges) > 1:
                source_nodes = [node_by_id.get(edge.get("from", ""), {}) for edge in in_edges]
                if all(src.get("kind") == "victim" for src in source_nodes if src):
                    sequence.append({
                        "kind": "victim",
                        "title": "Victim inputs",
                        "subtitle": f"{len(source_nodes)} addresses",
                        "amount_btc": sum(float(edge.get("amount_btc") or 0.0) for edge in in_edges),
                    })
                    break
                chosen = max(in_edges, key=lambda edge: float(edge.get("amount_btc") or 0.0))
            else:
                chosen = in_edges[0]
            current = chosen.get("from", "")
        paths.append(list(reversed(sequence)))
    return paths


def _freeze_endpoint_trace_view(exchange_data: dict, styles):
    paths = _freeze_endpoint_paths(
        exchange_data,
        list(CASE.get("victim_addresses") or []),
        str(CASE.get("recipient_address") or ""),
        HOPS,
    )
    if not paths:
        return []

    def _fmt_btc(value: float) -> str:
        digits = 4 if abs(value) >= 1 else 8
        return f"{value:.{digits}f}".rstrip("0").rstrip(".")

    palette = {
        "victim": ("#ECFDF5", "#0F766E"),
        "recipient": ("#FFF7ED", "#C2410C"),
        "exchange": ("#F0FDF4", "#166534"),
        "address": ("#F8FAFC", "#64748B"),
    }

    story = [
        Paragraph("Focused endpoint trace view:", styles["h2"]),
        Paragraph(
            "The following path view isolates only those traced nodes that lead into the exchange endpoints referenced by this freeze request.",
            styles["small"],
        ),
        Spacer(1, 5),
    ]

    for path in paths:
        row = []
        col_widths = []
        for idx, node in enumerate(path):
            kind = node.get("kind", "address")
            fill, stroke = palette.get(kind, palette["address"])
            body = (
                f"<b>{node['title']}</b><br/>"
                f"<font face='Courier'>{node['subtitle']}</font><br/>"
                f"{_fmt_btc(float(node.get('amount_btc') or 0.0))} BTC"
            )
            box = Table([[Paragraph(body, ParagraphStyle(
                "freeze_path_box",
                parent=styles["body"],
                fontSize=7.3,
                leading=9.2,
                textColor=C_DARK,
            ))]], colWidths=[34 * mm])
            box.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(fill)),
                ("BOX", (0, 0), (-1, -1), 1.0, colors.HexColor(stroke)),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            row.append(box)
            col_widths.append(34 * mm)
            if idx < len(path) - 1:
                row.append(Paragraph("→", ParagraphStyle(
                    "freeze_arrow",
                    parent=styles["body_bold"],
                    alignment=TA_CENTER,
                    fontSize=11,
                    textColor=C_GREY,
                )))
                col_widths.append(7 * mm)

        row_tbl = Table([row], colWidths=col_widths)
        row_tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(row_tbl)
        story.append(Spacer(1, 6))

    return story


def _styles():
    s = {}
    s["h1"] = ParagraphStyle("h1", fontSize=13, fontName="Helvetica-Bold",
                              textColor=C_PRIMARY, spaceAfter=4, spaceBefore=10)
    s["h2"] = ParagraphStyle("h2", fontSize=10, fontName="Helvetica-Bold",
                              textColor=C_PRIMARY, spaceAfter=3, spaceBefore=6)
    s["body"] = ParagraphStyle("body", fontSize=8.5, fontName="Helvetica",
                                textColor=C_DARK, leading=13)
    s["body_bold"] = ParagraphStyle("body_bold", fontSize=8.5, fontName="Helvetica-Bold",
                                     textColor=C_DARK, leading=13)
    s["small"] = ParagraphStyle("small", fontSize=7.5, fontName="Helvetica",
                                 textColor=C_GREY, leading=11)
    s["mono"] = ParagraphStyle("mono", fontSize=7, fontName="Courier",
                                textColor=C_DARK, leading=11)
    s["center"] = ParagraphStyle("center", fontSize=8.5, fontName="Helvetica",
                                  textColor=C_DARK, alignment=TA_CENTER)
    s["alert"] = ParagraphStyle("alert", fontSize=9, fontName="Helvetica-Bold",
                                 textColor=C_ALERT)
    return s


def _hr():
    return [HRFlowable(width="100%", thickness=0.5, color=C_BORDER), Spacer(1, 4)]


def _page_template(case_id, generated_at):
    def on_page(canvas, doc):
        canvas.saveState()
        # Header
        canvas.setFillColor(C_PRIMARY)
        canvas.rect(0, PAGE_H - 12*mm, PAGE_W, 12*mm, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(MARGIN, PAGE_H - 8*mm, "AIFinancialCrime - Forensic Blockchain Analysis Report")
        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 8*mm, f"Case: {case_id}")
        # Footer
        canvas.setFillColor(C_LIGHT)
        canvas.rect(0, 0, PAGE_W, 10*mm, fill=1, stroke=0)
        canvas.setFillColor(C_GREY)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(MARGIN, 4*mm,
                          f"Generated: {generated_at} | Confidential - For law enforcement and compliance use only")
        canvas.drawRightString(PAGE_W - MARGIN, 4*mm, f"Page {doc.page}")
        canvas.restoreState()
    return on_page


# ---------------------------------------------------------------------------
# Sektionen
# ---------------------------------------------------------------------------

def _cover(styles):
    story = []
    # Titel-Block
    title_data = [[
        Paragraph("FORENSIC BLOCKCHAIN ANALYSIS REPORT", ParagraphStyle(
            "title", fontSize=16, fontName="Helvetica-Bold",
            textColor=C_WHITE, alignment=TA_CENTER
        ))
    ]]
    title_tbl = Table(title_data, colWidths=[PAGE_W - 2*MARGIN])
    title_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_PRIMARY),
        ("TOPPADDING", (0,0), (-1,-1), 14),
        ("BOTTOMPADDING", (0,0), (-1,-1), 14),
    ]))
    story.append(title_tbl)
    story.append(Spacer(1, 8))

    subtitle_data = [[
        Paragraph(f"Wallet Theft - {_wallet_label()}", ParagraphStyle(
            "subtitle", fontSize=11, fontName="Helvetica",
            textColor=C_WHITE, alignment=TA_CENTER
        ))
    ]]
    subtitle_tbl = Table(subtitle_data, colWidths=[PAGE_W - 2*MARGIN])
    subtitle_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_ACCENT),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(subtitle_tbl)
    story.append(Spacer(1, 12))

    # Fall-Metadaten
    meta = [
        ["Case ID",           _case_text("case_id")],
        ["Reporting Party",   _case_text("victim_name")],
        ["Date of Theft",     _case_text("incident_date")],
        ["Date of Discovery", _case_text("discovery_date")],
        ["Loss Amount",       _amount_label()],
        ["Wallet Type",       _wallet_label()],
        ["Report Date",       _case_text("generated_at")],
    ]
    meta_tbl = Table(meta, colWidths=[45*mm, PAGE_W - 2*MARGIN - 45*mm])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,0), (-1,-1), [C_WHITE, C_LIGHT]),
        ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("TEXTCOLOR",     (0,0), (0,-1), C_PRIMARY),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Executive Summary", styles["h1"]))
    story += _hr()
    exchange_names = ", ".join(f"<b>{e['name']}</b>" for e in EXCHANGES_IDENTIFIED) if EXCHANGES_IDENTIFIED else "<b>no identified exchange</b>"
    hop_count = max(len(HOPS) - 1, 0)
    story.append(Paragraph(
        f"This report documents a reported unauthorized outflow transaction dated "
        f"{_case_text('incident_date')} involving an analyzed amount of <b>{_amount_label()}</b>. "
        f"The traced path contains <b>{hop_count}</b> downstream hop(s) after the originating transaction. "
        f"The analysis currently identifies the following exchange endpoint(s): "
        f"{exchange_names}.",
        styles["body"]
    ))
    story.append(Spacer(1, 8))

    rows = [["Exchange", "Address", "Confidence", "BTC"]]
    for ex in EXCHANGES_IDENTIFIED:
        rows.append([
            Paragraph(f"<b>{ex['name']}</b>", styles["body_bold"]),
            Paragraph(ex["address"], styles["mono"]),
            Paragraph(ex["confidence"], ParagraphStyle(
                "conf", fontSize=8.5, fontName="Helvetica-Bold",
                textColor=CONF_COLORS.get(ex["confidence"], C_DARK)
            )),
            f"{ex['btc_involved']:.8f}",
        ])
    ex_tbl = Table(rows, colWidths=[22*mm, 85*mm, 18*mm, 30*mm])
    ex_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), C_PRIMARY),
        ("TEXTCOLOR",     (0,0), (-1,0), C_WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_WHITE, C_LIGHT]),
        ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story.append(ex_tbl)
    return story


def _methodology(styles):
    story = [Paragraph("1. Methodology & Confidence Framework", styles["h1"])]
    story += _hr()
    story.append(Paragraph(
        "This analysis is based exclusively on on-chain verifiable data. "
        "All findings are traceable through transaction identifiers and block heights. "
        "The following confidence framework is applied:",
        styles["body"]
    ))
    story.append(Spacer(1, 6))

    conf_rows = [
        ["Level", "Classification", "Criteria"],
        ["L1", "Mathematically proven",
         "Direct UTXO link - cryptographically conclusive"],
        ["L2", "Forensically corroborated",
         "Direct exchange attribution from a validated source (for example official reserve data, local intel agent, or WalletExplorer)"],
        ["L3", "Indicative only",
         "Downstream, pattern-based, or contextual signal - not burden-bearing and excluded from the report"],
        ["L4", "Speculative",
         "Heuristic only, without a direct connection - excluded from the report"],
    ]
    conf_tbl = Table(conf_rows, colWidths=[12*mm, 42*mm, PAGE_W - 2*MARGIN - 54*mm])
    conf_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), C_PRIMARY),
        ("TEXTCOLOR",     (0,0), (-1,0), C_WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("BACKGROUND",    (0,1), (-1,1), colors.HexColor("#D5F5E3")),
        ("BACKGROUND",    (0,2), (-1,2), colors.HexColor("#D6EAF8")),
        ("BACKGROUND",    (0,3), (-1,3), colors.HexColor("#FDEBD0")),
        ("BACKGROUND",    (0,4), (-1,4), colors.HexColor("#FADBD8")),
        ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("FONTNAME",      (0,1), (0,-1), "Helvetica-Bold"),
    ]))
    story.append(conf_tbl)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report contains L1 and L2 findings only. "
        "L3 and L4 observations are intentionally excluded in order to preserve evidentiary reliability.",
        styles["small"]
    ))
    return story


def _transaction_graph(styles):
    """Professional trace diagram for the PDF report."""
    from reportlab.graphics.shapes import Drawing, Rect, String, PolyLine, Line
    from src.api.report_helpers import _build_flow_graph

    def _short(address: str, left: int = 12, right: int = 8) -> str:
        if not address:
            return "—"
        if len(address) <= left + right + 1:
            return address
        return f"{address[:left]}…{address[-right:]}"

    def _fmt_btc(value) -> str:
        try:
            num = float(value or 0)
        except Exception:
            num = 0.0
        digits = 4 if abs(num) >= 1 else 8
        text = f"{num:.{digits}f}".rstrip("0").rstrip(".")
        return text or "0"

    def _status_label(reason: str) -> str:
        return {
            "exchange": "Exchange endpoint",
            "pooling": "Pooling detected",
            "unspent": "Unspent UTXO",
            "lookup_incomplete": "Resolution incomplete",
        }.get(reason or "", "")

    def _palette(kind: str) -> dict:
        palettes = {
            "victim": {
                "fill": colors.HexColor("#ECFDF5"),
                "stroke": colors.HexColor("#0F766E"),
                "tag_fill": colors.HexColor("#CCFBF1"),
                "tag_text": colors.HexColor("#115E59"),
                "tag": "VICTIM",
            },
            "recipient": {
                "fill": colors.HexColor("#FFF7ED"),
                "stroke": colors.HexColor("#C2410C"),
                "tag_fill": colors.HexColor("#FED7AA"),
                "tag_text": colors.HexColor("#9A3412"),
                "tag": "RECIPIENT",
            },
            "exchange": {
                "fill": colors.HexColor("#F0FDF4"),
                "stroke": colors.HexColor("#166534"),
                "tag_fill": colors.HexColor("#DCFCE7"),
                "tag_text": colors.HexColor("#166534"),
                "tag": "EXCHANGE",
            },
            "address": {
                "fill": colors.HexColor("#F8FAFC"),
                "stroke": colors.HexColor("#64748B"),
                "tag_fill": colors.HexColor("#E2E8F0"),
                "tag_text": colors.HexColor("#475569"),
                "tag": "TRACED ADDRESS",
            },
        }
        return palettes.get(kind, palettes["address"])

    story = [Paragraph("3. Transaction Graph - Overview", styles["h1"])]
    story += _hr()
    story.append(Paragraph(
        "The diagram below provides a compact evidentiary flow view of the traced bitcoin path. "
        "Victim-controlled input addresses are grouped where necessary for readability. "
        "All downstream splits and exchange endpoints remain individually visible. "
        "Detailed transaction identifiers, block heights, and evidentiary notes are listed in Section 2 (Chain of Custody).",
        styles["body"]
    ))
    story.append(Spacer(1, 8))

    victim_addresses = list(CASE.get("victim_addresses") or [])
    if not victim_addresses and HOPS:
        victim_addresses = [addr for addr, _ in HOPS[0].get("from_addresses", []) if addr]

    recipient_address = str(CASE.get("recipient_address") or "")
    if not recipient_address and HOPS:
        victim_set = set(victim_addresses)
        for addr, _ in HOPS[0].get("to_addresses", []):
            if addr and addr not in victim_set:
                recipient_address = addr
                break

    graph = _build_flow_graph(victim_addresses, recipient_address, HOPS)
    nodes = [dict(node) for node in graph.get("nodes", [])]
    edges = [dict(edge) for edge in graph.get("edges", [])]

    W = PAGE_W - 2 * MARGIN
    H = 150 * mm
    d = Drawing(W, H)

    d.add(Rect(0, 0, W, H, rx=10, ry=10,
               fillColor=colors.HexColor("#FBFCFD"),
               strokeColor=C_BORDER, strokeWidth=0.7))

    if not nodes:
        d.add(String(W / 2, H / 2, "No trace graph is available for this report.",
                     fontSize=10, fontName="Helvetica-Bold",
                     fillColor=C_GREY, textAnchor="middle"))
        story.append(d)
        story.append(Spacer(1, 8))
        return story

    victim_set = {node["address"] for node in nodes if node.get("kind") == "victim"}
    if len(victim_set) > 1:
        cluster_id = "__victim_input_cluster__"
        victim_nodes = [node for node in nodes if node["address"] in victim_set]
        node_by_id = {node["id"]: node for node in nodes}
        aggregated_edges: dict[str, dict] = {}
        preserved_edges: list[dict] = []
        for edge in edges:
            if edge.get("from") in victim_set:
                target = edge.get("to", "")
                if target not in aggregated_edges:
                    target_node = node_by_id.get(target, {})
                    aggregated_edges[target] = {
                        **edge,
                        "id": f"{cluster_id}:{target}",
                        "from": cluster_id,
                        "amount_btc": float(target_node.get("display_in_btc") or target_node.get("total_in_btc") or 0.0),
                        "notes": "Aggregated victim-controlled input set.",
                    }
            else:
                preserved_edges.append(edge)
        grouped_output_btc = sum(float(edge.get("amount_btc") or 0) for edge in aggregated_edges.values())
        edges = preserved_edges + list(aggregated_edges.values())
        nodes = [node for node in nodes if node["address"] not in victim_set]
        nodes.append({
            "id": cluster_id,
            "address": "",
            "column": 0,
            "kind": "victim",
            "exchange": "",
            "is_sanctioned": any(node.get("is_sanctioned") for node in victim_nodes),
            "total_in_btc": 0.0,
            "total_out_btc": grouped_output_btc,
            "display_in_btc": 0.0,
            "display_out_btc": grouped_output_btc,
            "has_change_output": False,
            "chain_end_reason": "",
            "display_label": "Victim input set",
            "short_address": f"{len(victim_nodes)} addresses",
            "member_count": len(victim_nodes),
        })

    columns: dict[int, list[dict]] = {}
    for node in nodes:
        columns.setdefault(int(node.get("column") or 0), []).append(node)

    kind_order = {"victim": 0, "recipient": 1, "address": 2, "exchange": 3}
    for col_nodes in columns.values():
        col_nodes.sort(
            key=lambda node: (
                kind_order.get(node.get("kind", "address"), 9),
                -(float(node.get("total_in_btc") or 0) + float(node.get("total_out_btc") or 0)),
                node.get("address", ""),
            )
        )

    col_keys = sorted(columns.keys())
    max_rows = max(len(col_nodes) for col_nodes in columns.values())
    lane_labels = {int(item.get("column", 0)): str(item.get("label", "")) for item in graph.get("lanes", [])}
    if any(node.get("id") == "__victim_input_cluster__" for node in nodes):
        lane_labels[0] = "Victim Inputs"

    panel_pad = 10
    lane_h = 14
    col_gap = 8
    top_margin = 10
    bottom_margin = 34
    row_gap = 8 if max_rows <= 4 else 6
    column_count = max(1, len(col_keys))
    track_w = (W - 2 * panel_pad - (column_count - 1) * col_gap) / column_count
    node_w = max(60, min(82, track_w - 4))
    available_h = H - top_margin - bottom_margin - lane_h - 18
    node_h = max(36, min(52, (available_h - row_gap * max(max_rows - 1, 0)) / max_rows))
    lane_y = H - top_margin - lane_h

    positions: dict[str, dict] = {}

    for idx, col in enumerate(col_keys):
        x_track = panel_pad + idx * (track_w + col_gap)
        x_node = x_track + (track_w - node_w) / 2
        d.add(Rect(x_track, lane_y, track_w, lane_h, rx=6, ry=6,
                   fillColor=colors.HexColor("#EEF4FF"),
                   strokeColor=colors.HexColor("#C7D6EB"),
                   strokeWidth=0.7))
        d.add(String(x_track + track_w / 2, lane_y + 4.2,
                     (lane_labels.get(col) or f"Hop {max(col - 1, 0)}").upper(),
                     fontSize=5.5, fontName="Helvetica-Bold",
                     fillColor=C_ACCENT, textAnchor="middle"))

        col_nodes = columns[col]
        total_col_h = len(col_nodes) * node_h + max(len(col_nodes) - 1, 0) * row_gap
        start_y = lane_y - 14 - node_h - max(0, (available_h - total_col_h) / 2)

        for row_idx, node in enumerate(col_nodes):
            y_node = start_y - row_idx * (node_h + row_gap)
            positions[node["id"]] = {"x": x_node, "y": y_node, "w": node_w, "h": node_h}

    for edge in edges:
        src = positions.get(edge.get("from"))
        dst = positions.get(edge.get("to"))
        if not src or not dst:
            continue
        start_x = src["x"] + src["w"]
        start_y = src["y"] + src["h"] / 2
        end_x = dst["x"]
        end_y = dst["y"] + dst["h"] / 2
        bend_a = start_x + min(18, max(10, (end_x - start_x) * 0.25))
        bend_b = end_x - min(18, max(10, (end_x - start_x) * 0.25))
        line_color = colors.HexColor("#334155") if edge.get("confidence") == "L1" else colors.HexColor("#94A3B8")
        dash = None if edge.get("confidence") == "L1" else [3, 2]

        d.add(PolyLine(
            [start_x, start_y, bend_a, start_y, bend_b, end_y, end_x, end_y],
            strokeColor=line_color,
            strokeWidth=1.1 if edge.get("confidence") == "L1" else 0.9,
            strokeDashArray=dash,
            fillColor=None,
        ))
        d.add(PolyLine(
            [end_x - 4, end_y + 2.4, end_x, end_y, end_x - 4, end_y - 2.4],
            strokeColor=line_color,
            strokeWidth=1.0,
            fillColor=None,
        ))

        if edge.get("amount_btc") is not None:
            edge_amount = _fmt_btc(edge.get("amount_btc"))
            label_x = (bend_a + bend_b) / 2
            label_y = (start_y + end_y) / 2 + (4 if end_y >= start_y else -7)
            d.add(String(label_x, label_y, f"{edge_amount} BTC",
                         fontSize=4.6, fontName="Helvetica",
                         fillColor=C_GREY, textAnchor="middle"))

    for node in nodes:
        box = positions[node["id"]]
        palette = _palette(node.get("kind", "address"))
        x = box["x"]
        y = box["y"]
        w = box["w"]
        h = box["h"]

        d.add(Rect(x, y, w, h, rx=7, ry=7,
                   fillColor=palette["fill"],
                   strokeColor=palette["stroke"],
                   strokeWidth=1.0))
        d.add(Rect(x + 6, y + h - 12, min(42, w - 12), 8, rx=4, ry=4,
                   fillColor=palette["tag_fill"],
                   strokeColor=None))
        d.add(String(x + 9, y + h - 9.5, palette["tag"],
                     fontSize=4.3, fontName="Helvetica-Bold",
                     fillColor=palette["tag_text"]))

        if node.get("id") == "__victim_input_cluster__":
            title = "Victim input set"
            subtitle = f"{node.get('member_count', 0)} addresses"
            amount_line = f"{_fmt_btc(node.get('display_out_btc', node.get('total_out_btc')))} BTC"
        elif node.get("kind") == "victim":
            title = "Victim input"
            subtitle = _short(node.get("address", ""))
            amount_line = f"{_fmt_btc(node.get('display_out_btc', node.get('total_out_btc')))} BTC"
        elif node.get("kind") == "recipient":
            title = "Recipient"
            subtitle = _short(node.get("address", ""))
            amount_line = f"{_fmt_btc(max(node.get('display_in_btc') or 0, node.get('display_out_btc') or 0, node.get('total_in_btc') or 0, node.get('total_out_btc') or 0))} BTC"
        elif node.get("kind") == "exchange":
            title = node.get("exchange") or "Exchange"
            subtitle = _short(node.get("address", ""))
            amount_line = f"{_fmt_btc(node.get('display_in_btc', node.get('total_in_btc')))} BTC"
        else:
            title = "Traced address"
            subtitle = _short(node.get("address", ""))
            amount_line = f"{_fmt_btc(max(node.get('display_in_btc') or 0, node.get('display_out_btc') or 0, node.get('total_in_btc') or 0, node.get('total_out_btc') or 0))} BTC"

        status = _status_label(str(node.get("chain_end_reason") or ""))

        d.add(String(x + 8, y + h - 20, title,
                     fontSize=6.5, fontName="Helvetica-Bold",
                     fillColor=C_DARK))
        d.add(String(x + 8, y + h - 29, subtitle,
                     fontSize=5.2, fontName="Courier",
                     fillColor=colors.HexColor("#475569")))
        d.add(String(x + 8, y + h - 38, amount_line,
                     fontSize=5.2, fontName="Helvetica",
                     fillColor=C_DARK))
        if status:
            d.add(String(x + 8, y + 6, status,
                         fontSize=4.8, fontName="Helvetica-Bold",
                         fillColor=colors.HexColor("#92400E")))

    legend_y = 10
    legend_items = [
        ("victim", "Victim-controlled input set"),
        ("recipient", "Initial recipient / traced target path"),
        ("address", "Intermediate traced address"),
        ("exchange", "Corroborated exchange endpoint"),
    ]
    legend_x = 12
    for kind, label in legend_items:
        palette = _palette(kind)
        d.add(Rect(legend_x, legend_y, 8, 8, rx=2, ry=2,
                   fillColor=palette["fill"], strokeColor=palette["stroke"], strokeWidth=0.9))
        d.add(String(legend_x + 12, legend_y + 1.5, label,
                     fontSize=5.6, fontName="Helvetica",
                     fillColor=C_DARK))
        legend_x += 118

    story.append(d)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Solid connectors indicate L1 (mathematically proven via UTXO). "
        "Dashed connectors indicate L2 (forensically corroborated). "
        "This diagram is intentionally condensed for report readability; the authoritative transaction-by-transaction evidence is set out in Section 2.",
        styles["small"]
    ))
    story.append(Spacer(1, 8))
    return story


def _chain_of_custody(styles):
    story = [Paragraph("2. Chain of Custody", styles["h1"])]
    story += _hr()
    story.append(Paragraph(
        "The following table documents the full on-chain verifiable transaction path "
        "of the stolen bitcoin from the victim-controlled address set to the identified endpoint.",
        styles["body"]
    ))
    story.append(Spacer(1, 6))

    for hop in HOPS:
        conf = hop["confidence"]
        conf_color = CONF_COLORS.get(conf, C_DARK)

        # Hop-Header
        header_data = [[
            Paragraph(f"Hop {hop['hop']} - {hop['label']}", ParagraphStyle(
                "hop_h", fontSize=9, fontName="Helvetica-Bold", textColor=C_WHITE
            )),
            Paragraph(f"{conf} — {hop['confidence_label']}", ParagraphStyle(
                "hop_conf", fontSize=9, fontName="Helvetica-Bold",
                textColor=C_WHITE, alignment=TA_RIGHT
            )),
        ]]
        header_tbl = Table(header_data,
                           colWidths=[PAGE_W - 2*MARGIN - 55*mm, 55*mm])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), conf_color),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("RIGHTPADDING",  (-1,0), (-1,-1), 8),
        ]))

        # Details
        detail_rows = [
            ["TXID", Paragraph(str(hop["txid"]), styles["mono"])],
            ["Block", str(hop["block"])],
            ["Timestamp", hop["timestamp"]],
            ["Method", hop["method"]],
        ]

        # Inputs
        if hop["from_addresses"]:
            for i, (addr, val) in enumerate(hop["from_addresses"]):
                label = "From" if i == 0 else ""
                val_str = f"{val:.8f} BTC" if val else "—"
                detail_rows.append([label, Paragraph(
                    f"{addr}  <b>{val_str}</b>", styles["mono"]
                )])

        # Outputs
        if hop["to_addresses"]:
            for i, (addr, val) in enumerate(hop["to_addresses"]):
                label = "To" if i == 0 else ""
                val_str = f"{val:.8f} BTC" if val else "—"
                detail_rows.append([label, Paragraph(
                    f"{addr}  <b>{val_str}</b>", styles["mono"]
                )])

        if hop.get("fee_btc"):
            detail_rows.append(["Fee", f"{hop['fee_btc']:.8f} BTC"])

        detail_rows.append(["Note", Paragraph(hop["notes"], styles["small"])])

        # Exchange-Label falls vorhanden
        if hop.get("exchange"):
            detail_rows.append(["Exchange", Paragraph(
                f"<b>{hop['exchange']}</b>",
                ParagraphStyle("ex_label", fontSize=9, fontName="Helvetica-Bold",
                               textColor=C_ALERT)
            )])

        detail_tbl = Table(detail_rows,
                           colWidths=[20*mm, PAGE_W - 2*MARGIN - 20*mm])
        detail_tbl.setStyle(TableStyle([
            ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 7.5),
            ("ROWBACKGROUNDS",(0,0), (-1,-1), [C_WHITE, C_LIGHT]),
            ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ("TEXTCOLOR",     (0,0), (0,-1), C_PRIMARY),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ]))

        # Verifikations-Link
        verify_url = f"https://blockstream.info/tx/{hop['txid']}"
        if len(str(hop["txid"])) == 64:
            verify = [Paragraph(
                f"Verification: {verify_url}",
                styles["small"]
            )]
        else:
            verify = []

        # Kettenende-Banner wenn dies der letzte L1-Hop ist
        chain_end = hop.get("chain_end_reason")
        end_elements = []
        if chain_end:
            end_texts = {
                "exchange": (
                    C_ALERT,
                    "CHAIN END - Exchange identified",
                    "The stolen funds were deposited to a cryptocurrency exchange. "
                    "The L1 evidentiary chain ends at this point. A formal freeze request "
                    "has been prepared for this exchange."
                ),
                "pooling": (
                    colors.HexColor("#5D4037"),
                    "CHAIN END - Pooling / consolidation detected",
                    "The stolen funds were combined with third-party funds. "
                    "A mathematically unique attribution (L1) is no longer possible "
                    "beyond this point. The evidentiary chain ends here under forensic standards."
                ),
                "unspent": (
                    colors.HexColor("#1A5276"),
                    "CHAIN END - UTXO unspent",
                    "The stolen funds remain unspent at this address as of the time of analysis. "
                    "The trace therefore ends here naturally. "
                    "A direct preservation or freeze request is recommended."
                ),
                "lookup_incomplete": (
                    colors.HexColor("#7D6608"),
                    "CHAIN END - Forwarding path not fully resolved",
                    "The funds were not classified as unspent. "
                    "Instead, spend resolution was incomplete with the current infrastructure, "
                    "so the next hop could not be determined to an evidentiary standard. "
                    "The report is incomplete at this point and must not be read as a final endpoint assessment."
                ),
            }
            if chain_end in end_texts:
                bg_col, title_str, body_str = end_texts[chain_end]
                end_title_data = [[Paragraph(title_str, ParagraphStyle(
                    "end_h", fontSize=8.5, fontName="Helvetica-Bold", textColor=C_WHITE
                ))]]
                end_title_tbl = Table(end_title_data, colWidths=[PAGE_W - 2*MARGIN])
                end_title_tbl.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0), (-1,-1), bg_col),
                    ("TOPPADDING",    (0,0), (-1,-1), 5),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                    ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ]))
                end_body = Table([[Paragraph(body_str, styles["small"])]],
                                 colWidths=[PAGE_W - 2*MARGIN])
                end_body.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#1C2833")),
                    ("TOPPADDING",    (0,0), (-1,-1), 5),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                    ("LEFTPADDING",   (0,0), (-1,-1), 8),
                    ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
                ]))
                end_elements = [end_title_tbl, end_body, Spacer(1, 4)]

        story.append(KeepTogether([header_tbl, detail_tbl] + verify + end_elements + [Spacer(1, 8)]))

    return story


def _integrity(report_hash, styles):
    story = [Paragraph("5. Report Integrity", styles["h1"])]
    story += _hr()
    rows = [
        ["SHA-256 checksum", Paragraph(report_hash, styles["mono"])],
        ["Generated at", CASE["generated_at"]],
        ["System", "AIFinancialCrime Forensic System v1.0"],
        ["Data source", "Bitcoin node / Blockstream + BTC Exchange Intel Agent"],
    ]
    tbl = Table(rows, colWidths=[35*mm, PAGE_W - 2*MARGIN - 35*mm])
    tbl.setStyle(TableStyle([
        ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("BACKGROUND",    (0,0), (-1,-1), C_LIGHT),
        ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report was generated automatically by the AIFinancialCrime forensic system. "
        "All on-chain data remains publicly verifiable. "
        "The SHA-256 checksum is provided for integrity verification of the report content.",
        styles["small"]
    ))
    return story


def _recommended_actions(styles):
    story = [Paragraph("4. Recommended Actions", styles["h1"])]
    story += _hr()

    actions = [
        ("IMMEDIATE (within 24 hours)",
         C_ALERT,
         [
             "File a criminal complaint with the competent law enforcement authority (cybercrime unit).",
         ] + [
             f"Send a freeze request to {ex['name']} Compliance: {ex['compliance_email']}"
             for ex in EXCHANGES_IDENTIFIED
         ] + [
             "Document every freeze request together with this analysis and the relevant transaction identifiers.",
         ]),
        ("SHORT TERM (within 1 week)",
         C_WARNING,
         [
             "Notify BaFin (Germany) or the competent national financial regulator, where applicable.",
             "Consider a Europol EC3 report: https://www.europol.europa.eu/report-a-crime",
             "Engage legal counsel with cryptocurrency tracing or asset recovery experience.",
             "Treat the affected wallet or seed environment as compromised and establish new secure credentials or a new seed phrase.",
         ]),
        ("MEDIUM TERM",
         C_SUCCESS,
         [
             "Record and preserve all responses received from exchanges.",
             "Coordinate with law enforcement if an account preservation or freeze is confirmed.",
             "Assess civil recovery options if the exchange cooperates.",
         ]),
    ]

    for title, color, items in actions:
        header = Table([[Paragraph(title, ParagraphStyle(
            "act_h", fontSize=9, fontName="Helvetica-Bold", textColor=C_WHITE
        ))]], colWidths=[PAGE_W - 2*MARGIN])
        header.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), color),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(header)
        for item in items:
            story.append(Paragraph(f"• {item}", styles["body"]))
        story.append(Spacer(1, 6))

    return story


# ---------------------------------------------------------------------------
# Freeze Request Generator
# ---------------------------------------------------------------------------

def _freeze_request(exchange_data, styles, output_path):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=18*mm, bottomMargin=16*mm,
        title=f"Freeze Request — {exchange_data['name']}",
    )

    on_page = _page_template(CASE["case_id"], CASE["generated_at"])
    story = []

    # Header
    hdr = Table([[Paragraph(
        f"FREEZE REQUEST — {exchange_data['name'].upper()} COMPLIANCE",
        ParagraphStyle("fr_title", fontSize=14, fontName="Helvetica-Bold",
                       textColor=C_WHITE, alignment=TA_CENTER)
    )]], colWidths=[PAGE_W - 2*MARGIN])
    hdr.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_ALERT),
        ("TOPPADDING", (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
    ]))
    story.append(hdr)
    story.append(Spacer(1, 10))

    story.append(Paragraph(f"To: {exchange_data['name']} Compliance Team", styles["body_bold"]))
    story.append(Paragraph(f"Email: {exchange_data['compliance_email']}", styles["body"]))
    story.append(Paragraph(f"Date: {CASE['generated_at']}", styles["body"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Subject: Urgent asset preservation request - bitcoin theft", styles["h1"]))
    story += _hr()

    story.append(Paragraph(
        f"Dear {exchange_data['name']} Compliance Team,",
        styles["body"]
    ))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"I hereby request the immediate preservation or freezing of all accounts and assets "
        f"associated with the bitcoin addresses listed below. "
        f"On {_case_text('incident_date')}, <b>{_btc_label(CASE.get('fraud_amount'))}</b> "
        f"was withdrawn without authorization from my wallet environment. "
        f"The attached forensic blockchain analysis shows that part of these funds "
        f"passed through your platform. This request is limited to the addresses and transaction path "
        f"for which a corroborated exchange attribution was identified in the attached report.",
        styles["body"]
    ))
    story.append(Spacer(1, 8))

    all_addresses = exchange_data.get("all_addresses") or [(exchange_data["address"], exchange_data["btc_involved"])]

    story.append(Paragraph("Exchange attribution summary:", styles["h2"]))
    addr_rows = _freeze_summary_rows(exchange_data)
    addr_tbl = _freeze_summary_table(addr_rows, styles)
    story.append(addr_tbl)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Attributed deposit addresses:", styles["h2"]))
    address_rows = [["Bitcoin address", "BTC traced into endpoint"]]
    for address, btc in all_addresses:
        address_rows.append([address, f"{float(btc or 0):.8f} BTC"])
    address_tbl = Table(address_rows, colWidths=[95*mm, PAGE_W - 2*MARGIN - 95*mm])
    address_tbl.setStyle(TableStyle([
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_WHITE, C_LIGHT]),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#F8FAFC")),
        ("GRID", (0,0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(address_tbl)
    story.append(Spacer(1, 8))

    story += _freeze_endpoint_trace_view(exchange_data, styles)

    # Originating transaction
    _fraud_txid = HOPS[0]["txid"] if HOPS else ""
    _fraud_block = str(HOPS[0].get("block", "")) if HOPS else ""
    _fraud_ts = HOPS[0].get("timestamp", _case_text("incident_date", "")) if HOPS else _case_text("incident_date", "")
    _fraud_amount = _btc_label(CASE.get("fraud_amount"))
    story.append(Paragraph("Originating transaction (theft event):", styles["h2"]))
    tx_rows = [
        ["TXID",        _fraud_txid],
        ["Block",       _fraud_block],
        ["Timestamp",   _fraud_ts],
        ["Amount",      _fraud_amount],
        ["Verification", f"https://blockstream.info/tx/{_fraud_txid}"],
    ]
    tx_tbl = Table(tx_rows, colWidths=[28*mm, PAGE_W - 2*MARGIN - 28*mm])
    tx_tbl.setStyle(TableStyle([
        ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 7.5),
        ("ROWBACKGROUNDS",(0,0), (-1,-1), [C_WHITE, C_LIGHT]),
        ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
    ]))
    story.append(tx_tbl)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Legal basis:", styles["h2"]))
    story.append(Paragraph(
        "• EU Anti-Money Laundering Directive (AMLD5/6) - exchanges are expected to cooperate where there is a substantiated suspicion of fraud or money laundering.\n"
        "• FATF Recommendation 16 (Travel Rule) - transfer tracing obligations may apply.\n"
        "• Applicable national fraud and cybercrime provisions may be engaged, subject to the relevant jurisdiction.\n"
        "• The attached report identifies the traced path, relevant transaction identifiers and attributed exchange endpoints.\n"
        "• This request does not assert ownership of every account at the exchange, but seeks urgent preservation of all records and balances reasonably linked to the listed deposit endpoints pending further review.",
        styles["body"]
    ))
    story.append(Spacer(1, 8))

    # Requested actions
    req_data = [[Paragraph(
        "WE REQUEST:\n"
        "1. Immediate preservation or freezing of all accounts linked to the address listed above\n"
        "2. Preservation of all KYC records associated with the account holder\n"
        "3. Written confirmation of receipt of this request within 24 hours\n"
        "4. Cooperation with the competent law enforcement authorities",
        ParagraphStyle("req", fontSize=9, fontName="Helvetica-Bold",
                       textColor=C_PRIMARY, leading=14)
    )]]
    req_tbl = Table(req_data, colWidths=[PAGE_W - 2*MARGIN])
    req_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#EBF5FB")),
        ("BOX",        (0,0), (-1,-1), 1.5, C_ACCENT),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING", (0,0), (-1,-1), 12),
    ]))
    story.append(req_tbl)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Sincerely,", styles["body"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>{CASE['victim_name']}</b>", styles["body_bold"]))
    story.append(Paragraph(f"Case reference: {CASE['case_id']}", styles["small"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"Attachment: full forensic blockchain analysis report ({CASE['case_id']})",
        styles["small"]
    ))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    with open(output_path, "wb") as f:
        f.write(buf.getvalue())
    print(f"  ✅ {output_path}")



# ---------------------------------------------------------------------------
# DB-Integration — Hops automatisch laden
# ---------------------------------------------------------------------------

def load_hops_from_db(fraud_txid: str, max_hops: int = 10) -> list:
    """
    Load the hop chain automatically from PostgreSQL.
    """
    import os, psycopg2
    from dotenv import load_dotenv
    load_dotenv()

    conn = psycopg2.connect(os.environ["POSTGRES_DSN"])
    hops = []
    visited = set()
    current_txids = [fraud_txid]
    hop_idx = 1

    try:
        while current_txids and hop_idx <= max_hops:
            next_txids = []
            for txid in current_txids:
                if txid in visited:
                    continue
                visited.add(txid)

                with conn.cursor() as cur:
                    # Spent outputs
                    cur.execute("""
                        SELECT o.txid, o.address, o.amount_sats, o.spent_by_txid,
                               t.block_height, t.first_seen
                        FROM tx_outputs o
                        JOIN transactions t ON t.txid = o.txid
                        WHERE o.txid = %s AND o.spent_by_txid IS NOT NULL
                        LIMIT 5
                    """, (txid,))
                    rows = cur.fetchall()

                for row in rows:
                    from_txid, from_addr, amount_sats, to_txid, block, ts = row
                    if to_txid in visited:
                        continue

                    # Outputs of the follow-on transaction
                    with conn.cursor() as cur:
                        cur.execute("""
                            SELECT o2.address, o2.amount_sats
                            FROM tx_outputs o2
                            WHERE o2.txid = %s
                            ORDER BY o2.amount_sats DESC
                        """, (to_txid,))
                        to_rows = cur.fetchall()

                    to_addresses = [(r[0], r[1]/1e8) for r in to_rows if r[0]]
                    ts_str = ts.strftime("%Y-%m-%d %H:%M UTC") if ts else "—"

                    hops.append({
                        "hop": hop_idx,
                        "label": f"Hop {hop_idx} - UTXO forwarding",
                        "txid": to_txid,
                        "block": block or 0,
                        "timestamp": ts_str,
                        "from_addresses": [(from_addr, amount_sats/1e8)],
                        "to_addresses": to_addresses,
                        "fee_btc": None,
                        "confidence": "L1",
                        "confidence_label": "Mathematically proven",
                        "method": "Direct UTXO link",
                        "notes": "Automatically detected via the local Bitcoin node.",
                    })
                    next_txids.append(to_txid)
                    hop_idx += 1

            current_txids = next_txids
    finally:
        conn.close()

    return hops


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_all():
    styles = _styles()
    CASES_DIR = pathlib.Path.home() / "AIFinancialCrime-Cases"
    OUTPUT_DIR = CASES_DIR / "output"
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Generating forensic analysis report...")
    report_content = str(HOPS) + str(CASE)
    report_hash = hashlib.sha256(report_content.encode()).hexdigest()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=18*mm, bottomMargin=16*mm,
        title=f"Forensic Analysis Report {CASE['case_id']}",
        author="AIFinancialCrime Forensic System",
    )
    on_page = _page_template(CASE["case_id"], CASE["generated_at"])

    story = []
    story += _cover(styles)
    story.append(PageBreak())
    story += _methodology(styles)
    story.append(Spacer(1, 8))
    story += _chain_of_custody(styles)
    story.append(PageBreak())
    story += _transaction_graph(styles)
    story.append(PageBreak())
    story += _recommended_actions(styles)
    story.append(Spacer(1, 8))
    story += _integrity(report_hash, styles)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

    report_path = str(OUTPUT_DIR / f"{CASE['case_id']}_Forensic_Analysis_Report.pdf")
    with open(report_path, "wb") as f:
        f.write(buf.getvalue())
    print(f"  ✅ {report_path}")

    print("Generating freeze requests...")
    for ex in EXCHANGES_IDENTIFIED:
        path = str(OUTPUT_DIR / f"{CASE['case_id']}_Freeze_Request_{ex['name']}.pdf")
        _freeze_request(ex, styles, path)

    print(f"\nOK - All documents generated in {OUTPUT_DIR}")
    print(f"   SHA-256: {report_hash}")


def _wallet_type_from_intake(incident: dict) -> str:
    wallet_brand = str(incident.get("wallet_brand", "") or "").strip()
    wallet_type = str(incident.get("wallet_type", "") or "").strip()
    if wallet_brand and wallet_type:
        return f"{wallet_brand} ({wallet_type})"
    return wallet_brand or wallet_type or "—"


def _load_case_from_file(case_id: str) -> None:
    import json
    import pathlib

    cases_dir = pathlib.Path.home() / "AIFinancialCrime-Cases"
    case_file = cases_dir / "cases" / f"{case_id}.json"
    if not case_file.exists():
        raise FileNotFoundError(str(case_file))

    with open(case_file, encoding="utf-8") as f:
        intake = json.load(f)

    victim = intake.get("victim", {})
    incident = intake.get("incident", {})
    blockchain = intake.get("blockchain", {})

    CASE["case_id"] = intake.get("case_id", case_id)
    CASE["victim_name"] = victim.get("name", "")
    CASE["victim_contact"] = victim.get("email", "")
    CASE["incident_date"] = incident.get("date", "")
    CASE["discovery_date"] = incident.get("discovery_date", "")
    CASE["fraud_amount"] = blockchain.get("fraud_amount_btc", "")
    CASE["fraud_amount_eur"] = blockchain.get("fraud_amount_eur", "") or ""
    CASE["wallet_type"] = _wallet_type_from_intake(incident)
    CASE["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if HOPS:
        if blockchain.get("victim_addresses"):
            HOPS[0]["from_addresses"] = [(address, None) for address in blockchain["victim_addresses"]]
        if blockchain.get("recipient_address"):
            HOPS[0]["to_addresses"] = [(
                blockchain["recipient_address"],
                float(blockchain.get("fraud_amount_btc") or 0),
            )]
        if blockchain.get("fraud_txid"):
            HOPS[0]["txid"] = blockchain["fraud_txid"]
        HOPS[0]["timestamp"] = incident.get("date", "")

    print(f"OK - Case file loaded: {case_file}")
    print(f"   Reporting party: {CASE['victim_name']}")
    print(f"   Amount:          {CASE['fraud_amount']} BTC")
    print(f"   TXID:            {str(blockchain.get('fraud_txid', '?'))[:32]}...")

    fraud_txid = blockchain.get("fraud_txid")
    if fraud_txid:
        print("Loading hops from PostgreSQL...")
        db_hops = load_hops_from_db(fraud_txid)
        if db_hops:
            HOPS[1:] = db_hops
            print(f"   {len(db_hops)} hop(s) loaded from the database.")
        else:
            print("   No hops found in the database - using existing hops.")


def cli(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="AIFinancialCrime Report Generator")
    parser.add_argument(
        "--case",
        metavar="ID",
        help="Case ID - loads cases/<ID>.json and generates the report",
    )
    args = parser.parse_args(argv)

    if args.case:
        try:
            _load_case_from_file(args.case)
        except FileNotFoundError as exc:
            print(f"ERROR - Case file not found: {exc}")
            print("   Place the case file in ~/AIFinancialCrime-Cases/cases/.")
            return 1

    generate_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
