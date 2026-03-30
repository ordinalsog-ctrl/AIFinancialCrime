#!/usr/bin/env python3
"""
AIFinancialCrime — Fall-Report Generator
=========================================
Dieses Modul wird NUR als Bibliothek von report_endpoint.py genutzt.
ALLE Daten (CASE, HOPS, EXCHANGES_IDENTIFIED) werden vom Endpoint
vor der PDF-Generierung dynamisch gesetzt.
Hardcoded Werte hier dienen NUR als leere Vorlage / Typ-Referenz.

NICHT direkt ausführen. Nur über den API-Endpoint nutzen.
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
        canvas.drawString(MARGIN, PAGE_H - 8*mm, "AIFinancialCrime — Forensischer Blockchain-Analysebericht")
        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 8*mm, f"Fall: {case_id}")
        # Footer
        canvas.setFillColor(C_LIGHT)
        canvas.rect(0, 0, PAGE_W, 10*mm, fill=1, stroke=0)
        canvas.setFillColor(C_GREY)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(MARGIN, 4*mm,
                          f"Generiert: {generated_at} | Vertraulich — Nur für Strafverfolgung und Compliance")
        canvas.drawRightString(PAGE_W - MARGIN, 4*mm, f"Seite {doc.page}")
        canvas.restoreState()
    return on_page


# ---------------------------------------------------------------------------
# Sektionen
# ---------------------------------------------------------------------------

def _cover(styles):
    story = []
    # Titel-Block
    title_data = [[
        Paragraph("FORENSISCHER BLOCKCHAIN-ANALYSEBERICHT", ParagraphStyle(
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
        Paragraph(f"Wallet-Diebstahl — {_wallet_label()}", ParagraphStyle(
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
        ["Fall-ID",           _case_text("case_id")],
        ["Geschädigter",      _case_text("victim_name")],
        ["Schadensdatum",     _case_text("incident_date")],
        ["Entdeckungsdatum",  _case_text("discovery_date")],
        ["Schadensbetrag",    _amount_label()],
        ["Wallet-Typ",        _wallet_label()],
        ["Berichtsdatum",     _case_text("generated_at")],
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

    # Zusammenfassung
    story.append(Paragraph("Zusammenfassung", styles["h1"]))
    story += _hr()
    exchange_names = " und ".join(f"<b>{e['name']}</b>" for e in EXCHANGES_IDENTIFIED) if EXCHANGES_IDENTIFIED else "<b>keine identifizierte Exchange</b>"
    hop_count = max(len(HOPS) - 1, 0)
    story.append(Paragraph(
        f"Der vorliegende Bericht dokumentiert eine gemeldete unautorisierte Abfluss-Transaktion "
        f"vom {_case_text('incident_date')} mit einem analysierten Volumen von <b>{_amount_label()}</b>. "
        f"Im ausgewerteten Pfad wurden <b>{hop_count}</b> Folge-Hop(s) nach der Ursprungstransaktion "
        f"forensisch dokumentiert. Als derzeit identifizierte Ziel-Exchange(s) weist die Analyse "
        f"{exchange_names} aus.",
        styles["body"]
    ))
    story.append(Spacer(1, 8))

    # Exchange-Übersicht
    rows = [["Exchange", "Adresse", "Confidence", "BTC"]]
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
    story = [Paragraph("1. Methodik & Confidence-Framework", styles["h1"])]
    story += _hr()
    story.append(Paragraph(
        "Die Analyse basiert ausschließlich auf on-chain verifizierbaren Daten. "
        "Alle Behauptungen sind durch Transaktions-IDs und Block-Höhen belegbar. "
        "Das folgende Confidence-Framework wird verwendet:",
        styles["body"]
    ))
    story.append(Spacer(1, 6))

    conf_rows = [
        ["Level", "Bezeichnung", "Kriterien"],
        ["L1", "Mathematisch bewiesen",
         "Direkter UTXO-Link — kryptographisch unwiderlegbar"],
        ["L2", "Forensisch belegt",
         "Direkte Exchange-Attribution aus validierter Quelle (z. B. offizieller Seed, lokaler Intel-Agent, WalletExplorer)"],
        ["L3", "Hinweis (nicht beweiskräftig)",
         "Downstream-, Muster- oder Kontext-Hinweis — nicht belastend und nicht im Report"],
        ["L4", "Spekulativ",
         "Heuristisch, keine direkte Verbindung — nicht im Report"],
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
        "Dieser Bericht enthält ausschließlich L1- und L2-Befunde. "
        "L3/L4-Beobachtungen wurden bewusst ausgeschlossen um die "
        "Gerichtsverwertbarkeit zu gewährleisten.",
        styles["small"]
    ))
    return story


def _transaction_graph(styles):
    """Visueller Transaktionsgraph als ReportLab Drawing."""
    from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle, PolyLine
    from reportlab.graphics import renderPDF

    story = [Paragraph("2. Transaktionsgraph — Übersicht", styles["h1"])]
    story += _hr()
    story.append(Paragraph(
        "Der folgende Graph zeigt den vollständigen Transaktionspfad der gestohlenen "
        "Bitcoin. Rote Knoten = Täter-Adressen, grüne Knoten = identifizierte Exchanges, "
        "graue Knoten = Intermediäre. Jede Kante repräsentiert eine on-chain Transaktion.",
        styles["body"]
    ))
    story.append(Spacer(1, 8))

    # Canvas
    W = (PAGE_W - 2*MARGIN)
    H = 130 * mm
    d = Drawing(W, H)

    # Farben
    COL_VICTIM   = colors.HexColor("#C0392B")   # rot — Opfer
    COL_THIEF    = colors.HexColor("#E67E22")   # orange — Täter
    COL_INTER    = colors.HexColor("#7F8C8D")   # grau — Intermediär
    COL_EXCHANGE = colors.HexColor("#1E8449")   # grün — Exchange
    COL_EDGE     = colors.HexColor("#2C3E50")
    COL_WHITE    = colors.white
    COL_LIGHT    = colors.HexColor("#ECF0F1")

    # Dynamischer Graph aus HOPS
    # Schritt 1: Alle eindeutigen Adressen sammeln
    addr_roles = {}  # addr -> role: victim/thief/inter/exchange
    
    # Opfer-Adressen
    for addr, _ in (HOPS[0]["from_addresses"] if HOPS else []):
        if addr:
            addr_roles[addr] = "victim"
    
    # Alle anderen Adressen aus Hops
    for hop in HOPS:
        for addr, _ in hop.get("to_addresses", []):
            if not addr:
                continue
            if addr in addr_roles:
                continue
            if hop.get("exchange"):
                addr_roles[addr] = "exchange"
            else:
                addr_roles[addr] = "thief"
        for addr, _ in hop.get("from_addresses", []):
            if addr and addr not in addr_roles:
                addr_roles[addr] = "thief"

    # Schritt 2: Unique Adressen als Nodes platzieren
    unique_addrs = list(dict.fromkeys(
        [a for h in HOPS for a,_ in h.get("from_addresses",[]) + h.get("to_addresses",[]) if a]
    ))
    
    n = len(unique_addrs)
    nodes = {}
    for i, addr in enumerate(unique_addrs):
        role = addr_roles.get(addr, "thief")
        x_pct = 0.05 + (i / max(n-1, 1)) * 0.90
        y_pct = 0.5
        # Staffeln: Opfer oben, Exchanges unten
        if role == "victim":
            y_pct = 0.80
        elif role == "exchange":
            y_pct = 0.20
        elif i % 2 == 0:
            y_pct = 0.65
        else:
            y_pct = 0.35
            
        col = {"victim": COL_VICTIM, "thief": COL_THIEF,
               "exchange": COL_EXCHANGE, "inter": COL_INTER}.get(role, COL_THIEF)
        short = addr[:10] + "..."
        label = addr[:8] + "..."
        radius = 11 if role == "exchange" else (10 if role == "victim" else 7)
        
        # Exchange Namen
        ex_name = next((h.get("exchange","") for h in HOPS 
                       if any(a==addr for a,_ in h.get("to_addresses",[]))), "")
        sublabel = ex_name if ex_name else f"{short}"
        if ex_name:
            label = ex_name
            
        nodes[addr] = (x_pct, y_pct, label, sublabel, col, radius)

    # Schritt 3: Edges aus Hops
    edges = []
    for hop in HOPS:
        for from_addr, _ in hop.get("from_addresses", []):
            if not from_addr or from_addr not in nodes:
                continue
            for to_addr, _ in hop.get("to_addresses", []):
                if not to_addr or to_addr not in nodes:
                    continue
                conf = hop.get("confidence", "L1")
                tx_short = hop["txid"][:8] if len(hop["txid"]) == 64 else ""
                block = hop.get("block", "")
                edge_label = f"TX {tx_short}\nBlock {block}" if tx_short and conf == "L1" else ""
                edges.append((from_addr, to_addr, edge_label, conf))

    # Positionen berechnen
    pos = {}
    for key, (xp, yp, *_) in nodes.items():
        pos[key] = (xp * W, yp * H)

    # Edges zeichnen
    for src, dst, label, conf in edges:
        if src not in pos or dst not in pos:
            continue
        x1, y1 = pos[src]
        x2, y2 = pos[dst]
        edge_color = COL_EDGE if conf == "L1" else colors.HexColor("#AEB6BF")
        dash = None if conf == "L1" else [3, 2]

        line = Line(x1, y1, x2, y2,
                    strokeColor=edge_color,
                    strokeWidth=1.2 if conf == "L1" else 0.8,
                    strokeDashArray=dash)
        d.add(line)

        # Pfeil-Spitze
        import math
        dx, dy = x2 - x1, y2 - y1
        length = math.sqrt(dx*dx + dy*dy)
        if length > 0:
            ux, uy = dx/length, dy/length
            # Zurücksetzen um Node-Radius
            nr = (nodes[dst][5] if dst in nodes else 7) + 1
            ax = x2 - ux * nr
            ay = y2 - uy * nr
            # Pfeil
            perp_x, perp_y = -uy * 3, ux * 3
            arrow = PolyLine(
                [ax - ux*6 + perp_x, ay - uy*6 + perp_y,
                 ax, ay,
                 ax - ux*6 - perp_x, ay - uy*6 - perp_y],
                strokeColor=edge_color, strokeWidth=1.2
            )
            d.add(arrow)

        # Edge-Label
        if label and conf == "L1":
            mx = (x1 + x2) / 2
            my = (y1 + y2) / 2
            for i, line_txt in enumerate(label.split("\n")):
                lbl = String(mx + 2, my + 4 - i*7, line_txt,
                             fontSize=5, fillColor=COL_EDGE,
                             textAnchor="middle")
                d.add(lbl)

    # Nodes zeichnen
    for key, (xp, yp, label, sublabel, col, r) in nodes.items():
        x, y = pos[key]

        # Schatten
        shadow = Circle(x + 1.5, y - 1.5, r,
                        fillColor=colors.HexColor("#BDC3C7"),
                        strokeColor=None)
        d.add(shadow)

        # Node
        circle = Circle(x, y, r, fillColor=col,
                        strokeColor=COL_WHITE, strokeWidth=1.5)
        d.add(circle)

        # Label (mehrzeilig)
        for i, line_txt in enumerate(label.split("\n")):
            lbl = String(x, y - (len(label.split("\n")) - 1) * 4 + i * 8 - 3,
                         line_txt, fontSize=5.5,
                         fillColor=COL_WHITE, textAnchor="middle")
            d.add(lbl)

        # Sub-Label unterhalb
        sub = String(x, y - r - 9, sublabel,
                     fontSize=5, fillColor=COL_EDGE,
                     textAnchor="middle")
        d.add(sub)

    # Legende
    legend_items = [
        (COL_VICTIM,   "Opfer-Adresse"),
        (COL_THIEF,    "Täter-Adresse"),
        (COL_INTER,    "Intermediär (unbekannt)"),
        (COL_EXCHANGE, "Identifizierte Exchange"),
    ]
    lx = 10
    ly = 10
    for col, label in legend_items:
        c = Circle(lx + 5, ly + 4, 4, fillColor=col,
                   strokeColor=COL_WHITE, strokeWidth=0.8)
        d.add(c)
        s = String(lx + 12, ly + 1, label,
                   fontSize=6, fillColor=COL_EDGE)
        d.add(s)
        lx += 50

    story.append(d)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "— — — Gestrichelte Linien = L2 (forensisch belegt, nicht mathematisch bewiesen) | "
        "Durchgezogene Linien = L1 (mathematisch bewiesen via UTXO)",
        styles["small"]
    ))
    story.append(Spacer(1, 8))
    return story


def _chain_of_custody(styles):
    story = [Paragraph("2. Transaktionskette (Chain of Custody)", styles["h1"])]
    story += _hr()
    story.append(Paragraph(
        "Die folgende Tabelle dokumentiert den vollständigen, on-chain verifizierbaren "
        "Transaktionspfad der gestohlenen Bitcoin vom Opfer bis zur Exchange.",
        styles["body"]
    ))
    story.append(Spacer(1, 6))

    for hop in HOPS:
        conf = hop["confidence"]
        conf_color = CONF_COLORS.get(conf, C_DARK)

        # Hop-Header
        header_data = [[
            Paragraph(f"Hop {hop['hop']} — {hop['label']}", ParagraphStyle(
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
            ["TX-ID", Paragraph(str(hop["txid"]), styles["mono"])],
            ["Block", str(hop["block"])],
            ["Zeitstempel", hop["timestamp"]],
            ["Methode", hop["method"]],
        ]

        # Inputs
        if hop["from_addresses"]:
            for i, (addr, val) in enumerate(hop["from_addresses"]):
                label = "Von" if i == 0 else ""
                val_str = f"{val:.8f} BTC" if val else "—"
                detail_rows.append([label, Paragraph(
                    f"{addr}  <b>{val_str}</b>", styles["mono"]
                )])

        # Outputs
        if hop["to_addresses"]:
            for i, (addr, val) in enumerate(hop["to_addresses"]):
                label = "An" if i == 0 else ""
                val_str = f"{val:.8f} BTC" if val else "—"
                detail_rows.append([label, Paragraph(
                    f"{addr}  <b>{val_str}</b>", styles["mono"]
                )])

        if hop.get("fee_btc"):
            detail_rows.append(["Fee", f"{hop['fee_btc']:.8f} BTC"])

        detail_rows.append(["Hinweis", Paragraph(hop["notes"], styles["small"])])

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
                f"Verifikation: {verify_url}",
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
                    "⬛  KETTENENDE — Exchange identifiziert",
                    "Die gestohlenen Mittel wurden auf einer Kryptobörse eingezahlt. "
                    "Die L1-Beweiskette endet hier. Ein formeller Freeze-Request wurde "
                    "für diese Exchange generiert."
                ),
                "pooling": (
                    colors.HexColor("#5D4037"),
                    "⬛  KETTENENDE — Pooling / Konsolidierung erkannt",
                    "Die gestohlenen Mittel wurden mit Fremdmitteln zusammengeführt. "
                    "Eine mathematisch eindeutige Zuordnung (L1) ist ab diesem Punkt "
                    "nicht mehr möglich. Die Beweiskette endet hier gemäss forensischem Standard."
                ),
                "unspent": (
                    colors.HexColor("#1A5276"),
                    "⬛  KETTENENDE — UTXO nicht ausgegeben",
                    "Die gestohlenen Mittel liegen noch unausgegeben an dieser Adresse "
                    "(Stand: Analysezeitpunkt). Die Kette endet hier natürlich. "
                    "Ein direktes Freeze-Request an Behörden ist empfohlen."
                ),
                "lookup_incomplete": (
                    colors.HexColor("#7D6608"),
                    "⬛  KETTENENDE — Weiterleitung technisch nicht vollstaendig aufgeloest",
                    "Die Mittel wurden nicht als unspent klassifiziert. "
                    "Vielmehr war die Spend-Aufloesung mit der aktuellen Infrastruktur unvollstaendig, "
                    "sodass der naechste Hop nicht belastbar bestimmt werden konnte. "
                    "Der Bericht ist an dieser Stelle unvollstaendig und darf nicht als Endpunktbewertung gelesen werden."
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
    story = [Paragraph("4. Berichtsintegrität", styles["h1"])]
    story += _hr()
    rows = [
        ["SHA-256 Prüfsumme", Paragraph(report_hash, styles["mono"])],
        ["Generiert am", CASE["generated_at"]],
        ["System", "AIFinancialCrime Forensik-System v1.0"],
        ["Datenquelle", "Bitcoin-Node/Blockstream + BTC Exchange Intel Agent"],
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
        "Dieser Bericht wurde automatisch durch das AIFinancialCrime Forensik-System "
        "generiert. Alle on-chain Daten sind öffentlich verifizierbar. "
        "Die SHA-256 Prüfsumme dient der Integritätsverifikation des Berichtsinhalts.",
        styles["small"]
    ))
    return story


def _recommended_actions(styles):
    story = [Paragraph("3. Empfohlene Maßnahmen", styles["h1"])]
    story += _hr()

    actions = [
        ("SOFORT (innerhalb 24h)",
         C_ALERT,
         [
             "Strafanzeige bei der zuständigen Polizeibehörde erstatten (Cybercrime-Abteilung)",
         ] + [
             f"Freeze-Request an {ex['name']} Compliance: {ex['compliance_email']}"
             for ex in EXCHANGES_IDENTIFIED
         ] + [
             "Alle Freeze-Requests mit dieser Analyse und den TX-IDs dokumentieren",
         ]),
        ("KURZFRISTIG (innerhalb 1 Woche)",
         C_WARNING,
         [
             "Anzeige bei BaFin (Deutschland) oder zuständiger nationaler Finanzaufsicht",
             "Europol EC3 Meldung: https://www.europol.europa.eu/report-a-crime",
             "Rechtsanwalt mit Cryptocurrency-Erfahrung hinzuziehen",
             "Betroffene Wallet-/Seed-Umgebung als kompromittiert behandeln und neue Zugangsdaten beziehungsweise Seed-Phrase erzeugen",
         ]),
        ("MITTELFRISTIG",
         C_SUCCESS,
         [
             "Antwort der Exchanges abwarten und dokumentieren",
             "Bei Kontoeinfrierung: Strafverfolgung koordinieren",
             "Zivilrechtliche Schritte prüfen falls Exchange kooperiert",
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

    story.append(Paragraph(f"An: {exchange_data['name']} Compliance Team", styles["body_bold"]))
    story.append(Paragraph(f"E-Mail: {exchange_data['compliance_email']}", styles["body"]))
    story.append(Paragraph(f"Datum: {CASE['generated_at']}", styles["body"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Betreff: Dringende Anfrage zur Kontoeinfrierung — Bitcoin-Diebstahl", styles["h1"]))
    story += _hr()

    story.append(Paragraph(
        f"Sehr geehrtes Compliance-Team von {exchange_data['name']},",
        styles["body"]
    ))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"hiermit beantrage ich die sofortige Einfrierung aller Konten und Vermögenswerte "
        f"die mit den unten genannten Bitcoin-Adressen in Verbindung stehen. "
        f"Am {_case_text('incident_date')} wurden <b>{_btc_label(CASE.get('fraud_amount'))}</b> "
        f"ohne meine Autorisierung aus meiner Wallet-Umgebung abgezogen. "
        f"Die forensische Blockchain-Analyse (beigefügt) belegt, dass ein Teil dieser "
        f"Mittel über Ihre Plattform geflossen ist.",
        styles["body"]
    ))
    story.append(Spacer(1, 8))

    # Identifizierte Adressen
    story.append(Paragraph("Identifizierte Adressen auf Ihrer Plattform:", styles["h2"]))
    addr_rows = [
        ["Bitcoin-Adresse", exchange_data["address"]],
        ["Attribution", exchange_data["label"]],
        ["Wallet-ID", exchange_data["wallet_id"]],
        ["Confidence", f"{exchange_data['confidence']} — Forensisch belegt (validierte Quelle)"],
        ["BTC betroffen", f"{exchange_data['btc_involved']:.8f} BTC"],
    ]
    addr_tbl = Table(addr_rows, colWidths=[35*mm, PAGE_W - 2*MARGIN - 35*mm])
    addr_tbl.setStyle(TableStyle([
        ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8.5),
        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#FDEDEE")),
        ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
        ("BOX",           (0,0), (-1,-1), 1.5, C_ALERT),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
    ]))
    story.append(addr_tbl)
    story.append(Spacer(1, 8))

    # Ursprungs-TX
    _fraud_txid = HOPS[0]["txid"] if HOPS else ""
    _fraud_block = str(HOPS[0].get("block", "")) if HOPS else ""
    _fraud_ts = HOPS[0].get("timestamp", _case_text("incident_date", "")) if HOPS else _case_text("incident_date", "")
    _fraud_amount = _btc_label(CASE.get("fraud_amount"))
    story.append(Paragraph("Ursprungstransaktion (Diebstahl):", styles["h2"]))
    tx_rows = [
        ["TX-ID",       _fraud_txid],
        ["Block",       _fraud_block],
        ["Zeitstempel", _fraud_ts],
        ["Betrag",      _fraud_amount],
        ["Verifikation", f"https://blockstream.info/tx/{_fraud_txid}"],
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

    # Rechtliche Grundlage
    story.append(Paragraph("Rechtliche Grundlage:", styles["h2"]))
    story.append(Paragraph(
        "• EU Anti-Money Laundering Directive (AMLD5/6) — Exchanges sind verpflichtet "
        "bei begründetem Verdacht auf Geldwäsche oder Betrug zu kooperieren.\n"
        "• FATF Recommendation 16 (Travel Rule) — Nachverfolgungspflicht bei Transfers.\n"
        "• Strafgesetzbuch §263 (Betrug) / §202a (Datendiebstahl) — Strafanzeige ist gestellt.\n"
        "• Eine vollständige forensische Analyse ist diesem Schreiben beigefügt.",
        styles["body"]
    ))
    story.append(Spacer(1, 8))

    # Anforderungen
    req_data = [[Paragraph(
        "WIR BEANTRAGEN:\n"
        "1. Sofortige Einfrierung aller Konten die mit der oben genannten Adresse verknüpft sind\n"
        "2. Sicherung aller KYC-Daten des Kontoinhabers\n"
        "3. Bestätigung des Eingangs dieser Anfrage binnen 24 Stunden\n"
        "4. Kooperation mit den zuständigen Strafverfolgungsbehörden",
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

    story.append(Paragraph("Mit freundlichen Grüßen,", styles["body"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>{CASE['victim_name']}</b>", styles["body_bold"]))
    story.append(Paragraph(f"Fall-Referenz: {CASE['case_id']}", styles["small"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"Beilage: Vollständiger forensischer Blockchain-Analysebericht ({CASE['case_id']})",
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
    Lädt die Hop-Chain automatisch aus PostgreSQL.
    Ersetzt die hardcoded HOPS für Hops 1+.
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
                    # Outputs die ausgegeben wurden
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

                    # Outputs der Folge-TX
                    with conn.cursor() as cur:
                        cur.execute("""
                            SELECT o2.address, o2.amount_sats
                            FROM tx_outputs o2
                            WHERE o2.txid = %s
                            ORDER BY o2.amount_sats DESC
                        """, (to_txid,))
                        to_rows = cur.fetchall()

                    to_addresses = [(r[0], r[1]/1e8) for r in to_rows if r[0]]
                    ts_str = ts.strftime("%d.%m.%Y ~%H:%M UTC") if ts else "—"

                    hops.append({
                        "hop": hop_idx,
                        "label": f"Hop {hop_idx} — UTXO Weiterleitung",
                        "txid": to_txid,
                        "block": block or 0,
                        "timestamp": ts_str,
                        "from_addresses": [(from_addr, amount_sats/1e8)],
                        "to_addresses": to_addresses,
                        "fee_btc": None,
                        "confidence": "L1",
                        "confidence_label": "Mathematisch bewiesen",
                        "method": "Direkter UTXO-Link",
                        "notes": f"Automatisch erkannt via lokalen Bitcoin-Node.",
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

    # --- Hauptbericht ---
    print("Generiere forensischen Analysebericht...")
    report_content = str(HOPS) + str(CASE)
    report_hash = hashlib.sha256(report_content.encode()).hexdigest()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=18*mm, bottomMargin=16*mm,
        title=f"Forensischer Analysebericht {CASE['case_id']}",
        author="AIFinancialCrime Forensik-System",
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

    report_path = str(OUTPUT_DIR / f"{CASE['case_id']}_Forensischer_Analysebericht.pdf")
    with open(report_path, "wb") as f:
        f.write(buf.getvalue())
    print(f"  ✅ {report_path}")

    # --- Freeze Requests ---
    print("Generiere Freeze Requests...")
    for ex in EXCHANGES_IDENTIFIED:
        path = str(OUTPUT_DIR / f"{CASE['case_id']}_Freeze_Request_{ex['name']}.pdf")
        _freeze_request(ex, styles, path)

    print(f"\n✅ Alle Dokumente generiert in {OUTPUT_DIR}")
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

    print(f"✅ Fallakte geladen: {case_file}")
    print(f"   Geschädigter: {CASE['victim_name']}")
    print(f"   Betrag:       {CASE['fraud_amount']} BTC")
    print(f"   TX-ID:        {str(blockchain.get('fraud_txid', '?'))[:32]}...")

    fraud_txid = blockchain.get("fraud_txid")
    if fraud_txid:
        print("Lade Hops aus PostgreSQL-DB...")
        db_hops = load_hops_from_db(fraud_txid)
        if db_hops:
            HOPS[1:] = db_hops
            print(f"   {len(db_hops)} Hops aus DB geladen.")
        else:
            print("   Keine Hops in DB — nutze vorhandene Hops.")


def cli(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="AIFinancialCrime Report Generator")
    parser.add_argument(
        "--case",
        metavar="ID",
        help="Fall-ID — lädt cases/<ID>.json und generiert Report",
    )
    args = parser.parse_args(argv)

    if args.case:
        try:
            _load_case_from_file(args.case)
        except FileNotFoundError as exc:
            print(f"❌ Fallakte nicht gefunden: {exc}")
            print(f"   Bitte Fallakte in ~/AIFinancialCrime-Cases/cases/ ablegen.")
            return 1

    generate_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
