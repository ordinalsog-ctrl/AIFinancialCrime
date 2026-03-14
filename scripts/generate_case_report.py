#!/usr/bin/env python3
"""
AIFinancialCrime — Fall-Report Generator
=========================================
Standalone Script für Fall: Ledger Wallet Diebstahl 12.12.2025
Generiert:
  1. Forensischer Analysebericht (PDF)
  2. Freeze-Request Huobi (PDF)
  3. Freeze-Request Poloniex (PDF)

Aufruf:
    python3 generate_case_report.py
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

CASE = {
    "case_id":        "AIFC-2025-001",
    "victim_name":    "Jonas Weiss",
    "victim_contact": "",
    "incident_date":  "12.12.2025 09:44 UTC",
    "discovery_date": "19.12.2025",
    "fraud_amount":   "0.41240620 BTC",
    "fraud_amount_eur": "~38.000 EUR (Kurs 12.12.2025)",
    "wallet_type":    "Ledger Hardware Wallet (USB)",
    "generated_at":   datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
}

# Transaktionskette
HOPS = [
    {
        "hop": 0,
        "label": "Diebstahl — Konsolidierung",
        "txid": "1f4bfff88ef9cfa869665cb27acbe03974bf640ccb73479bf8a3592c1c081101",
        "block": 927547,
        "timestamp": "12.12.2025 09:44 UTC",
        "from_addresses": [
            ("bc1qg2q5yr6w5dw84hzcajsy5pzwxkvqz3y79vqamr", 0.12248481),
            ("bc1q7arfhs692cwgj7nhnugs3vzt3z77zyl5zfnpae", 0.02086576),
            ("bc1q2nqts9hey3u63ls86l5y6y9pf7hzsf8m6097zs", 0.00712257),
            ("bc1qxxc49pfhstaxvq9gg5965pmq35h43xzvkmd5vd", 0.00857886),
            ("bc1qvegrt50sd3hf8my4f7myc2hq6gr40a238vl09c", 0.00857713),
            ("bc1qrtefpya3kjn93lrr3440jm3rg3e8qd5cwf6tvk", 0.06139335),
            ("bc1quk6r256n6x3lfdg3vfzvfgswvm07p8tks53w6h", 0.05488155),
            ("bc1q8chlflparxe6vdyhps0ykf9utlp5g0nqtvc0a7", 0.10507195),
            ("bc1q7mphfunurltapx93ge2jvzly0z838r7m3uy5j0", 0.02345670),
        ],
        "to_addresses": [
            ("bc1qztlxu7flfclwfadlysrlv3lc5efnlrhxtwud72", 0.41240620),
        ],
        "fee_btc": 0.00002648,
        "confidence": "L1",
        "confidence_label": "Mathematisch bewiesen",
        "method": "Direkter UTXO-Link",
        "notes": "9 Opfer-Adressen in einer TX konsolidiert. Vollständiger Saldo abgezogen. Keine Change-Output.",
    },
    {
        "hop": 1,
        "label": "Layering — Split in zwei Pfade",
        "txid": "5e1e80ff0bb4362ccdd2626df3b6c5f95c8a661c4e8ab27be1d489c707b66371",
        "block": 927550,
        "timestamp": "12.12.2025 ~10:14 UTC",
        "from_addresses": [
            ("bc1qztlxu7flfclwfadlysrlv3lc5efnlrhxtwud72", 0.41240620),
        ],
        "to_addresses": [
            ("bc1qtm8nrnm6n4498mym3tndaddttc0d53pzqmrcgn", 0.20000000),
            ("bc1qztlxu7flfclwfadlysrlv3lc5efnlrhxtwud72", 0.21240479),
        ],
        "fee_btc": 0.00000141,
        "confidence": "L1",
        "confidence_label": "Mathematisch bewiesen",
        "method": "Direkter UTXO-Link",
        "notes": "Runder Betrag (0.20 BTC) typisch für Exchange-Einzahlung. Change zurück an Täter-Adresse.",
    },
    {
        "hop": 2,
        "label": "Layering — Zweiter Split",
        "txid": "578dbd7a557c6307b8306f68434363b2cfe14bc889cfa7d2c0e7b8c72b3d962a",
        "block": 927551,
        "timestamp": "12.12.2025 ~10:20 UTC",
        "from_addresses": [
            ("bc1qztlxu7flfclwfadlysrlv3lc5efnlrhxtwud72", 0.21240479),
        ],
        "to_addresses": [
            ("bc1qtrqkv3kk4jeecz4psnzcdz3hdkrmyeuuzcw8d3", 0.21240000),
        ],
        "fee_btc": 0.00000479,
        "confidence": "L1",
        "confidence_label": "Mathematisch bewiesen",
        "method": "Direkter UTXO-Link",
        "notes": "Restbetrag weitergeleitet.",
    },
    {
        "hop": 3,
        "label": "Exchange-Einzahlung Pfad A → Intermediär",
        "txid": "df8dd0028b34abc4193205b4711f1a38ada20f0c3514a0d5a579da0e81b54d6a",
        "block": 927550,
        "timestamp": "12.12.2025 ~10:14 UTC",
        "from_addresses": [
            ("bc1qtm8nrnm6n4498mym3tndaddttc0d53pzqmrcgn", 0.20000000),
        ],
        "to_addresses": [
            ("1DLymHytXsdD2Bhz7Ywa8JpGX7QsQFH1xr", 0.19999805),
        ],
        "fee_btc": 0.00000195,
        "confidence": "L1",
        "confidence_label": "Mathematisch bewiesen",
        "method": "Direkter UTXO-Link",
        "notes": "Intermediär-Adresse mit 56 TXs und 0.527 BTC Gesamtvolumen.",
    },
    {
        "hop": 4,
        "label": "Exchange-Einzahlung Pfad B → Intermediär",
        "txid": "8d362e37f4079db1bd28c203374450f903d2eb8bb8359f732f0f63504d48cf8e",
        "block": 927551,
        "timestamp": "12.12.2025 ~10:20 UTC",
        "from_addresses": [
            ("bc1qtrqkv3kk4jeecz4psnzcdz3hdkrmyeuuzcw8d3", 0.21240000),
        ],
        "to_addresses": [
            ("1B2opjpPPJNVQHmCjyxqnGP6mLq4wQcPgg", 0.21239805),
        ],
        "fee_btc": 0.00000195,
        "confidence": "L1",
        "confidence_label": "Mathematisch bewiesen",
        "method": "Direkter UTXO-Link",
        "notes": "Intermediär-Adresse mit 37 TXs und 1.764 BTC Gesamtvolumen.",
    },
    {
        "hop": 5,
        "label": "Exchange-Identifikation — HUOBI (Pfad A + B)",
        "txid": "mehrere (siehe Hop 3+4 Weiterleitung)",
        "block": "927550–938583",
        "timestamp": "12.12.2025 – Jan 2026",
        "from_addresses": [
            ("1DLymHytXsdD2Bhz7Ywa8JpGX7QsQFH1xr", 0.19999805),
            ("1B2opjpPPJNVQHmCjyxqnGP6mLq4wQcPgg", 0.21239805),
        ],
        "to_addresses": [
            ("1AQLXAB6aXSVbRMjbhSBudLf1kcsbWSEjg", None),
        ],
        "fee_btc": None,
        "confidence": "L2",
        "confidence_label": "Forensisch belegt",
        "method": "WalletExplorer Attribution (wallet_id: 0000044b60b2c25d)",
        "notes": "Adresse 1AQLXAB6... ist Teil des Huobi.com-2 Wallet-Clusters. 103.134 TXs, 583.144 BTC Gesamtvolumen. Quelle: WalletExplorer.com.",
        "exchange": "Huobi",
    },
    {
        "hop": 6,
        "label": "Exchange-Identifikation — POLONIEX (Pfad A)",
        "txid": "via Cluster 0000001bce8b8aa0",
        "block": "~928000+",
        "timestamp": "nach 12.12.2025",
        "from_addresses": [
            ("1DLymHytXsdD2Bhz7Ywa8JpGX7QsQFH1xr", None),
        ],
        "to_addresses": [
            ("1LgW4RA5iE98khRJ58Bhx5RLABP3QGjn9y", None),
        ],
        "fee_btc": None,
        "confidence": "L2",
        "confidence_label": "Forensisch belegt",
        "method": "WalletExplorer Attribution (Poloniex.com)",
        "notes": "Adresse 1LgW4RA5... ist Poloniex.com zugeordnet per WalletExplorer. Indirekter Pfad via Intermediär-Cluster.",
        "exchange": "Poloniex",
    },
]

EXCHANGES_IDENTIFIED = [
    {
        "name": "Huobi",
        "address": "1AQLXAB6aXSVbRMjbhSBudLf1kcsbWSEjg",
        "wallet_id": "0000044b60b2c25d",
        "label": "Huobi.com-2",
        "tx_count": 103134,
        "confidence": "L2",
        "compliance_email": "compliance@huobi.com",
        "compliance_url": "https://www.htx.com/en-us/support/",
        "btc_involved": 0.41240620,
        "note": "Beide Pfade (A+B) führen zu dieser Adresse.",
    },
    {
        "name": "Poloniex",
        "address": "1LgW4RA5iE98khRJ58Bhx5RLABP3QGjn9y",
        "wallet_id": "Poloniex.com (WalletExplorer)",
        "label": "Poloniex.com",
        "tx_count": None,
        "confidence": "L2",
        "compliance_email": "support@poloniex.com",
        "compliance_url": "https://poloniex.com/support",
        "btc_involved": 0.19999805,
        "note": "Indirekter Pfad via Intermediär-Cluster.",
    },
]

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
        Paragraph("Wallet-Diebstahl — Ledger Hardware Wallet", ParagraphStyle(
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
        ["Fall-ID",           CASE["case_id"]],
        ["Geschädigter",      CASE["victim_name"]],
        ["Schadensdatum",     CASE["incident_date"]],
        ["Entdeckungsdatum",  CASE["discovery_date"]],
        ["Schadensbetrag",    f"{CASE['fraud_amount']} ({CASE['fraud_amount_eur']})"],
        ["Wallet-Typ",        CASE["wallet_type"]],
        ["Berichtsdatum",     CASE["generated_at"]],
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
    story.append(Paragraph(
        f"Am {CASE['incident_date']} wurden ohne Autorisierung des Inhabers "
        f"<b>{CASE['fraud_amount']}</b> Bitcoin vom vollständigen Bestand einer Ledger "
        f"Hardware Wallet entwendet. Die gestohlenen Mittel wurden in einer einzigen "
        f"Transaktion (9 Inputs → 1 Output) konsolidiert und anschließend durch "
        f"Splitting auf zwei Pfade aufgeteilt (Layering). Die Blockchain-Analyse "
        f"identifiziert <b>Huobi</b> und <b>Poloniex</b> als Ziel-Exchanges.",
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
         "Betragsübereinstimmung + Exchange-Attribution (WalletExplorer)"],
        ["L3", "Hinweis (nicht beweiskräftig)",
         "Muster erkennbar, zeitlicher Zusammenhang — nicht im Report"],
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

    # Node-Definitionen: (x_pct, y_pct, label, sublabel, color, radius)
    # x/y in Prozent der Canvas-Breite/Höhe
    nodes = {
        "victim":   (0.08, 0.50, "9 Opfer-\nAdressen", "0.4124 BTC", COL_VICTIM,   10),
        "thief":    (0.28, 0.50, "bc1qztlxu7...", "Täter-Wallet", COL_THIEF,    9),
        "split_a":  (0.46, 0.72, "bc1qtm8nrn...", "0.2000 BTC", COL_THIEF,    7),
        "split_b":  (0.46, 0.28, "bc1qtrqkv3...", "0.2124 BTC", COL_THIEF,    7),
        "inter_a":  (0.63, 0.72, "1DLymHytX...", "Intermediär", COL_INTER,    7),
        "inter_b":  (0.63, 0.28, "1B2opjpPP...", "Intermediär", COL_INTER,    7),
        "huobi":    (0.85, 0.60, "Huobi", "1AQLXAB6...", COL_EXCHANGE, 11),
        "poloniex": (0.85, 0.28, "Poloniex", "1LgW4RA5...", COL_EXCHANGE, 11),
        "unknown":  (0.85, 0.85, "Unbekannt", "Intermediär", COL_INTER,    8),
    }

    # Edges: (from, to, label, confidence)
    edges = [
        ("victim",  "thief",    "TX 1f4bfff8\nBlock 927547", "L1"),
        ("thief",   "split_a",  "TX 5e1e80ff\nBlock 927550", "L1"),
        ("thief",   "split_b",  "TX 578dbd7a\nBlock 927551", "L1"),
        ("split_a", "inter_a",  "TX df8dd002\nBlock 927550", "L1"),
        ("split_b", "inter_b",  "TX 8d362e37\nBlock 927551", "L1"),
        ("inter_a", "huobi",    "L2", "L2"),
        ("inter_b", "huobi",    "L2", "L2"),
        ("inter_a", "unknown",  "", "L2"),
        ("inter_b", "poloniex", "L2", "L2"),
    ]

    # Positionen berechnen
    pos = {}
    for key, (xp, yp, *_) in nodes.items():
        pos[key] = (xp * W, yp * H)

    # Edges zeichnen
    for src, dst, label, conf in edges:
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
            nr = nodes[dst][5] + 1
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

        story.append(KeepTogether([header_tbl, detail_tbl] + verify + [Spacer(1, 8)]))

    return story


def _integrity(report_hash, styles):
    story = [Paragraph("4. Berichtsintegrität", styles["h1"])]
    story += _hr()
    rows = [
        ["SHA-256 Prüfsumme", Paragraph(report_hash, styles["mono"])],
        ["Generiert am", CASE["generated_at"]],
        ["System", "AIFinancialCrime Forensik-System v1.0"],
        ["Datenquelle", "Blockstream.info API + WalletExplorer.com"],
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
             "Freeze-Request an Huobi Compliance: compliance@huobi.com",
             "Freeze-Request an Poloniex Compliance: support@poloniex.com",
             "Alle Freeze-Requests mit dieser Analyse und den TX-IDs dokumentieren",
         ]),
        ("KURZFRISTIG (innerhalb 1 Woche)",
         C_WARNING,
         [
             "Anzeige bei BaFin (Deutschland) oder zuständiger nationaler Finanzaufsicht",
             "Europol EC3 Meldung: https://www.europol.europa.eu/report-a-crime",
             "Rechtsanwalt mit Cryptocurrency-Erfahrung hinzuziehen",
             "Alle Ledger-Geräte als kompromittiert betrachten — neue Seed-Phrase generieren",
         ]),
        ("MITTELFRISTIG",
         C_SUCCESS,
         [
             "Antwort der Exchanges abwarten (typisch: 2-4 Wochen)",
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
        f"Am {CASE['incident_date']} wurden <b>{CASE['fraud_amount']}</b> Bitcoin "
        f"ohne meine Autorisierung von meiner Ledger Hardware Wallet entwendet. "
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
        ["Confidence", f"{exchange_data['confidence']} — Forensisch belegt (WalletExplorer)"],
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
    story.append(Paragraph("Ursprungstransaktion (Diebstahl):", styles["h2"]))
    tx_rows = [
        ["TX-ID",      "1f4bfff88ef9cfa869665cb27acbe03974bf640ccb73479bf8a3592c1c081101"],
        ["Block",      "927547"],
        ["Zeitstempel","12.12.2025 09:44 UTC"],
        ["Betrag",     "0.41240620 BTC (gesamter Wallet-Bestand)"],
        ["Verifikation","https://blockstream.info/tx/1f4bfff88ef9cfa869665cb27acbe03974bf640ccb73479bf8a3592c1c081101"],
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
        "Beilage: Vollständiger forensischer Blockchain-Analysebericht (AIFC-2025-001)",
        styles["small"]
    ))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    with open(output_path, "wb") as f:
        f.write(buf.getvalue())
    print(f"  ✅ {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_all():
    styles = _styles()
    os.makedirs("output", exist_ok=True)

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

    report_path = f"output/{CASE['case_id']}_Forensischer_Analysebericht.pdf"
    with open(report_path, "wb") as f:
        f.write(buf.getvalue())
    print(f"  ✅ {report_path}")

    # --- Freeze Requests ---
    print("Generiere Freeze Requests...")
    for ex in EXCHANGES_IDENTIFIED:
        path = f"output/{CASE['case_id']}_Freeze_Request_{ex['name']}.pdf"
        _freeze_request(ex, styles, path)

    print(f"\n✅ Alle Dokumente generiert in ./output/")
    print(f"   SHA-256: {report_hash}")



# PATCH: --case argument support
import sys as _sys
if '--case' in _sys.argv:
    import argparse as _ap, json as _json, pathlib as _pl
    from datetime import datetime as _dt, timezone as _tz
    _p = _ap.ArgumentParser()
    _p.add_argument('--case')
    _args, _ = _p.parse_known_args()
    if _args.case:
        _f = _pl.Path('cases') / f'{_args.case}.json'
        if not _f.exists():
            print(f'Fallakte nicht gefunden: {_f}')
            _sys.exit(1)
        with open(_f) as _fh:
            _d = _json.load(_fh)
        _v = _d.get('victim', {})
        _inc = _d.get('incident', {})
        _bc = _d.get('blockchain', {})
        CASE['case_id']          = _d.get('case_id', _args.case)
        CASE['victim_name']      = _v.get('name', '')
        CASE['victim_contact']   = _v.get('email', '')
        CASE['incident_date']    = _inc.get('date', '')
        CASE['discovery_date']   = _inc.get('discovery_date', '')
        CASE['fraud_amount']     = _bc.get('fraud_amount_btc', '')
        CASE['fraud_amount_eur'] = _bc.get('fraud_amount_eur') or '—'
        CASE['wallet_type']      = f"{_inc.get('wallet_brand','')} ({_inc.get('wallet_type','')})"
        CASE['generated_at']     = _dt.now(_tz.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        if _bc.get('victim_addresses'):
            HOPS[0]['from_addresses'] = [(_a, None) for _a in _bc['victim_addresses']]
        if _bc.get('recipient_address'):
            HOPS[0]['to_addresses'] = [(_bc['recipient_address'], float(_bc.get('fraud_amount_btc') or 0))]
        if _bc.get('fraud_txid'):
            HOPS[0]['txid'] = _bc['fraud_txid']
        print(f"✅ Fallakte: {CASE['case_id']} — {CASE['victim_name']} — {CASE['fraud_amount']} BTC")
    generate_all()
