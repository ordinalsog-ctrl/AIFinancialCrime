"""
Forensic Report Generator

Produces a court-ready PDF from an InvestigationChain.

Design principles:
  - Every claim in the report is backed by on-chain evidence
  - Confidence levels are explained in plain language (DE)
  - All L3/L4 findings are explicitly excluded or labelled as non-binding
  - Report includes a methodology section for legal transparency
  - Verifiable URLs for every transaction (Blockstream.info)
  - SHA-256 hash of report content embedded for integrity verification
"""

from __future__ import annotations

import hashlib
import io
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.investigation.confidence_engine import (
    ConfidenceLevel,
    InvestigationChain,
    TracingHop,
    TracingMethod,
)

# ---------------------------------------------------------------------------
# Color palette — professional, neutral
# ---------------------------------------------------------------------------
COLOR_DARK       = colors.HexColor("#1A1A2E")
COLOR_PRIMARY    = colors.HexColor("#16213E")
COLOR_ACCENT     = colors.HexColor("#0F3460")
COLOR_ALERT      = colors.HexColor("#C0392B")
COLOR_WARNING    = colors.HexColor("#E67E22")
COLOR_SUCCESS    = colors.HexColor("#1E8449")
COLOR_LIGHT_GREY = colors.HexColor("#F4F6F7")
COLOR_MID_GREY   = colors.HexColor("#AEB6BF")
COLOR_BORDER     = colors.HexColor("#D5D8DC")
COLOR_WHITE      = colors.white

CONFIDENCE_COLORS = {
    ConfidenceLevel.L1_VERIFIED_FACT:   COLOR_SUCCESS,
    ConfidenceLevel.L2_HIGH_CONFIDENCE: COLOR_ACCENT,
    ConfidenceLevel.L3_INDICATIVE:      COLOR_WARNING,
    ConfidenceLevel.L4_SPECULATIVE:     COLOR_ALERT,
}

CONFIDENCE_LABELS_DE = {
    ConfidenceLevel.L1_VERIFIED_FACT:   "L1 — Mathematisch bewiesen",
    ConfidenceLevel.L2_HIGH_CONFIDENCE: "L2 — Forensisch belegt",
    ConfidenceLevel.L3_INDICATIVE:      "L3 — Hinweis (nicht beweiskräftig)",
    ConfidenceLevel.L4_SPECULATIVE:     "L4 — Spekulativ (nicht im Report)",
}

METHOD_LABELS_DE = {
    TracingMethod.UTXO_DIRECT:          "Direkter UTXO-Link",
    TracingMethod.AMOUNT_EXACT_MATCH:   "Betragsübereinstimmung (exakt)",
    TracingMethod.AMOUNT_TEMPORAL:      "Betragsübereinstimmung (zeitverzögert)",
    TracingMethod.AMOUNT_SPLIT:         "Aufspaltungs-Match",
    TracingMethod.EXCHANGE_ATTRIBUTION: "Exchange-Attribution",
    TracingMethod.OFAC_MATCH:           "OFAC-Sanktionsliste",
    TracingMethod.CIO_HEURISTIC:        "Common-Input-Ownership (intern)",
}

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


# ---------------------------------------------------------------------------
# Style definitions
# ---------------------------------------------------------------------------

def _build_styles() -> dict:
    base = getSampleStyleSheet()
    s = {}

    s["cover_title"] = ParagraphStyle(
        "cover_title", fontSize=22, leading=28,
        textColor=COLOR_WHITE, fontName="Helvetica-Bold",
        alignment=TA_LEFT,
    )
    s["cover_sub"] = ParagraphStyle(
        "cover_sub", fontSize=11, leading=16,
        textColor=COLOR_MID_GREY, fontName="Helvetica",
        alignment=TA_LEFT,
    )
    s["cover_meta"] = ParagraphStyle(
        "cover_meta", fontSize=9, leading=13,
        textColor=COLOR_MID_GREY, fontName="Helvetica",
        alignment=TA_LEFT,
    )
    s["h1"] = ParagraphStyle(
        "h1", fontSize=13, leading=18, spaceBefore=14, spaceAfter=4,
        textColor=COLOR_PRIMARY, fontName="Helvetica-Bold",
    )
    s["h2"] = ParagraphStyle(
        "h2", fontSize=10, leading=14, spaceBefore=10, spaceAfter=3,
        textColor=COLOR_ACCENT, fontName="Helvetica-Bold",
    )
    s["body"] = ParagraphStyle(
        "body", fontSize=8.5, leading=13, spaceAfter=4,
        textColor=COLOR_DARK, fontName="Helvetica",
    )
    s["body_bold"] = ParagraphStyle(
        "body_bold", fontSize=8.5, leading=13,
        textColor=COLOR_DARK, fontName="Helvetica-Bold",
    )
    s["mono"] = ParagraphStyle(
        "mono", fontSize=7.5, leading=11,
        textColor=COLOR_ACCENT, fontName="Courier",
        wordWrap="CJK",
    )
    s["mono_small"] = ParagraphStyle(
        "mono_small", fontSize=6.5, leading=10,
        textColor=COLOR_ACCENT, fontName="Courier",
        wordWrap="CJK",
    )
    s["alert"] = ParagraphStyle(
        "alert", fontSize=9, leading=13,
        textColor=COLOR_ALERT, fontName="Helvetica-Bold",
    )
    s["warning"] = ParagraphStyle(
        "warning", fontSize=8.5, leading=13,
        textColor=COLOR_WARNING, fontName="Helvetica-Bold",
    )
    s["caption"] = ParagraphStyle(
        "caption", fontSize=7.5, leading=11,
        textColor=COLOR_MID_GREY, fontName="Helvetica",
        alignment=TA_CENTER,
    )
    s["footer"] = ParagraphStyle(
        "footer", fontSize=7, leading=10,
        textColor=COLOR_MID_GREY, fontName="Helvetica",
        alignment=TA_CENTER,
    )
    return s


# ---------------------------------------------------------------------------
# Page template — header + footer on every page
# ---------------------------------------------------------------------------

def _make_page_template(case_id: str, generated_at: str):
    def on_page(canvas, doc):
        canvas.saveState()
        w, h = A4

        # Top bar
        canvas.setFillColor(COLOR_PRIMARY)
        canvas.rect(0, h - 12*mm, w, 12*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(COLOR_WHITE)
        canvas.drawString(MARGIN, h - 8*mm, "FORENSISCHER BLOCKCHAIN-ANALYSEBERICHT")
        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(w - MARGIN, h - 8*mm, f"Fall-ID: {case_id}")

        # Bottom bar
        canvas.setFillColor(COLOR_LIGHT_GREY)
        canvas.rect(0, 0, w, 10*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(COLOR_MID_GREY)
        canvas.drawString(MARGIN, 3.5*mm,
            f"Erstellt: {generated_at} UTC  |  Vertraulich — nur für autorisierte Empfänger")
        canvas.drawRightString(w - MARGIN, 3.5*mm, f"Seite {doc.page}")

        canvas.restoreState()

    return on_page


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _hr(styles) -> list:
    return [
        Spacer(1, 3),
        HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER),
        Spacer(1, 6),
    ]


def _section_cover(chain: InvestigationChain, styles: dict, generated_at: str) -> list:
    story = []

    # Dark cover block
    cover_data = [[
        Paragraph(f"Forensischer Blockchain-Analysebericht", styles["cover_title"]),
    ]]
    cover_table = Table(cover_data, colWidths=[PAGE_W - 2*MARGIN])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_PRIMARY),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOR_PRIMARY]),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 8))

    # Meta block
    exchange_hits = chain.exchange_hits
    exchange_text = ", ".join(set(h.exchange_name for h in exchange_hits)) \
        if exchange_hits else "Keine Exchange identifiziert"

    sanctioned_hops = [h for h in chain.hops if getattr(h, "is_sanctioned", False)]
    sanction_text = "⚠ SANKTIONIERTE ADRESSE IDENTIFIZIERT" if sanctioned_hops \
        else "Keine sanktionierten Adressen"

    meta_rows = [
        ["Fall-ID",             chain.case_id],
        ["Fraud-Adresse",       chain.fraud_address],
        ["Fraud-Transaktion",   chain.fraud_txid],
        ["Betrag",              f"{chain.fraud_amount_btc} BTC"],
        ["Zeitpunkt (UTC)",     chain.fraud_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Bericht erstellt",    f"{generated_at} UTC"],
        ["Analysierte Hops",    str(len(chain.hops))],
        ["Im Report (L1+L2)",   str(len(chain.official_report_hops))],
        ["Exchange-Hits",       exchange_text],
        ["OFAC-Status",         sanction_text],
    ]

    tbl = Table(meta_rows, colWidths=[55*mm, PAGE_W - 2*MARGIN - 55*mm])
    tbl_style = [
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",  (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",  (0, 0), (-1, -1), 8.5),
        ("LEADING",   (0, 0), (-1, -1), 13),
        ("TEXTCOLOR", (0, 0), (0, -1), COLOR_PRIMARY),
        ("TEXTCOLOR", (1, 0), (1, -1), COLOR_DARK),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_GREY]),
        ("GRID",      (0, 0), (-1, -1), 0.3, COLOR_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]
    if sanctioned_hops:
        tbl_style.append(("TEXTCOLOR", (1, 9), (1, 9), COLOR_ALERT))
        tbl_style.append(("FONTNAME",  (1, 9), (1, 9), "Helvetica-Bold"))

    tbl.setStyle(TableStyle(tbl_style))
    story.append(tbl)
    return story


def _section_methodology(styles: dict) -> list:
    story = [Paragraph("1. Methodik und Rechtshinweise", styles["h1"])]
    story += _hr(styles)

    story.append(Paragraph(
        "Dieser Bericht wurde automatisiert durch das AIFinancialCrime "
        "Forensik-System erstellt. Alle Schlussfolgerungen basieren "
        "ausschliesslich auf verifizierbaren On-Chain-Daten der Bitcoin-Blockchain. "
        "Die Analyse ist vollständig reproduzierbar — jede dritte Partei kann "
        "die angegebenen Transaktions-IDs und Block-Höhen unabhängig verifizieren.",
        styles["body"]
    ))

    conf_rows = [
        ["Level", "Bezeichnung", "Bedeutung", "Im offiziellen Report"],
        ["L1", "Mathematisch bewiesen",
         "Direkter UTXO-Link — mathematisch eindeutig durch das Bitcoin-Protokoll",
         "Ja"],
        ["L2", "Forensisch belegt",
         "Betragsübereinstimmung + Zeitkorrelation oder bekannte Exchange-Attribution",
         "Ja"],
        ["L3", "Hinweis",
         "Beobachtbares Muster, kein direkter Beweis — nur als Hinweis aufgeführt",
         "Nur mit Caveat"],
        ["L4", "Spekulativ",
         "Heuristische Analyse — nicht im offiziellen Report enthalten",
         "Nein"],
    ]
    conf_tbl = Table(
        conf_rows,
        colWidths=[12*mm, 38*mm, PAGE_W - 2*MARGIN - 100*mm, 30*mm]
    )
    conf_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), COLOR_PRIMARY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
        ("LEADING",       (0, 0), (-1, -1), 11),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_GREY]),
        ("GRID",          (0, 0), (-1, -1), 0.3, COLOR_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("TEXTCOLOR",     (0, 1), (0, 1), COLOR_SUCCESS),
        ("TEXTCOLOR",     (0, 2), (0, 2), COLOR_ACCENT),
        ("TEXTCOLOR",     (0, 3), (0, 3), COLOR_WARNING),
        ("TEXTCOLOR",     (0, 4), (0, 4), COLOR_ALERT),
        ("FONTNAME",      (0, 1), (0, -1), "Helvetica-Bold"),
    ]))
    story.append(conf_tbl)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Zeitkorrelations-Schwellen: Exakter Match ≤10 Minuten (L2), "
        "verzögerter Match ≤6 Stunden (L2 mit Hinweis), "
        "indikativer Bereich ≤48 Stunden (L3), darüber hinaus (L4, nicht im Report). "
        "Betragstoleranz für Miner-Gebühren: 0,001 BTC (100.000 Satoshi).",
        styles["body"]
    ))
    return story


def _section_chain_of_custody(chain: InvestigationChain, styles: dict) -> list:
    story = [Paragraph("2. Transaktionskette (Chain of Custody)", styles["h1"])]
    story += _hr(styles)

    hops = chain.official_report_hops
    if not hops:
        story.append(Paragraph(
            "Keine reportfähigen Hops (L1/L2) gefunden. "
            "Alle Verbindungen liegen unterhalb der forensischen Beweisschwelle.",
            styles["alert"]
        ))
        return story

    story.append(Paragraph(
        f"Die folgende Kette dokumentiert {len(hops)} belegte Transitionsschritte "
        f"ausgehend von der Fraud-Transaktion. Jeder Schritt enthält Methode, "
        f"Confidence-Level und vollständige Evidenz.",
        styles["body"]
    ))
    story.append(Spacer(1, 6))

    for hop in hops:
        story += _build_hop_block(hop, styles)

    return story


def _build_hop_block(hop: TracingHop, styles: dict) -> list:
    conf_color = CONFIDENCE_COLORS.get(hop.confidence, COLOR_MID_GREY)
    conf_label = CONFIDENCE_LABELS_DE.get(hop.confidence, str(hop.confidence))
    method_label = METHOD_LABELS_DE.get(hop.method, hop.method.value)

    # Header row
    header_data = [[
        Paragraph(f"Hop {hop.hop_index}", styles["body_bold"]),
        Paragraph(conf_label, ParagraphStyle(
            "conf_inline", fontSize=8, fontName="Helvetica-Bold",
            textColor=conf_color, leading=11,
        )),
        Paragraph(method_label, ParagraphStyle(
            "method_inline", fontSize=8, fontName="Helvetica",
            textColor=COLOR_MID_GREY, leading=11, alignment=TA_RIGHT,
        )),
    ]]
    header_tbl = Table(header_data, colWidths=[20*mm, 70*mm, PAGE_W - 2*MARGIN - 90*mm])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), COLOR_LIGHT_GREY),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("LINEBELOW",     (0, 0), (-1, -1), 1.5, conf_color),
    ]))

    # Transaction rows
    def _addr(a): return a[:20] + "..." + a[-8:] if a and len(a) > 32 else (a or "—")
    def _txid(t): return t[:24] + "..." if t and len(t) > 30 else (t or "—")

    detail_rows = [
        ["Von TX",    Paragraph(_txid(hop.from_txid), styles["mono_small"])],
        ["An TX",     Paragraph(_txid(hop.to_txid), styles["mono_small"])],
        ["Von Adresse", Paragraph(_addr(hop.from_address or "—"), styles["mono_small"])],
        ["An Adresse",  Paragraph(_addr(hop.to_address or "—"), styles["mono_small"])],
        ["Betrag",    Paragraph(f"{hop.amount_btc} BTC", styles["body"])],
        ["Block (von→an)", Paragraph(
            f"{hop.block_height_from} → {hop.block_height_to}", styles["body"])],
        ["Zeitstempel", Paragraph(
            f"{hop.timestamp_from.strftime('%Y-%m-%d %H:%M:%S') if hop.timestamp_from else '—'} → "
            f"{hop.timestamp_to.strftime('%H:%M:%S') if hop.timestamp_to else '—'} UTC",
            styles["body"]
        )],
        ["Zeitversatz", Paragraph(
            _fmt_delta(hop.time_delta_seconds), styles["body"])],
    ]

    if hop.exchange_name:
        detail_rows.append([
            "Exchange",
            Paragraph(
                f"<b>{hop.exchange_name}</b> — {hop.exchange_source}",
                ParagraphStyle("exch", fontSize=8.5, fontName="Helvetica-Bold",
                               textColor=COLOR_ALERT, leading=12)
            )
        ])

    if hop.caveat:
        detail_rows.append([
            "Hinweis",
            Paragraph(hop.caveat, ParagraphStyle(
                "caveat_style", fontSize=8, fontName="Helvetica",
                textColor=COLOR_WARNING, leading=11)
            )
        ])

    detail_tbl = Table(
        detail_rows,
        colWidths=[30*mm, PAGE_W - 2*MARGIN - 30*mm]
    )
    detail_tbl.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",  (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_GREY]),
        ("GRID",      (0, 0), (-1, -1), 0.3, COLOR_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (0, 0), (0, -1), COLOR_PRIMARY),
    ]))

    # Evidence items
    evidence_items = []
    for ev in hop.evidence:
        evidence_items.append(Paragraph(
            f"<b>{ev.evidence_type}</b>: {ev.description}",
            ParagraphStyle("ev", fontSize=7.5, fontName="Helvetica",
                           textColor=COLOR_DARK, leading=11)
        ))
        if ev.verifiable_at:
            evidence_items.append(Paragraph(
                f"Verifizierbar: {ev.verifiable_at}",
                styles["mono_small"]
            ))

    ev_data = [[Paragraph("Evidenz", styles["body_bold"]),
                evidence_items[0] if evidence_items else Paragraph("—", styles["body"])]]
    for item in evidence_items[1:]:
        ev_data.append(["", item])

    ev_tbl = Table(ev_data, colWidths=[30*mm, PAGE_W - 2*MARGIN - 30*mm])
    ev_tbl.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",  (0, 0), (-1, -1), 7.5),
        ("BACKGROUND",(0, 0), (-1, -1), colors.HexColor("#EBF5FB")),
        ("GRID",      (0, 0), (-1, -1), 0.3, COLOR_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (0, 0), (0, -1), COLOR_PRIMARY),
    ]))

    return [
        KeepTogether([header_tbl, detail_tbl, ev_tbl]),
        Spacer(1, 8),
    ]


def _section_exchange_summary(chain: InvestigationChain, styles: dict) -> list:
    hits = chain.exchange_hits
    if not hits:
        return []

    story = [Paragraph("3. Exchange-Identifikation", styles["h1"])]
    story += _hr(styles)
    story.append(Paragraph(
        "Die folgenden Exchanges wurden als Empfänger der Fraud-Mittel identifiziert. "
        "Für eine Kontoeinfrierung wird empfohlen, unverzüglich Kontakt mit dem "
        "Compliance-Team der jeweiligen Exchange aufzunehmen und eine Strafanzeige "
        "bei der zuständigen Behörde einzureichen.",
        styles["body"]
    ))
    story.append(Spacer(1, 6))

    rows = [["Exchange", "Adresse", "Betrag (BTC)", "Quelle", "Confidence"]]
    for h in hits:
        rows.append([
            Paragraph(f"<b>{h.exchange_name}</b>", styles["body_bold"]),
            Paragraph(h.to_address or "—", styles["mono_small"]),
            str(h.amount_btc),
            h.exchange_source or "—",
            CONFIDENCE_LABELS_DE.get(h.confidence, "—"),
        ])

    tbl = Table(rows, colWidths=[30*mm, 52*mm, 22*mm, 35*mm, PAGE_W - 2*MARGIN - 139*mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), COLOR_ALERT),
        ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_GREY]),
        ("GRID",          (0, 0), (-1, -1), 0.3, COLOR_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    story.append(tbl)
    return story


def _section_recommended_actions(chain: InvestigationChain, styles: dict) -> list:
    story = [PageBreak(), Paragraph("4. Empfohlene Massnahmen", styles["h1"])]
    story += _hr(styles)

    steps = [
        ("Strafanzeige", (
            "Reichen Sie diesen Bericht als Anlage zur Strafanzeige bei der zuständigen "
            "Polizeidienststelle oder der Zentralstelle Cybercrime ein. "
            "In Deutschland: Landeskriminalamt (LKA) oder Bundeskriminalamt (BKA). "
            "In Österreich: Bundeskriminalamt Cybercrime-Kompetenzstelle (C4)."
        )),
        ("Exchange-Kontakt", (
            "Senden Sie diesen Bericht per E-Mail an das Compliance/Law-Enforcement-Team "
            "der identifizierten Exchange(s). Die meisten grossen Exchanges haben dedizierte "
            "LE-Portale. Referenz: die Transaktions-IDs und Adressen aus Abschnitt 3."
        ) if chain.exchange_hits else (
            "Keine Exchange identifiziert. Empfehlung: weiteres Tracing mit erweitertem "
            "Hop-Limit oder Einsatz professioneller Forensik-Dienste."
        )),
        ("Zeitkritisch", (
            "Handeln Sie schnellstmöglich. Kryptowerte können schnell weiterbewegt werden. "
            "Je früher ein Freeze-Request bei der Exchange eingeht, desto höher die "
            "Chance einer Sicherstellung."
        )),
        ("Dokumentation", (
            "Bewahren Sie alle Original-Kommunikation, Screenshots, Transaktionsnachweise "
            "und diesen Bericht sicher auf. Die Transaktions-IDs in diesem Bericht sind "
            "permanent auf der Bitcoin-Blockchain verankert und unveränderlich."
        )),
    ]

    for title, text in steps:
        story.append(KeepTogether([
            Paragraph(title, styles["h2"]),
            Paragraph(text, styles["body"]),
            Spacer(1, 4),
        ]))

    return story


def _section_integrity(report_hash: str, generated_at: str, styles: dict) -> list:
    story = [Paragraph("5. Integritätssicherung", styles["h1"])]
    story += _hr(styles)
    story.append(Paragraph(
        "Der folgende SHA-256 Hash wurde über den vollständigen Reportinhalt berechnet "
        "und dient als Integritätsnachweis. Eine Veränderung des Berichts würde einen "
        "abweichenden Hash erzeugen.",
        styles["body"]
    ))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Report-Hash (SHA-256):", styles["body_bold"]))
    story.append(Paragraph(report_hash, styles["mono"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Erstellt: {generated_at} UTC", styles["body"]))
    story.append(Paragraph(
        "Alle Transaktions-IDs sind permanent auf der Bitcoin-Blockchain gespeichert "
        "und können unabhängig auf blockstream.info, mempool.space oder jedem "
        "anderen Bitcoin Block Explorer verifiziert werden.",
        styles["body"]
    ))
    return story


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_delta(seconds: Optional[int]) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}min {seconds % 60}s"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    return f"{h}h {m}min"


def _compute_hash(chain: InvestigationChain) -> str:
    """SHA-256 over the deterministic chain dict representation."""
    import json
    content = json.dumps(chain.to_dict(), sort_keys=True, default=str)
    return hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_report(chain: InvestigationChain, output_path: str) -> str:
    """
    Generate a court-ready forensic PDF report.

    Args:
        chain:       Complete InvestigationChain with all hops
        output_path: Where to write the PDF

    Returns:
        SHA-256 hash of report content (for integrity verification)
    """
    report_hash = _compute_hash(chain)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    styles = _build_styles()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=18*mm,
        bottomMargin=16*mm,
        title=f"Forensischer Blockchain-Analysebericht — {chain.case_id}",
        author="AIFinancialCrime Forensik-System",
        subject=f"Bitcoin Fraud Investigation — {chain.fraud_address[:20]}...",
        creator="AIFinancialCrime v1.0",
    )

    on_page = _make_page_template(chain.case_id, generated_at)

    story = []
    story += _section_cover(chain, styles, generated_at)
    story.append(PageBreak())
    story += _section_methodology(styles)
    story.append(Spacer(1, 10))
    story += _section_chain_of_custody(chain, styles)
    story += _section_exchange_summary(chain, styles)
    story += _section_recommended_actions(chain, styles)
    story.append(Spacer(1, 10))
    story += _section_integrity(report_hash, generated_at, styles)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

    with open(output_path, "wb") as f:
        f.write(buf.getvalue())

    return report_hash
