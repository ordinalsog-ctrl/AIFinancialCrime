"""
AIFinancialCrime — Report Generator v4
=======================================
Erweitert v3 um drei neue Sektionen:

  1. Transaktionsgraph (SVG — direkt in PDF eingebettet)
  2. Temporal-Analyse (Timezone-Inference, Pattern-Tabelle, FATF-Warnung)
  3. Change-Output-Markierung in der Hop-Tabelle (visuell hervorgehoben)

Neue generate_report_v4() Signatur:
    generate_report_v4(
        chain, output_path,
        peeling_result=None,
        victim_name="", victim_contact="",
        language="de",
        serial_matches=None,
        graph_result=None,          ← NEU
        temporal_result=None,       ← NEU
        confidence_summary=None,    ← NEU
    )

Rückwärtskompatibel: generate_report() bleibt unverändert (v3).
"""

from __future__ import annotations

import io
import hashlib
from datetime import datetime, timezone
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak,
    Paragraph, SimpleDocTemplate, Spacer,
    Table, TableStyle, Image,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle, PolyLine
from reportlab.graphics import renderPDF
from reportlab.graphics.shapes import Group

# Import v3 as base
from src.investigation.report_generator import (
    generate_report,
    _build_styles,
    _make_page_template,
    _section_cover,
    _section_methodology,
    _section_chain_of_custody,
    _section_exchange_summary,
    _section_serial_actor,
    _section_peeling_chain,
    _section_recommended_actions,
    _section_integrity,
    _compute_hash,
    COLOR_DARK, COLOR_PRIMARY, COLOR_ACCENT,
    COLOR_ALERT, COLOR_WARNING, COLOR_SUCCESS,
    COLOR_LIGHT_GREY, COLOR_MID_GREY, COLOR_BORDER,
    COLOR_WHITE, CONFIDENCE_COLORS,
    MARGIN, PAGE_W,
)

from src.core.logging_config import get_logger
from src.core.metrics import metrics

logger = get_logger("aifc.report_v4")

# ---------------------------------------------------------------------------
# Additional colors for v4
# ---------------------------------------------------------------------------
COLOR_GRAPH_NODE    = colors.HexColor("#1A3A5C")
COLOR_GRAPH_EDGE    = colors.HexColor("#4A90D9")
COLOR_GRAPH_EXCHANGE = colors.HexColor("#1E8449")
COLOR_GRAPH_LAYERING = colors.HexColor("#C0392B")
COLOR_GRAPH_CHANGE  = colors.HexColor("#E67E22")
COLOR_TEMPORAL_BG   = colors.HexColor("#F0F4F8")
COLOR_FATF_WARN     = colors.HexColor("#7D1128")


# ===========================================================================
# SECTION: Transaction Graph (SVG → ReportLab Drawing)
# ===========================================================================

def _build_graph_drawing(graph_result, max_width_mm: float = 160) -> Optional[Drawing]:
    """
    Baut ein ReportLab Drawing aus dem GraphAnalysisResult.
    Zeigt Nodes als Kreise, Edges als Pfeile, Exchanges grün markiert.
    """
    if not graph_result or not graph_result.nodes:
        return None

    nodes = graph_result.nodes
    edges = graph_result.edges

    # Layout: Hierarchisch nach hop_distance (Spalten) + Position (Zeilen)
    # Gruppierung nach hop_distance
    from collections import defaultdict
    by_depth: dict[int, list] = defaultdict(list)
    for addr, node in nodes.items():
        depth = node.hop_distance if node.hop_distance >= 0 else 99
        by_depth[depth].append((addr, node))

    max_depth = max(by_depth.keys()) if by_depth else 0
    max_nodes_per_col = max(len(v) for v in by_depth.values()) if by_depth else 1

    # Canvas-Dimensionen
    W = max_width_mm * mm
    H = min(120 * mm, max(60 * mm, max_nodes_per_col * 18 * mm))
    d = Drawing(W, H)

    # Node-Positionen berechnen
    node_pos: dict[str, tuple[float, float]] = {}
    col_count = max_depth + 1
    col_width = W / max(col_count, 1)

    for depth, node_list in by_depth.items():
        x = depth * col_width + col_width / 2
        n = len(node_list)
        for i, (addr, node) in enumerate(node_list):
            y = H - (i + 1) * H / (n + 1)
            node_pos[addr] = (x, y)

    # Edges zeichnen
    addr_set = set(node_pos.keys())
    for edge in edges[:40]:  # Max 40 Edges für Lesbarkeit
        if edge.from_address not in addr_set or edge.to_address not in addr_set:
            continue
        x1, y1 = node_pos[edge.from_address]
        x2, y2 = node_pos[edge.to_address]
        line = Line(x1, y1, x2, y2,
                    strokeColor=COLOR_GRAPH_EDGE,
                    strokeWidth=0.8,
                    strokeDashArray=None)
        d.add(line)

    # Nodes zeichnen
    for addr, node in nodes.items():
        if addr not in node_pos:
            continue
        x, y = node_pos[addr]
        r = 5

        # Farbe nach Typ
        from src.investigation.graph_engine import NodeType
        if node.node_type == NodeType.VICTIM:
            fill = COLOR_ALERT
            r = 7
        elif node.node_type == NodeType.EXCHANGE:
            fill = COLOR_GRAPH_EXCHANGE
            r = 7
        elif node.node_type in (NodeType.DISTRIBUTION,):
            fill = COLOR_GRAPH_LAYERING
        elif node.node_type == NodeType.CHANGE:
            fill = COLOR_GRAPH_CHANGE
        elif node.node_type == NodeType.HOLDING:
            fill = COLOR_MID_GREY
        else:
            fill = COLOR_GRAPH_NODE

        circle = Circle(x, y, r, fillColor=fill, strokeColor=COLOR_WHITE, strokeWidth=0.5)
        d.add(circle)

        # Label (kurze Adresse)
        short = addr[:6] + "…" if len(addr) > 8 else addr
        label_y = y - r - 7
        lbl = String(x, label_y, short,
                     fontSize=4.5, fillColor=COLOR_DARK,
                     textAnchor="middle")
        d.add(lbl)

        # Attribution Label
        if node.attribution_label:
            attr_short = node.attribution_label[:10]
            attr_lbl = String(x, label_y - 6, attr_short,
                              fontSize=4, fillColor=COLOR_GRAPH_EXCHANGE,
                              textAnchor="middle")
            d.add(attr_lbl)

    return d


def _section_graph(graph_result, styles: dict) -> list:
    """PDF-Sektion: Transaktionsgraph."""
    if not graph_result:
        return []

    story = [
        Paragraph("4. Transaktionsgraph", styles["h1"]),
        HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER),
        Spacer(1, 4),
        Paragraph(
            "Der folgende Graph zeigt den gerichteten Transaktionspfad der Fraud-Mittel. "
            "Jeder Knoten repräsentiert eine Bitcoin-Adresse, jede Kante eine Transaktion. "
            "Rote Knoten = Opfer-Adresse, grüne Knoten = identifizierte Exchange.",
            styles["body"]
        ),
        Spacer(1, 6),
    ]

    # Graph-Zeichnung
    drawing = _build_graph_drawing(graph_result)
    if drawing:
        story.append(drawing)
        story.append(Spacer(1, 4))

    # Pattern-Tabelle
    if graph_result.patterns:
        story.append(Paragraph("Erkannte Muster:", styles["body_bold"]))
        story.append(Spacer(1, 3))

        PATTERN_LABELS = {
            "fan_out":     "Fan-out (Verteilung)",
            "fan_in":      "Konsolidierung",
            "layering":    "Layering (Verschleierung)",
            "convergence": "Re-Konvergenz",
            "dead_end":    "Unausgegebene UTXOs",
        }
        SEVERITY_COLORS = {
            "high":   COLOR_ALERT,
            "medium": COLOR_WARNING,
            "low":    COLOR_SUCCESS,
            "info":   COLOR_MID_GREY,
        }

        rows = [["Muster", "Schwere", "BTC", "Beschreibung"]]
        for p in graph_result.patterns[:10]:
            sev_color = SEVERITY_COLORS.get(p.severity, COLOR_DARK)
            rows.append([
                Paragraph(PATTERN_LABELS.get(p.pattern, p.pattern), styles["body_bold"]),
                Paragraph(
                    f"<font color='#{sev_color.hexval()[2:]}'>{p.severity.upper()}</font>",
                    styles["body"]
                ),
                f"{p.btc_involved:.6f}",
                Paragraph(p.description[:120], styles["small"]),
            ])

        tbl = Table(rows, colWidths=[32*mm, 18*mm, 24*mm, PAGE_W - 2*MARGIN - 74*mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), COLOR_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_GREY]),
            ("GRID",          (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 4))

    # Dead-end Adressen
    if graph_result.dead_end_addresses:
        story.append(Paragraph(
            f"Unausgegebene UTXOs ({len(graph_result.dead_end_addresses)} Adresse(n) — "
            f"mögliche Halte-Wallets oder unzugängliche Gelder):",
            styles["body"]
        ))
        for addr in graph_result.dead_end_addresses[:5]:
            story.append(Paragraph(
                f"• <font name='Courier'>{addr}</font>",
                styles["mono_small"]
            ))
        if len(graph_result.dead_end_addresses) > 5:
            story.append(Paragraph(
                f"… und {len(graph_result.dead_end_addresses) - 5} weitere.",
                styles["small"]
            ))

    story.append(Spacer(1, 8))
    return story


# ===========================================================================
# SECTION: Temporal Analysis
# ===========================================================================

def _section_temporal(temporal_result, styles: dict) -> list:
    """PDF-Sektion: Temporal-Analyse."""
    if not temporal_result or not temporal_result.hops:
        return []

    story = [
        Paragraph("5. Temporal-Analyse", styles["h1"]),
        HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER),
        Spacer(1, 4),
    ]

    # Übersichts-Box
    duration_h = temporal_result.total_duration_hours
    avg_min = temporal_result.avg_hop_interval_minutes
    biz_pct = temporal_result.business_hours_ratio * 100
    wknd_pct = temporal_result.weekend_ratio * 100

    overview_rows = [
        ["Gesamtdauer", f"{duration_h:.1f} Stunden"],
        ["Ø Hop-Intervall", f"{avg_min:.1f} Minuten"],
        ["Aktivität Geschäftszeiten", f"{biz_pct:.0f}%"],
        ["Wochenend-Aktivität", f"{wknd_pct:.0f}%"],
        ["Kürzestes Intervall", f"{temporal_result.min_hop_interval_seconds:.0f} Sekunden"],
        ["Längstes Intervall", f"{temporal_result.max_hop_interval_seconds / 3600:.1f} Stunden"],
    ]

    ov_tbl = Table(overview_rows, colWidths=[55*mm, 80*mm])
    ov_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), COLOR_TEMPORAL_BG),
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.3, COLOR_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(ov_tbl)
    story.append(Spacer(1, 6))

    # Timezone-Schätzung
    tz = temporal_result.timezone_estimate
    if tz and tz.confidence >= 0.35:
        tz_box_style = TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1),
             COLOR_LIGHT_GREY if tz.confidence < 0.6 else colors.HexColor("#D5F5E3")),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("LEFTPADDING",(0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BOX", (0, 0), (-1, -1), 1, COLOR_SUCCESS),
        ])
        tz_text = (
            f"<b>Geschätzte Täter-Zeitzone:</b> {tz.region} (UTC{tz.utc_offset_hours:+d}) — "
            f"Konfidenz: {tz.confidence:.0%}<br/>"
            f"<i>Basis: {tz.evidence}</i>"
        )
        tz_tbl = Table([[Paragraph(tz_text, styles["body"])]], colWidths=[PAGE_W - 2*MARGIN])
        tz_tbl.setStyle(tz_box_style)
        story.append(tz_tbl)
        story.append(Spacer(1, 6))

    # Pattern-Tabelle
    if temporal_result.patterns:
        story.append(Paragraph("Erkannte Zeitstempel-Muster:", styles["body_bold"]))
        story.append(Spacer(1, 3))

        PATTERN_LABELS_T = {
            "rapid_succession":             "Schnelle Folge",
            "deliberate_delay":             "Deliberate Verzögerung",
            "business_hours_clustering":    "Geschäftszeiten-Clustering",
            "night_activity":               "Nächtliche Aktivität",
            "acceleration":                 "Beschleunigung",
            "deceleration":                 "Verlangsamung",
            "regulatory_window_avoidance":  "FATF-Fenster-Umgehung",
        }

        rows = [["Muster", "Schwere", "Conf.Δ", "Beschreibung"]]
        has_fatf = False

        for p in temporal_result.patterns:
            if p.pattern == "regulatory_window_avoidance":
                has_fatf = True
            sev_color = {
                "high":   COLOR_ALERT,
                "medium": COLOR_WARNING,
                "low":    COLOR_SUCCESS,
                "info":   COLOR_MID_GREY,
            }.get(p.severity, COLOR_DARK)

            delta_str = f"{p.confidence_delta:+.2f}"
            rows.append([
                Paragraph(PATTERN_LABELS_T.get(p.pattern, p.pattern), styles["body_bold"]),
                Paragraph(p.severity.upper(), ParagraphStyle(
                    "sev", fontSize=7.5, textColor=sev_color, fontName="Helvetica-Bold"
                )),
                delta_str,
                Paragraph(p.description[:130], styles["small"]),
            ])

        tbl = Table(rows, colWidths=[38*mm, 18*mm, 14*mm, PAGE_W - 2*MARGIN - 70*mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), COLOR_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [COLOR_WHITE, COLOR_LIGHT_GREY]),
            ("GRID",          (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 4))

        # FATF-Warnbox
        if has_fatf:
            fatf_style = TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FDEDEE")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING",  (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("BOX", (0, 0), (-1, -1), 1.5, COLOR_FATF_WARN),
            ])
            fatf_text = (
                "<b>⚠ FATF-Monitoring-Fenster-Umgehung erkannt</b><br/>"
                "Mehrere Transaktionsintervalle liegen gezielt knapp über 24 Stunden. "
                "Dies entspricht einem bekannten Muster zur Umgehung der FATF Travel Rule "
                "Monitoring-Fenster. Dieses Muster ist forensisch relevant und sollte in "
                "der Strafanzeige explizit erwähnt werden."
            )
            fatf_tbl = Table(
                [[Paragraph(fatf_text, ParagraphStyle(
                    "fatf", fontSize=8, fontName="Helvetica",
                    textColor=COLOR_FATF_WARN, leading=12
                ))]],
                colWidths=[PAGE_W - 2*MARGIN]
            )
            fatf_tbl.setStyle(fatf_style)
            story.append(fatf_tbl)
            story.append(Spacer(1, 4))

    story.append(Spacer(1, 8))
    return story


# ===========================================================================
# SECTION: Confidence Summary (v4 neu)
# ===========================================================================

def _section_confidence_summary(confidence_summary, styles: dict) -> list:
    """PDF-Sektion: Aggregierte Confidence-Aussage."""
    if not confidence_summary:
        return []

    story = [
        Paragraph("6. Forensische Bewertung", styles["h1"]),
        HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER),
        Spacer(1, 4),
    ]

    # Court-Readiness Badge
    cr = confidence_summary.court_readiness
    cr_color = {
        "high":   COLOR_SUCCESS,
        "medium": COLOR_WARNING,
        "low":    COLOR_ALERT,
    }.get(cr, COLOR_MID_GREY)
    cr_label = {
        "high":   "HOHE GERICHTSVERWERTBARKEIT",
        "medium": "MITTLERE GERICHTSVERWERTBARKEIT",
        "low":    "EINGESCHRÄNKTE GERICHTSVERWERTBARKEIT",
    }.get(cr, "UNBEKANNT")

    badge_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), cr_color),
        ("TEXTCOLOR",  (0, 0), (-1, -1), COLOR_WHITE),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME",   (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ])
    badge = Table([[cr_label]], colWidths=[PAGE_W - 2*MARGIN])
    badge.setStyle(badge_style)
    story.append(badge)
    story.append(Spacer(1, 6))

    # Hop-Distribution
    dist = confidence_summary.hop_distribution
    total = sum(dist.values())
    if total > 0:
        dist_rows = [
            ["Confidence", "Anzahl Hops", "Anteil", "Bedeutung"],
            ["L1 — Mathematisch bewiesen", str(dist.get("L1", 0)),
             f"{dist.get('L1', 0)/total:.0%}", "Gerichtsverwertbar"],
            ["L2 — Forensisch belegt",     str(dist.get("L2", 0)),
             f"{dist.get('L2', 0)/total:.0%}", "Ermittlungsrelevant"],
            ["L3 — Hinweis",               str(dist.get("L3", 0)),
             f"{dist.get('L3', 0)/total:.0%}", "Nicht beweiskräftig"],
            ["L4 — Spekulativ",            str(dist.get("L4", 0)),
             f"{dist.get('L4', 0)/total:.0%}", "Nicht im Report"],
        ]
        conf_tbl = Table(dist_rows, colWidths=[55*mm, 22*mm, 20*mm, 60*mm])
        conf_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), COLOR_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0), COLOR_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND",    (0, 1), (-1, 1), colors.HexColor("#D5F5E3")),
            ("BACKGROUND",    (0, 2), (-1, 2), colors.HexColor("#D6EAF8")),
            ("BACKGROUND",    (0, 3), (-1, 3), colors.HexColor("#FDEBD0")),
            ("BACKGROUND",    (0, 4), (-1, 4), colors.HexColor("#FADBD8")),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("GRID",          (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        story.append(conf_tbl)
        story.append(Spacer(1, 6))

    # Notizen
    if confidence_summary.notes:
        for note in confidence_summary.notes:
            story.append(Paragraph(f"• {note}", styles["body"]))
        story.append(Spacer(1, 4))

    # Temporal adjustment
    if confidence_summary.temporal_adjustment != 0:
        sign = "+" if confidence_summary.temporal_adjustment > 0 else ""
        story.append(Paragraph(
            f"Temporal-Anpassung: {sign}{confidence_summary.temporal_adjustment:.2f} "
            f"(basierend auf Zeitstempel-Mustern)",
            styles["small"]
        ))

    story.append(Spacer(1, 8))
    return story


# ===========================================================================
# Main: generate_report_v4
# ===========================================================================

def generate_report_v4(
    chain,
    output_path: str,
    peeling_result=None,
    victim_name: str = "",
    victim_contact: str = "",
    language: str = "de",
    serial_matches: Optional[list] = None,
    graph_result=None,
    temporal_result=None,
    confidence_summary=None,
) -> str:
    """
    Generiert einen court-ready forensischen PDF-Report (v4).

    Neue Parameter gegenüber v3:
        graph_result:       GraphAnalysisResult aus graph_engine.py
        temporal_result:    TemporalAnalysisResult aus temporal_engine.py
        confidence_summary: ConfidenceSummary aus pipeline_v3.py

    Returns:
        SHA-256 Hash des Report-Inhalts (für Integritätsverifikation)
    """
    t0 = __import__("time").monotonic()

    report_hash  = _compute_hash(chain)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    styles       = _build_styles()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=18*mm,
        bottomMargin=16*mm,
        title=f"Forensischer Blockchain-Analysebericht — {chain.case_id}",
        author="AIFinancialCrime Forensik-System v4",
        subject=f"Bitcoin Fraud Investigation — {chain.fraud_address[:20]}...",
        creator="AIFinancialCrime v4.0",
    )

    on_page = _make_page_template(chain.case_id, generated_at)

    story = []

    # --- Basis-Sektionen (v3) ---
    story += _section_cover(chain, styles, generated_at,
                             victim_name=victim_name,
                             victim_contact=victim_contact,
                             language=language)
    story.append(PageBreak())
    story += _section_methodology(styles)
    story.append(Spacer(1, 10))
    story += _section_chain_of_custody(chain, styles)
    story += _section_exchange_summary(chain, styles)

    if serial_matches:
        story += _section_serial_actor(serial_matches, styles)
    if peeling_result and getattr(peeling_result, "detected", False):
        story += _section_peeling_chain(peeling_result, styles)

    # --- Neue Sektionen (v4) ---
    if graph_result:
        story.append(PageBreak())
        story += _section_graph(graph_result, styles)

    if temporal_result and temporal_result.hops:
        story += _section_temporal(temporal_result, styles)

    if confidence_summary:
        story += _section_confidence_summary(confidence_summary, styles)

    # --- Abschluss-Sektionen (v3) ---
    story += _section_recommended_actions(chain, styles, language=language)
    story.append(Spacer(1, 10))
    story += _section_integrity(report_hash, generated_at, styles)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

    with open(output_path, "wb") as f:
        f.write(buf.getvalue())

    duration = __import__("time").monotonic() - t0
    metrics.report_generated(language=language, duration_s=duration)
    logger.info("report_v4_generated",
                output=output_path,
                has_graph=graph_result is not None,
                has_temporal=temporal_result is not None,
                has_confidence=confidence_summary is not None,
                duration_s=round(duration, 1))

    return report_hash
