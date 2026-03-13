"""
Exchange Freeze Request Generator

Generates professional, exchange-specific freeze request letters
from an InvestigationChain. Output: PDF (letterhead format).

Design principles:
  - Only L1/L2 evidence included — no speculation
  - Bilingual: German cover + English body (international compliance teams)
  - Exchange-specific contact routing where known
  - Legal basis cited (EU AML5/6, FATF Recommendation 16)
  - Structured for law enforcement forwarding

Supported exchanges (known LE/compliance contacts):
  Binance, Coinbase, Kraken, Bitfinex, Bitstamp, OKX, Bybit, KuCoin, Huobi, Generic
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak,
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from src.investigation.confidence_engine import InvestigationChain, TracingHop

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
COLOR_DARK      = colors.HexColor("#1A1A2E")
COLOR_PRIMARY   = colors.HexColor("#16213E")
COLOR_ACCENT    = colors.HexColor("#0F3460")
COLOR_ALERT     = colors.HexColor("#C0392B")
COLOR_BORDER    = colors.HexColor("#D5D8DC")
COLOR_LIGHT     = colors.HexColor("#F4F6F7")
COLOR_MID_GREY  = colors.HexColor("#AEB6BF")
PAGE_W, PAGE_H  = A4
MARGIN          = 22 * mm

# ---------------------------------------------------------------------------
# Exchange contact database
# ---------------------------------------------------------------------------

@dataclass
class ExchangeContact:
    name: str
    compliance_email: str
    le_portal: Optional[str]       # law enforcement portal URL
    freeze_sla_hours: int          # typical response SLA
    accepts_pdf: bool = True
    notes: str = ""

EXCHANGE_CONTACTS: dict[str, ExchangeContact] = {
    "Binance": ExchangeContact(
        name="Binance",
        compliance_email="law_enforcement@binance.com",
        le_portal="https://www.binance.com/en/legal/law-enforcement",
        freeze_sla_hours=48,
        notes="Requires case number from law enforcement for account freeze. "
              "Submit via LE portal for fastest response.",
    ),
    "Coinbase": ExchangeContact(
        name="Coinbase",
        compliance_email="investigations@coinbase.com",
        le_portal="https://www.coinbase.com/legal/law_enforcement",
        freeze_sla_hours=72,
        notes="US-based. Responds to official law enforcement requests. "
              "Private parties should file police report first.",
    ),
    "Kraken": ExchangeContact(
        name="Kraken",
        compliance_email="lawenforcement@kraken.com",
        le_portal="https://www.kraken.com/legal/law-enforcement",
        freeze_sla_hours=48,
        notes="Accepts requests from registered law enforcement agencies. "
              "Include jurisdiction and badge/case number.",
    ),
    "Bitfinex": ExchangeContact(
        name="Bitfinex",
        compliance_email="compliance@bitfinex.com",
        le_portal=None,
        freeze_sla_hours=72,
        notes="Submit detailed report with on-chain evidence. "
              "Attach blockchain analysis report.",
    ),
    "Bitstamp": ExchangeContact(
        name="Bitstamp",
        compliance_email="compliance@bitstamp.net",
        le_portal="https://www.bitstamp.net/legal/law-enforcement/",
        freeze_sla_hours=48,
        notes="EU-regulated (Luxembourg). Strong AML5 compliance. "
              "Include IBAN or deposit address.",
    ),
    "OKX": ExchangeContact(
        name="OKX",
        compliance_email="compliance@okx.com",
        le_portal="https://www.okx.com/legal/law-enforcement",
        freeze_sla_hours=72,
        notes="Submit via LE portal. Include deposit address and TX hash.",
    ),
    "Bybit": ExchangeContact(
        name="Bybit",
        compliance_email="compliance@bybit.com",
        le_portal=None,
        freeze_sla_hours=96,
        notes="Submit detailed on-chain evidence. Response within 4 business days.",
    ),
    "KuCoin": ExchangeContact(
        name="KuCoin",
        compliance_email="compliance@kucoin.com",
        le_portal="https://www.kucoin.com/legal/law-enforcement",
        freeze_sla_hours=72,
        notes="Seychelles-based. Include full forensic report.",
    ),
    "Huobi": ExchangeContact(
        name="Huobi",
        compliance_email="compliance@huobi.com",
        le_portal=None,
        freeze_sla_hours=96,
        notes="Submit via email with full documentation package.",
    ),
}

GENERIC_CONTACT = ExchangeContact(
    name="Unknown Exchange",
    compliance_email="compliance@[exchange-domain]",
    le_portal=None,
    freeze_sla_hours=72,
    notes="Contact details unknown. Identify via WHOIS or exchange website.",
)


def get_exchange_contact(exchange_name: str) -> ExchangeContact:
    for key, contact in EXCHANGE_CONTACTS.items():
        if key.lower() in exchange_name.lower():
            return contact
    return GENERIC_CONTACT


# ---------------------------------------------------------------------------
# Victim info dataclass
# ---------------------------------------------------------------------------

@dataclass
class VictimInfo:
    full_name: str
    email: str
    country: str
    phone: Optional[str] = None
    police_report_number: Optional[str] = None
    police_authority: Optional[str] = None
    date_of_fraud: Optional[datetime] = None
    additional_notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def _styles() -> dict:
    s = {}
    s["h1"] = ParagraphStyle("h1", fontSize=12, leading=16, spaceBefore=10, spaceAfter=4,
                              textColor=COLOR_PRIMARY, fontName="Helvetica-Bold")
    s["h2"] = ParagraphStyle("h2", fontSize=10, leading=14, spaceBefore=8, spaceAfter=3,
                              textColor=COLOR_ACCENT, fontName="Helvetica-Bold")
    s["body"] = ParagraphStyle("body", fontSize=9, leading=14, spaceAfter=4,
                                textColor=COLOR_DARK, fontName="Helvetica",
                                alignment=TA_JUSTIFY)
    s["body_left"] = ParagraphStyle("body_left", fontSize=9, leading=14,
                                     textColor=COLOR_DARK, fontName="Helvetica",
                                     alignment=TA_LEFT)
    s["bold"] = ParagraphStyle("bold", fontSize=9, leading=14,
                                textColor=COLOR_DARK, fontName="Helvetica-Bold")
    s["mono"] = ParagraphStyle("mono", fontSize=7.5, leading=11,
                                textColor=COLOR_ACCENT, fontName="Courier", wordWrap="CJK")
    s["small"] = ParagraphStyle("small", fontSize=7.5, leading=11,
                                 textColor=COLOR_MID_GREY, fontName="Helvetica")
    s["alert"] = ParagraphStyle("alert", fontSize=9, leading=13,
                                 textColor=COLOR_ALERT, fontName="Helvetica-Bold")
    s["center"] = ParagraphStyle("center", fontSize=9, leading=13,
                                  textColor=COLOR_DARK, fontName="Helvetica",
                                  alignment=TA_CENTER)
    return s


def _hr() -> list:
    return [Spacer(1, 3), HRFlowable(width="100%", thickness=0.4, color=COLOR_BORDER),
            Spacer(1, 5)]


# ---------------------------------------------------------------------------
# Page template
# ---------------------------------------------------------------------------

def _on_page(generated_at: str, case_id: str):
    def fn(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(COLOR_PRIMARY)
        canvas.rect(0, h - 11*mm, w, 11*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.setFillColor(colors.white)
        canvas.drawString(MARGIN, h - 7*mm, "FREEZE REQUEST — BITCOIN FRAUD INVESTIGATION")
        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(w - MARGIN, h - 7*mm, f"Fall-ID: {case_id}")
        canvas.setFillColor(COLOR_LIGHT)
        canvas.rect(0, 0, w, 9*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(COLOR_MID_GREY)
        canvas.drawString(MARGIN, 3*mm,
            f"Erstellt: {generated_at} UTC  |  Vertraulich — nur für autorisierte Empfänger")
        canvas.drawRightString(w - MARGIN, 3*mm, f"Seite {doc.page}")
        canvas.restoreState()
    return fn


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _cover_block(chain: InvestigationChain, contact: ExchangeContact,
                 victim: VictimInfo, generated_at: str, styles: dict) -> list:
    story = []

    # Recipient block
    recipient_rows = [
        [Paragraph("AN / TO:", styles["bold"]),
         Paragraph(f"<b>{contact.name}</b> — Compliance / AML Department", styles["body_left"])],
        ["", Paragraph(contact.compliance_email, styles["mono"])],
    ]
    if contact.le_portal:
        recipient_rows.append(["", Paragraph(f"LE Portal: {contact.le_portal}", styles["mono"])])

    rec_tbl = Table(recipient_rows, colWidths=[22*mm, PAGE_W - 2*MARGIN - 22*mm])
    rec_tbl.setStyle(TableStyle([
        ("FONTNAME",  (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",  (0,0), (-1,-1), 9),
        ("TOPPADDING",    (0,0), (-1,-1), 3),
        ("BOTTOMPADDING", (0,0), (-1,-1), 3),
        ("LEFTPADDING",   (0,0), (-1,-1), 0),
    ]))
    story.append(rec_tbl)
    story.append(Spacer(1, 8))

    # Subject line
    subject_data = [[Paragraph(
        f"BETREFF / RE: Urgent Freeze Request — Bitcoin Fraud — "
        f"{chain.fraud_amount_btc} BTC — Case {chain.case_id}",
        ParagraphStyle("subj", fontSize=10, fontName="Helvetica-Bold",
                       textColor=COLOR_ALERT, leading=14)
    )]]
    subj_tbl = Table(subject_data, colWidths=[PAGE_W - 2*MARGIN])
    subj_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#FDEDEC")),
        ("LINEABOVE",     (0,0), (-1,-1), 2, COLOR_ALERT),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ]))
    story.append(subj_tbl)
    story.append(Spacer(1, 10))

    # Key facts table
    facts = [
        ["Fall-ID / Case ID",       chain.case_id],
        ["Datum / Date",            generated_at + " UTC"],
        ["Fraud-Betrag / Amount",   f"{chain.fraud_amount_btc} BTC"],
        ["Fraud-TX / TXID",         chain.fraud_txid],
        ["Fraud-Adresse",           chain.fraud_address],
        ["Betroffene Exchange-Adresse",
         ", ".join(h.to_address for h in chain.exchange_hits if h.to_address) or "—"],
        ["Geschädigter / Victim",   f"{victim.full_name} ({victim.country})"],
        ["Strafanzeige / Report",
         victim.police_report_number or "In Vorbereitung / Being filed"],
    ]
    facts_tbl = Table(facts, colWidths=[52*mm, PAGE_W - 2*MARGIN - 52*mm])
    facts_tbl.setStyle(TableStyle([
        ("FONTNAME",  (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",  (1,0), (1,-1), "Helvetica"),
        ("FONTSIZE",  (0,0), (-1,-1), 8.5),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, COLOR_LIGHT]),
        ("GRID",      (0,0), (-1,-1), 0.3, COLOR_BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 7),
        ("TEXTCOLOR", (0,0), (0,-1), COLOR_PRIMARY),
    ]))
    story.append(facts_tbl)
    return story


def _section_request_de(chain: InvestigationChain, contact: ExchangeContact,
                         victim: VictimInfo, styles: dict) -> list:
    """German section — for German-speaking authorities and victims."""
    story = [Paragraph("1. Antrag auf sofortige Kontosperrung", styles["h1"])]
    story += _hr()

    story.append(Paragraph(
        f"Hiermit ersuchen wir Sie dringend, alle mit der nachfolgend genannten "
        f"Bitcoin-Einzahlungsadresse Ihrer Plattform verknüpften Konten und Guthaben "
        f"unverzüglich einzufrieren. Die aufgeführten Mittel stammen nachweislich aus "
        f"einer Betrugshandlung und wurden durch forensische On-Chain-Analyse lückenlos "
        f"zurückverfolgt.",
        styles["body"]
    ))

    exchange_addr = ", ".join(
        h.to_address for h in chain.exchange_hits if h.to_address
    ) or "Siehe beigefügten forensischen Analysebericht"

    story.append(Spacer(1, 4))
    story.append(Paragraph("Betroffene Einzahlungsadresse:", styles["bold"]))
    story.append(Paragraph(exchange_addr, styles["mono"]))
    story.append(Spacer(1, 6))

    story.append(Paragraph(
        f"Der Betrug wurde am "
        f"{chain.fraud_timestamp.strftime('%d.%m.%Y um %H:%M:%S')} UTC begangen. "
        f"Der Schaden beläuft sich auf {chain.fraud_amount_btc} BTC. "
        f"Die vollständige forensische Transaktionskette ist dem beigefügten "
        f"Analysebericht zu entnehmen. Alle aufgeführten Transaktionen sind "
        f"öffentlich auf der Bitcoin-Blockchain verifizierbar.",
        styles["body"]
    ))
    return story


def _section_request_en(chain: InvestigationChain, contact: ExchangeContact,
                         victim: VictimInfo, styles: dict) -> list:
    """English section — primary language for compliance teams."""
    story = [Paragraph("2. Urgent Freeze Request (English)", styles["h1"])]
    story += _hr()

    story.append(Paragraph(
        f"We hereby formally request the immediate freeze of all accounts and assets "
        f"associated with the Bitcoin deposit address listed below on your platform. "
        f"The funds in question have been traced through forensic on-chain analysis "
        f"and are directly linked to a fraud event. "
        f"This request is supported by a full forensic blockchain analysis report "
        f"attached to this letter.",
        styles["body"]
    ))

    story.append(Spacer(1, 6))

    # Exchange address highlight box
    exchange_addr = ", ".join(
        h.to_address for h in chain.exchange_hits if h.to_address
    ) or "See attached forensic report"

    addr_data = [[
        Paragraph("Deposit Address to Freeze:", styles["bold"]),
        Paragraph(exchange_addr, styles["mono"]),
    ]]
    addr_tbl = Table(addr_data, colWidths=[50*mm, PAGE_W - 2*MARGIN - 50*mm])
    addr_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#FDEDEC")),
        ("GRID",          (0,0), (-1,-1), 0.3, COLOR_ALERT),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
    ]))
    story.append(addr_tbl)
    story.append(Spacer(1, 6))

    story.append(Paragraph(
        f"The fraud occurred on "
        f"{chain.fraud_timestamp.strftime('%Y-%m-%d at %H:%M:%S')} UTC. "
        f"The total amount defrauded is {chain.fraud_amount_btc} BTC. "
        f"The full chain of custody — from the fraud transaction to your platform's "
        f"deposit address — is documented in the attached forensic report with "
        f"{len(chain.official_report_hops)} verified tracing steps.",
        styles["body"]
    ))

    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "We kindly request you to:",
        styles["bold"]
    ))

    actions = [
        "1. Immediately freeze all accounts and balances associated with the deposit address above.",
        "2. Preserve all KYC/AML data, transaction history, and account information "
           "related to the flagged address for law enforcement purposes.",
        "3. Respond to this request within your stated SLA "
           f"({contact.freeze_sla_hours} hours) confirming the freeze.",
        "4. Provide law enforcement (upon official request) with the account holder "
           "identity linked to the deposit address.",
    ]
    for action in actions:
        story.append(Paragraph(action, styles["body_left"]))

    if contact.notes:
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"Note: {contact.notes}", styles["small"]))

    return story


def _section_evidence(chain: InvestigationChain, styles: dict) -> list:
    story = [Paragraph("3. On-Chain Evidence Summary", styles["h1"])]
    story += _hr()

    story.append(Paragraph(
        "The following table summarises the verified tracing steps. "
        "All transactions are publicly verifiable on the Bitcoin blockchain. "
        "Only L1 (mathematically proven) and L2 (forensically established) "
        "evidence is included.",
        styles["body"]
    ))
    story.append(Spacer(1, 6))

    rows = [["Step", "Transaction ID", "Amount (BTC)", "Method", "Confidence"]]
    for hop in chain.official_report_hops:
        rows.append([
            str(hop.hop_index),
            Paragraph(hop.to_txid[:28] + "...", styles["mono"]),
            str(hop.amount_btc),
            hop.method.value.replace("_", " ").title(),
            hop.confidence.name.replace("_", " "),
        ])

    ev_tbl = Table(rows, colWidths=[12*mm, 68*mm, 25*mm, 38*mm,
                                     PAGE_W - 2*MARGIN - 143*mm])
    ev_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), COLOR_PRIMARY),
        ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",      (0,0), (-1,-1), 7.5),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, COLOR_LIGHT]),
        ("GRID",          (0,0), (-1,-1), 0.3, COLOR_BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 5),
    ]))
    story.append(ev_tbl)

    # Verification note
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "All transactions can be independently verified at: "
        "https://blockstream.info/tx/{TXID} or https://mempool.space/tx/{TXID}",
        styles["small"]
    ))
    return story


def _section_legal(styles: dict) -> list:
    story = [Paragraph("4. Legal Basis / Rechtliche Grundlage", styles["h1"])]
    story += _hr()

    story.append(Paragraph(
        "This freeze request is based on the following legal frameworks:",
        styles["body"]
    ))

    legal_items = [
        ("EU AML Directive 5 & 6 (AMLD5/6)",
         "Requires virtual asset service providers (VASPs) to freeze assets "
         "upon reasonable suspicion of money laundering or fraud."),
        ("FATF Recommendation 16 (Travel Rule)",
         "Requires VASPs to cooperate with law enforcement requests "
         "involving suspected illicit funds."),
        ("EU Regulation 2023/1113 (TFR / Travel Rule)",
         "Mandates information sharing for crypto transfers above EUR 1,000."),
        ("Strafgesetzbuch §263 (Germany) / §146 StGB (Austria)",
         "Criminal fraud provisions — funds from fraud are subject to seizure."),
        ("Budapest Convention on Cybercrime Art. 29",
         "Expedited preservation of stored computer data upon law enforcement request."),
    ]

    for title, desc in legal_items:
        story.append(KeepTogether([
            Paragraph(f"• {title}", styles["bold"]),
            Paragraph(f"  {desc}", styles["small"]),
            Spacer(1, 3),
        ]))

    return story


def _section_victim_contact(victim: VictimInfo, styles: dict) -> list:
    story = [Paragraph("5. Victim Contact / Kontaktdaten Geschädigter", styles["h1"])]
    story += _hr()

    rows = [
        ["Name",       victim.full_name],
        ["E-Mail",     victim.email],
        ["Land",       victim.country],
        ["Telefon",    victim.phone or "—"],
        ["Strafanzeige", victim.police_report_number or "In Vorbereitung"],
        ["Behörde",    victim.police_authority or "—"],
    ]
    tbl = Table(rows, colWidths=[35*mm, PAGE_W - 2*MARGIN - 35*mm])
    tbl.setStyle(TableStyle([
        ("FONTNAME",  (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",  (1,0), (1,-1), "Helvetica"),
        ("FONTSIZE",  (0,0), (-1,-1), 8.5),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, COLOR_LIGHT]),
        ("GRID",      (0,0), (-1,-1), 0.3, COLOR_BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 7),
        ("TEXTCOLOR", (0,0), (0,-1), COLOR_PRIMARY),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "We are available to provide any additional information, coordinate with "
        "law enforcement, or supply the full forensic report in any required format. "
        "Please respond to the e-mail address above within your stated SLA.",
        styles["body"]
    ))
    return story


def _section_attachments(styles: dict) -> list:
    story = [Paragraph("6. Attachments / Anlagen", styles["h1"])]
    story += _hr()
    attachments = [
        "Forensic Blockchain Analysis Report (PDF) — complete chain of custody",
        "Bitcoin Transaction IDs — all hops listed with block heights",
        "Police Report / Strafanzeige (if filed)",
        "Victim ID Document (upon request)",
    ]
    for a in attachments:
        story.append(Paragraph(f"• {a}", styles["body_left"]))
    return story


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_freeze_request(
    chain: InvestigationChain,
    victim: VictimInfo,
    output_path: str,
) -> list[str]:
    """
    Generate freeze request letters for all identified exchanges.

    Args:
        chain:       Completed InvestigationChain (official_report_hops only)
        victim:      Victim contact information
        output_path: Output PDF path (exchange name appended if multiple)

    Returns:
        List of generated PDF paths.
    """
    if not chain.exchange_hits:
        raise ValueError(
            "No exchange hits in chain. Cannot generate freeze request "
            "without a confirmed exchange destination."
        )

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    output_paths = []

    # Group hops by exchange
    exchanges: dict[str, list[TracingHop]] = {}
    for hop in chain.exchange_hits:
        name = hop.exchange_name or "Unknown"
        exchanges.setdefault(name, []).append(hop)

    for exchange_name, hops in exchanges.items():
        contact = get_exchange_contact(exchange_name)

        # Determine output path
        if len(exchanges) > 1:
            base = output_path.replace(".pdf", "")
            path = f"{base}_{exchange_name.replace(' ', '_')}.pdf"
        else:
            path = output_path

        _generate_single(chain, victim, contact, generated_at, path)
        output_paths.append(path)

    return output_paths


def _generate_single(
    chain: InvestigationChain,
    victim: VictimInfo,
    contact: ExchangeContact,
    generated_at: str,
    output_path: str,
) -> None:
    styles = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=16*mm, bottomMargin=14*mm,
        title=f"Freeze Request — {chain.case_id} — {contact.name}",
        author="AIFinancialCrime Forensik-System",
        subject=f"Bitcoin Fraud Freeze Request — {chain.fraud_address[:20]}...",
    )

    story = []
    story += _cover_block(chain, contact, victim, generated_at, styles)
    story.append(Spacer(1, 8))
    story += _section_request_de(chain, contact, victim, styles)
    story.append(Spacer(1, 6))
    story += _section_request_en(chain, contact, victim, styles)
    story.append(PageBreak())
    story += _section_evidence(chain, styles)
    story.append(Spacer(1, 6))
    story += _section_legal(styles)
    story.append(Spacer(1, 6))
    story += _section_victim_contact(victim, styles)
    story.append(Spacer(1, 6))
    story += _section_attachments(styles)

    on_page = _on_page(generated_at, chain.case_id)
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

    with open(output_path, "wb") as f:
        f.write(buf.getvalue())
