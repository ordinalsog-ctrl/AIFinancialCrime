"""
Exchange Contact Database
src/investigation/exchange_contacts.py

Aktuelle Law-Enforcement-Kontakte der wichtigsten Exchanges.
Datenstand: 2025 — muss regelmässig gepflegt werden.

Verwendung:
    from src.investigation.exchange_contacts import ExchangeContactDB
    db = ExchangeContactDB()
    contact = db.get("Binance")
    print(contact.le_portal_url)
    print(contact.response_days_typical)

Quellen:
    - Offizielle Exchange-Websites (law-enforcement Sections)
    - Öffentliche Transparenzberichte der Exchanges
    - Behördliche Dokumentation (Europol, BKA, IC3)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ExchangeContact:
    """Kontaktdaten einer Exchange für Freeze-Requests und LE-Anfragen."""

    name: str                               # Kanonischer Name (wie in Attribution DB)
    name_aliases: list[str]                 # Varianten (für Matching)

    # Law-Enforcement-Kontakt
    le_portal_url: Optional[str]            # Offizielles LE-Portal (bevorzugt)
    le_email: Optional[str]                 # E-Mail-Fallback
    le_postal: Optional[str]               # Postadresse für formelle Schreiben

    # Victim-Kontakt (wenn kein LE-Portal erreichbar)
    victim_support_url: Optional[str]       # Support für Betrugsopfer
    victim_email: Optional[str]

    # Zeiteinschätzung
    response_days_typical: int              # Typische Antwortzeit (Werktage)
    response_days_max: int                  # Maximale Wartezeit vor Nachfassen
    requires_police_report: bool            # Strafanzeige zwingend erforderlich
    accepts_victim_direct: bool             # Akzeptiert direkte Opfer-Anfragen

    # Jurisdiktion
    headquarters: str                       # Hauptsitz
    regulated_jurisdictions: list[str]      # Wo reguliert

    # Prozesshinweise
    process_notes_de: str                   # Hinweise für deutsche Opfer
    process_notes_en: str                   # Hinweise für englischsprachige Opfer

    # Metadaten
    last_verified: str                      # Datum der letzten Verifikation
    confidence: str = "HIGH"               # HIGH / MEDIUM / LOW


# =============================================================================
# Exchange-Datenbank
# =============================================================================

EXCHANGES: list[ExchangeContact] = [

    ExchangeContact(
        name="Binance",
        name_aliases=["binance.com", "Binance.com", "BNB", "BNANCE"],
        le_portal_url="https://www.binance.com/en/support/law-enforcement",
        le_email="law_enforcement@binance.com",
        le_postal=(
            "Binance Holdings Limited\n"
            "Compliance Department\n"
            "Cayman Islands"
        ),
        victim_support_url="https://www.binance.com/en/support/faq/crypto-scam",
        victim_email="support@binance.com",
        response_days_typical=3,
        response_days_max=14,
        requires_police_report=True,
        accepts_victim_direct=False,
        headquarters="Cayman Islands (operativ: Dubai / Singapur)",
        regulated_jurisdictions=["EU (MiCA)", "Frankreich (AMF)", "Bahrain", "Abu Dhabi"],
        process_notes_de=(
            "Binance bearbeitet Freeze-Requests ausschliesslich über das offizielle "
            "LE-Portal. Opfer können direkt über den Victim-Support-Link melden, "
            "jedoch ist eine offizielle Strafanzeige (mit Aktenzeichen) zwingend "
            "für eine Kontoeinfrierung erforderlich. In Deutschland: LKA Cybercrime "
            "kontaktieren, das dann offiziell an Binance herantritt."
        ),
        process_notes_en=(
            "Binance processes freeze requests exclusively via the official LE portal. "
            "A formal police report with case reference number is required for any "
            "account freeze. Victims may use the victim support link to report scams, "
            "but direct victim requests rarely result in account action."
        ),
        last_verified="2025-01",
        confidence="HIGH",
    ),

    ExchangeContact(
        name="Coinbase",
        name_aliases=["coinbase.com", "Coinbase Pro", "COIN"],
        le_portal_url="https://www.coinbase.com/legal/law_enforcement",
        le_email="investigations@coinbase.com",
        le_postal=(
            "Coinbase, Inc.\n"
            "Legal / Law Enforcement Requests\n"
            "548 Market St #23008\n"
            "San Francisco, CA 94104, USA"
        ),
        victim_support_url="https://help.coinbase.com/en/coinbase/privacy-and-security/account-compromised",
        victim_email=None,
        response_days_typical=5,
        response_days_max=21,
        requires_police_report=True,
        accepts_victim_direct=True,
        headquarters="San Francisco, CA, USA",
        regulated_jurisdictions=["USA (FinCEN, NYDFS)", "EU (MiCA)", "UK (FCA)", "Deutschland (BaFin)"],
        process_notes_de=(
            "Coinbase ist eines der kooperativsten Exchanges bei LE-Anfragen. "
            "Als börsennotiertes US-Unternehmen (NASDAQ: COIN) unterliegt es strikter "
            "Regulierung. Deutsche Opfer können über das LE-Portal einen Antrag einreichen "
            "oder das LKA beauftragen. Coinbase reagiert auch auf Opfer-Direktanfragen "
            "bei nachgewiesenem Betrug. Transparenzbericht zeigt hohe Compliance-Rate."
        ),
        process_notes_en=(
            "Coinbase is among the most cooperative exchanges for law enforcement. "
            "As a public US company, it complies with court orders and formal LE requests. "
            "Direct victim reports via help portal may result in account review. "
            "Formal requests via the LE portal are processed most reliably."
        ),
        last_verified="2025-01",
        confidence="HIGH",
    ),

    ExchangeContact(
        name="Kraken",
        name_aliases=["kraken.com", "Payward", "Payward Inc"],
        le_portal_url="https://www.kraken.com/legal/subpoenas",
        le_email="legal@kraken.com",
        le_postal=(
            "Payward, Inc. (Kraken)\n"
            "Legal Department\n"
            "237 Kearny Street #102\n"
            "San Francisco, CA 94108, USA"
        ),
        victim_support_url="https://support.kraken.com/hc/en-us/articles/115012482807",
        victim_email="support@kraken.com",
        response_days_typical=7,
        response_days_max=30,
        requires_police_report=True,
        accepts_victim_direct=True,
        headquarters="San Francisco, CA, USA",
        regulated_jurisdictions=["USA (FinCEN)", "EU (MiCA)", "UK (FCA)", "Kanada"],
        process_notes_de=(
            "Kraken veröffentlicht jährliche Transparenzberichte zu LE-Anfragen "
            "und zeigt hohe Compliance. 2024 erhielt Kraken 6.826 Anfragen (+38%). "
            "Deutschland war nach den USA und UK drittgrösster Anfragesteller. "
            "Kraken reagiert auf formelle Anfragen zuverlässig, direkte Opfer-Anfragen "
            "werden ebenfalls bearbeitet."
        ),
        process_notes_en=(
            "Kraken publishes annual transparency reports. Response times are typically "
            "longer than Binance/Coinbase. A formal LE request or court order yields "
            "the best results. Direct victim support is available and responsive."
        ),
        last_verified="2025-02",
        confidence="HIGH",
    ),

    ExchangeContact(
        name="Bybit",
        name_aliases=["bybit.com", "Bybit Exchange"],
        le_portal_url="https://www.bybit.com/en/legal/law-enforcement",
        le_email="security@bybit.com",
        le_postal=(
            "Bybit Fintech Limited\n"
            "Legal Department\n"
            "Road Town, Tortola\n"
            "British Virgin Islands"
        ),
        victim_support_url="https://help.bybit.com/hc/en-us/articles/360039749753",
        victim_email="support@bybit.com",
        response_days_typical=7,
        response_days_max=21,
        requires_police_report=True,
        accepts_victim_direct=False,
        headquarters="Dubai, UAE / British Virgin Islands",
        regulated_jurisdictions=["Dubai (VARA)", "EU (MiCA, einige Länder)"],
        process_notes_de=(
            "Bybit ist in Deutschland nicht direkt zugelassen. "
            "Freeze-Requests sollten über das BKA oder Europol an Bybit weitergeleitet "
            "werden. Direktkontakt für Opfer ist begrenzt wirksam. Nach dem Bybit-Hack "
            "2025 (1,5 Mrd USD durch nordkoreanische Hacker) hat Bybit die Sicherheits- "
            "und Compliance-Prozesse verstärkt."
        ),
        process_notes_en=(
            "Bybit processes LE requests via its official portal. Direct victim requests "
            "have limited effectiveness. For EU/German victims, routing through national "
            "law enforcement (BKA, Europol) is recommended. Bybit significantly expanded "
            "its compliance team after the 2025 hack incident."
        ),
        last_verified="2025-03",
        confidence="HIGH",
    ),

    ExchangeContact(
        name="OKX",
        name_aliases=["okx.com", "OKEx", "OKCoin"],
        le_portal_url="https://www.okx.com/help/law-enforcement",
        le_email="compliance@okx.com",
        le_postal=(
            "OKX (Aux Cayes FinTech Co. Ltd.)\n"
            "Compliance Department\n"
            "Seychelles"
        ),
        victim_support_url="https://www.okx.com/help/security-center",
        victim_email="security@okx.com",
        response_days_typical=10,
        response_days_max=30,
        requires_police_report=True,
        accepts_victim_direct=False,
        headquarters="Seychelles (operativ: Singapur / Dubai)",
        regulated_jurisdictions=["Dubai (VARA)", "EU (MiCA)", "Bahamas", "USA (ab 2025)"],
        process_notes_de=(
            "OKX hat 2025 in den USA nach seiner Strafe von 500+ Mio USD eine "
            "verstärkte Compliance-Abteilung aufgebaut. Für deutsche Opfer empfiehlt "
            "sich der Weg über die Zentralstelle Cybercrime des LKA. "
            "Direktanfragen von Opfern werden selten bearbeitet."
        ),
        process_notes_en=(
            "OKX pleaded guilty in February 2025 and paid $504M+ in US penalties. "
            "Its compliance processes have since improved significantly. LE requests "
            "via the official portal are the most effective route. "
            "Direct victim requests have low success rates."
        ),
        last_verified="2025-03",
        confidence="HIGH",
    ),

    ExchangeContact(
        name="KuCoin",
        name_aliases=["kucoin.com", "KuCoin Exchange"],
        le_portal_url=None,
        le_email="compliance@kucoin.com",
        le_postal=(
            "Mek Global Limited (KuCoin)\n"
            "Compliance Department\n"
            "Seychelles"
        ),
        victim_support_url="https://www.kucoin.com/support",
        victim_email="support@kucoin.com",
        response_days_typical=14,
        response_days_max=45,
        requires_police_report=True,
        accepts_victim_direct=True,
        headquarters="Seychelles",
        regulated_jurisdictions=["Bahamas", "Seychelles"],
        process_notes_de=(
            "KuCoin hat kein öffentliches LE-Portal. Anfragen müssen per E-Mail "
            "an compliance@kucoin.com mit vollständiger Dokumentation gesendet werden. "
            "Antwortzeiten sind variabel. Für DE-Opfer: Strafanzeige bei LKA stellen "
            "und BKA mit Kontaktaufnahme beauftragen."
        ),
        process_notes_en=(
            "KuCoin lacks a dedicated LE portal. Email to compliance is the primary "
            "channel. Response times are inconsistent. Formal LE requests through "
            "national authorities are more effective than direct victim contact."
        ),
        last_verified="2025-01",
        confidence="MEDIUM",
    ),

    ExchangeContact(
        name="Bitfinex",
        name_aliases=["bitfinex.com", "iFinex"],
        le_portal_url=None,
        le_email="security@bitfinex.com",
        le_postal=(
            "iFinex Inc. (Bitfinex)\n"
            "Legal Department\n"
            "Road Town, Tortola\n"
            "British Virgin Islands"
        ),
        victim_support_url="https://support.bitfinex.com",
        victim_email="support@bitfinex.com",
        response_days_typical=14,
        response_days_max=60,
        requires_police_report=True,
        accepts_victim_direct=False,
        headquarters="British Virgin Islands / Hongkong",
        regulated_jurisdictions=["BVI"],
        process_notes_de=(
            "Bitfinex ist bekannt für den Hack von 2016 (119.756 BTC gestohlen). "
            "US-Behörden haben 2022 einen Grossteil der Gelder zurückgewonnen. "
            "Bitfinex kooperiert mit LE-Behörden, bevorzugt jedoch formelle Wege. "
            "Kein öffentliches LE-Portal — Anfragen per E-Mail."
        ),
        process_notes_en=(
            "Bitfinex is known for the 2016 hack. US authorities recovered most funds "
            "in 2022. Bitfinex cooperates with formal LE requests. No public LE portal "
            "— email contact is the only channel."
        ),
        last_verified="2025-01",
        confidence="MEDIUM",
    ),

    ExchangeContact(
        name="Crypto.com",
        name_aliases=["crypto.com", "Crypto.com Exchange", "CDC"],
        le_portal_url="https://help.crypto.com/en/articles/3637257",
        le_email="law.enforcement@crypto.com",
        le_postal=(
            "Foris DAX Asia Pte. Ltd. (Crypto.com)\n"
            "Legal / Compliance\n"
            "Singapore"
        ),
        victim_support_url="https://help.crypto.com/en/articles/3637257",
        victim_email="support@crypto.com",
        response_days_typical=7,
        response_days_max=21,
        requires_police_report=True,
        accepts_victim_direct=True,
        headquarters="Singapur",
        regulated_jurisdictions=["Singapur (MAS)", "EU (MiCA)", "USA (FinCEN)", "Dubai (VARA)"],
        process_notes_de=(
            "Crypto.com ist MAS-reguliert (Singapur) und hat ein klares LE-Verfahren. "
            "Opfer können direkt über den Support ein Ticket einreichen mit Angabe "
            "der Fraud-Transaktion. Für formelle Freeze-Requests: Strafanzeige + "
            "offizielles Schreiben der Polizei/LKA an law.enforcement@crypto.com."
        ),
        process_notes_en=(
            "Crypto.com follows MAS (Singapore) compliance guidelines. "
            "Direct victim reports via support portal are processed, but formal "
            "LE requests yield faster and more reliable results."
        ),
        last_verified="2025-01",
        confidence="HIGH",
    ),

    ExchangeContact(
        name="Gemini",
        name_aliases=["gemini.com", "Gemini Trust"],
        le_portal_url="https://www.gemini.com/legal/subpoenas",
        le_email="legal@gemini.com",
        le_postal=(
            "Gemini Trust Company, LLC\n"
            "Legal Department\n"
            "600 Third Avenue, 2nd Floor\n"
            "New York, NY 10016, USA"
        ),
        victim_support_url="https://support.gemini.com",
        victim_email="support@gemini.com",
        response_days_typical=5,
        response_days_max=21,
        requires_police_report=True,
        accepts_victim_direct=True,
        headquarters="New York, USA",
        regulated_jurisdictions=["USA (NYDFS)", "UK (FCA)", "Singapur (MAS)"],
        process_notes_de=(
            "Gemini ist NYDFS-reguliert und bekannt für hohe Compliance. "
            "Als New Yorker Trust Company unterliegt Gemini strengsten US-Anforderungen. "
            "Für EU/DE-Opfer: Direktkontakt via LE-Portal oder über LKA/BKA."
        ),
        process_notes_en=(
            "Gemini is one of the most regulated US exchanges (NYDFS Trust Company). "
            "Formal LE requests via the subpoena portal are processed efficiently. "
            "Direct victim reports are taken seriously due to regulatory requirements."
        ),
        last_verified="2025-01",
        confidence="HIGH",
    ),

    ExchangeContact(
        name="Huobi",
        name_aliases=["huobi.com", "HTX", "HTX Global"],
        le_portal_url=None,
        le_email="compliance@htx.com",
        le_postal=None,
        victim_support_url="https://www.htx.com/support/en-us/",
        victim_email="support@htx.com",
        response_days_typical=21,
        response_days_max=90,
        requires_police_report=True,
        accepts_victim_direct=False,
        headquarters="Seychelles",
        regulated_jurisdictions=["Seychelles"],
        process_notes_de=(
            "HTX (ehemals Huobi) hat nur begrenzte öffentliche Compliance-Strukturen. "
            "Für EU-Opfer ist der Weg über Europol / Eurojust empfohlen. "
            "Direktkontakt ist selten erfolgreich."
        ),
        process_notes_en=(
            "HTX has limited public compliance infrastructure. "
            "Route requests through Europol or national LE authorities. "
            "Direct victim contact rarely results in action."
        ),
        last_verified="2025-01",
        confidence="LOW",
    ),
]


# =============================================================================
# Lookup-Klasse
# =============================================================================

class ExchangeContactDB:
    """Lookup-Interface für Exchange-Kontaktdaten."""

    def __init__(self):
        self._by_name: dict[str, ExchangeContact] = {}
        for exc in EXCHANGES:
            self._by_name[exc.name.lower()] = exc
            for alias in exc.name_aliases:
                self._by_name[alias.lower()] = exc

    def get(self, name: str) -> Optional[ExchangeContact]:
        """Gibt Kontaktdaten für eine Exchange zurück (case-insensitive)."""
        return self._by_name.get(name.lower())

    def get_all(self) -> list[ExchangeContact]:
        """Gibt alle Exchanges zurück (dedupliziert)."""
        return list({id(e): e for e in self._by_name.values()}.values())

    def get_by_confidence(self, min_confidence: str = "HIGH") -> list[ExchangeContact]:
        """Gibt nur Exchanges mit mindestens angegebener Konfidenz zurück."""
        order = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
        min_level = order.get(min_confidence, 0)
        return [e for e in self.get_all() if order.get(e.confidence, 0) >= min_level]

    def format_contact_block(self, name: str, language: str = "de") -> str:
        """Formatiert Kontaktdaten als lesbaren Text für Reports."""
        exc = self.get(name)
        if not exc:
            return f"Keine verifizierten Kontaktdaten für '{name}' verfügbar."

        lines = [f"{'─' * 50}", f"Exchange: {exc.name}", f"Hauptsitz: {exc.headquarters}"]

        if exc.le_portal_url:
            lines.append(f"LE-Portal:  {exc.le_portal_url}")
        if exc.le_email:
            lines.append(f"LE-E-Mail:  {exc.le_email}")
        if exc.victim_support_url and exc.accepts_victim_direct:
            lines.append(f"Opfer-URL:  {exc.victim_support_url}")

        lines.append(f"Antwortzeit: {exc.response_days_typical}–{exc.response_days_max} Werktage")
        lines.append(f"Strafanzeige erforderlich: {'Ja' if exc.requires_police_report else 'Nein'}")

        notes = exc.process_notes_de if language == "de" else exc.process_notes_en
        lines.append(f"\nHinweise: {notes}")
        lines.append(f"{'─' * 50}")
        lines.append(f"Letzte Verifikation: {exc.last_verified}")

        return "\n".join(lines)

    def all_names(self) -> list[str]:
        """Alle kanonischen Exchange-Namen."""
        return [e.name for e in self.get_all()]

    def stats(self) -> dict:
        all_exc = self.get_all()
        return {
            "total": len(all_exc),
            "with_le_portal":   sum(1 for e in all_exc if e.le_portal_url),
            "accepts_direct":   sum(1 for e in all_exc if e.accepts_victim_direct),
            "high_confidence":  sum(1 for e in all_exc if e.confidence == "HIGH"),
            "avg_response_days": round(
                sum(e.response_days_typical for e in all_exc) / len(all_exc), 1
            ),
        }
