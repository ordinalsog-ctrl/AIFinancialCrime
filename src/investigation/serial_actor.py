"""
Serial Actor Detection Engine
src/investigation/serial_actor.py

Erkennt Serientäter: gleiche Adressen oder CIO-Cluster in mehreren Fällen.

Kernlogik:
  1. Investigation abschliessen → alle Adressen in investigation_addresses speichern
  2. Quersuche: gibt es diese Adressen in anderen Fällen?
  3. Matches aggregieren → serial_actor_matches
  4. Profile erstellen / aktualisieren → serial_actor_profiles

Verwendung:
    engine = SerialActorEngine(db_conn)

    # Nach jeder neuen Investigation:
    matches = engine.check_new_investigation(chain, investigation_id)
    if matches:
        print(f"⚠ Serientäter: {len(matches)} Treffer in {matches[0].matching_cases}")

    # Profil-Übersicht:
    profiles = engine.get_active_profiles(min_cases=2)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from src.investigation.confidence_engine import ConfidenceLevel, InvestigationChain, TracingHop

logger = logging.getLogger(__name__)


# =============================================================================
# Datenstrukturen
# =============================================================================

@dataclass
class SerialMatch:
    """Ein Treffer: gleiche Adresse / Cluster in mehreren Fällen."""
    match_type: str           # SAME_ADDRESS | SAME_CIO_CLUSTER | SAME_EXCHANGE_DEPOSIT
    shared_value: str         # Adresse oder Cluster-ID
    matching_cases: list[str] # Andere Cases mit diesem Wert
    current_case: str
    confidence_level: str     # L1 / L2 / L3
    total_btc_involved: Decimal = Decimal("0")
    profile_id: Optional[int] = None


@dataclass
class SerialActorProfile:
    """Aggregiertes Profil eines Serientäters."""
    profile_id: int
    profile_label: Optional[str]
    total_cases: int
    total_btc_stolen: Decimal
    risk_score: int
    status: str
    known_addresses: list[str]
    known_cio_clusters: list[str]
    known_exchanges: list[str]
    first_case_date: Optional[datetime]
    last_case_date: Optional[datetime]
    modus_operandi: Optional[str]
    match_count: int = 0
    days_since_last_case: Optional[int] = None


@dataclass
class InvestigationAddressRecord:
    """Eine Adresse aus einer Investigation — zum Speichern in investigation_addresses."""
    investigation_id: int
    case_id: str
    address: str
    address_role: str          # FRAUD_ORIGIN | HOP | EXCHANGE_DEPOSIT
    hop_index: Optional[int]
    confidence_level: str
    amount_btc: Optional[Decimal]
    block_height: Optional[int]


# =============================================================================
# Hilfsfunktionen
# =============================================================================

def _confidence_to_str(level) -> str:
    """Normalisiert ConfidenceLevel zu L1/L2/L3/L4 String."""
    if hasattr(level, "name"):
        name = level.name
    else:
        name = str(level)
    if "L1" in name or "VERIFIED" in name:
        return "L1"
    if "L2" in name or "HIGH" in name:
        return "L2"
    if "L3" in name or "INDICATIVE" in name:
        return "L3"
    return "L4"


def _extract_addresses_from_chain(
    chain: InvestigationChain,
    investigation_id: int,
) -> list[InvestigationAddressRecord]:
    """Extrahiert alle relevanten Adressen aus einer InvestigationChain."""
    records: list[InvestigationAddressRecord] = []

    # Fraud-Ursprungsadresse
    records.append(InvestigationAddressRecord(
        investigation_id=investigation_id,
        case_id=chain.case_id,
        address=chain.fraud_address,
        address_role="FRAUD_ORIGIN",
        hop_index=0,
        confidence_level="L1",
        amount_btc=Decimal(str(chain.fraud_amount_btc)) if chain.fraud_amount_btc else None,
        block_height=None,
    ))

    # Alle Hop-Adressen (nur L1+L2 — forensisch belegt)
    for hop in chain.official_report_hops:
        conf = _confidence_to_str(hop.confidence)

        if hop.from_address and hop.from_address != chain.fraud_address:
            records.append(InvestigationAddressRecord(
                investigation_id=investigation_id,
                case_id=chain.case_id,
                address=hop.from_address,
                address_role="HOP",
                hop_index=hop.hop_index,
                confidence_level=conf,
                amount_btc=hop.amount_btc,
                block_height=hop.block_height_from,
            ))

        if hop.to_address:
            role = "EXCHANGE_DEPOSIT" if hop.exchange_name else "HOP"
            records.append(InvestigationAddressRecord(
                investigation_id=investigation_id,
                case_id=chain.case_id,
                address=hop.to_address,
                address_role=role,
                hop_index=hop.hop_index,
                confidence_level=conf,
                amount_btc=hop.amount_btc,
                block_height=hop.block_height_to,
            ))

    # Deduplizieren nach Adresse (gleiche Adresse nur einmal mit höchstem Confidence-Level)
    seen: dict[str, InvestigationAddressRecord] = {}
    priority = {"L1": 4, "L2": 3, "L3": 2, "L4": 1}
    for r in records:
        existing = seen.get(r.address)
        if not existing or priority.get(r.confidence_level, 0) > priority.get(existing.confidence_level, 0):
            seen[r.address] = r

    return list(seen.values())


# =============================================================================
# Engine
# =============================================================================

class SerialActorEngine:
    """
    Serientäter-Erkennungs-Engine.

    Benötigt eine PostgreSQL-Verbindung (psycopg2 oder asyncpg-kompatibel).
    Im Offline/Test-Modus ohne DB: check_offline() nutzen.
    """

    def __init__(self, conn=None):
        self._conn = conn
        self._online = conn is not None

    # ──────────────────────────────────────────────────────────────────────────
    # Hauptmethode: neue Investigation prüfen
    # ──────────────────────────────────────────────────────────────────────────

    def check_new_investigation(
        self,
        chain: InvestigationChain,
        investigation_id: int,
    ) -> list[SerialMatch]:
        """
        Prüft eine neue Investigation auf Serientäter-Muster.

        1. Adressen der Investigation speichern
        2. Gegen frühere Investigations querieren
        3. Matches in serial_actor_matches speichern
        4. Ergebnis zurückgeben

        Returns:
            Liste von SerialMatch-Objekten (leer wenn kein Serientäter)
        """
        if not self._online:
            logger.warning("Kein DB-Verbindung — Serientäter-Check übersprungen")
            return []

        records = _extract_addresses_from_chain(chain, investigation_id)

        try:
            # Adressen speichern
            self._save_addresses(records)

            # DB-Funktion aufrufen
            return self._query_matches(chain.case_id, investigation_id)

        except Exception as e:
            logger.error(f"Serientäter-Check fehlgeschlagen: {e}")
            return []

    def _save_addresses(self, records: list[InvestigationAddressRecord]) -> None:
        """Speichert Adressen in investigation_addresses."""
        if not records:
            return
        with self._conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO investigation_addresses
                    (investigation_id, case_id, address, address_role,
                     hop_index, confidence_level, amount_btc, block_height)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                [
                    (r.investigation_id, r.case_id, r.address, r.address_role,
                     r.hop_index, r.confidence_level,
                     float(r.amount_btc) if r.amount_btc else None,
                     r.block_height)
                    for r in records
                ],
            )
        self._conn.commit()
        logger.info(f"{len(records)} Adressen gespeichert")

    def _query_matches(
        self,
        case_id: str,
        investigation_id: int,
    ) -> list[SerialMatch]:
        """Ruft find_serial_matches() auf und verarbeitet Ergebnis."""
        matches = []
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT match_type, shared_value, matching_cases, confidence_level "
                "FROM find_serial_matches(%s)",
                (investigation_id,),
            )
            rows = cur.fetchall()

        for match_type, shared_value, matching_cases, confidence in rows:
            match = SerialMatch(
                match_type=match_type,
                shared_value=shared_value,
                matching_cases=matching_cases or [],
                current_case=case_id,
                confidence_level=confidence or "L3",
            )
            matches.append(match)
            logger.info(
                f"Serientäter-Treffer: {match_type} | {shared_value[:20]}... "
                f"in {len(matching_cases)} anderen Case(s)"
            )

        if matches:
            self._save_matches(matches, case_id)

        return matches

    def _save_matches(self, matches: list[SerialMatch], new_case_id: str) -> None:
        """Speichert neue Matches in serial_actor_matches."""
        with self._conn.cursor() as cur:
            for m in matches:
                all_cases = sorted(set([new_case_id] + m.matching_cases))
                cur.execute(
                    """
                    INSERT INTO serial_actor_matches
                        (match_type, shared_value, case_ids, investigation_ids,
                         confidence_level, total_btc_involved, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())
                    ON CONFLICT DO NOTHING
                    """,
                    (m.match_type, m.shared_value, all_cases, [],
                     m.confidence_level,
                     float(m.total_btc_involved) if m.total_btc_involved else None),
                )
        self._conn.commit()

    # ──────────────────────────────────────────────────────────────────────────
    # Profil-Abfragen
    # ──────────────────────────────────────────────────────────────────────────

    def get_active_profiles(self, min_cases: int = 2) -> list[SerialActorProfile]:
        """Gibt alle aktiven Serientäter-Profile mit mind. min_cases Fällen zurück."""
        if not self._online:
            return []
        with self._conn.cursor() as cur:
            cur.execute(
                """
                SELECT profile_id, profile_label, total_cases, total_btc_stolen,
                       risk_score, status, known_addresses, known_cio_clusters,
                       known_exchanges, first_case_date, last_case_date,
                       modus_operandi, match_count, days_since_last_case
                FROM serial_actor_overview
                WHERE total_cases >= %s AND status != 'RESOLVED'
                ORDER BY risk_score DESC, total_cases DESC
                """,
                (min_cases,),
            )
            rows = cur.fetchall()

        profiles = []
        for row in rows:
            profiles.append(SerialActorProfile(
                profile_id=row[0], profile_label=row[1],
                total_cases=row[2],
                total_btc_stolen=Decimal(str(row[3])) if row[3] else Decimal("0"),
                risk_score=row[4] or 0, status=row[5],
                known_addresses=row[6] or [], known_cio_clusters=row[7] or [],
                known_exchanges=row[8] or [],
                first_case_date=row[9], last_case_date=row[10],
                modus_operandi=row[11], match_count=row[12] or 0,
                days_since_last_case=row[13],
            ))
        return profiles

    def get_matches_for_case(self, case_id: str) -> list[SerialMatch]:
        """Gibt alle Serientäter-Matches für einen bestimmten Case zurück."""
        if not self._online:
            return []
        with self._conn.cursor() as cur:
            cur.execute(
                """
                SELECT match_type, shared_value, case_ids, confidence_level,
                       total_btc_involved, profile_id
                FROM serial_actor_matches
                WHERE %s = ANY(case_ids)
                ORDER BY case_count DESC
                """,
                (case_id,),
            )
            rows = cur.fetchall()

        return [
            SerialMatch(
                match_type=r[0], shared_value=r[1],
                matching_cases=[c for c in (r[2] or []) if c != case_id],
                current_case=case_id,
                confidence_level=r[3] or "L3",
                total_btc_involved=Decimal(str(r[4])) if r[4] else Decimal("0"),
                profile_id=r[5],
            )
            for r in rows
        ]

    def create_profile_from_matches(
        self,
        match_ids: list[int],
        profile_label: str,
        modus_operandi: str = "",
    ) -> Optional[int]:
        """Erstellt ein neues Täter-Profil aus einer Gruppe von Matches."""
        if not self._online:
            return None
        with self._conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO serial_actor_profiles
                    (profile_label, modus_operandi)
                VALUES (%s, %s)
                RETURNING profile_id
                """,
                (profile_label, modus_operandi),
            )
            profile_id = cur.fetchone()[0]

            if match_ids:
                cur.execute(
                    "UPDATE serial_actor_matches SET profile_id = %s WHERE match_id = ANY(%s)",
                    (profile_id, match_ids),
                )

            cur.execute("SELECT refresh_serial_profile(%s)", (profile_id,))
        self._conn.commit()
        logger.info(f"Neues Serientäter-Profil erstellt: ID={profile_id} Label='{profile_label}'")
        return profile_id

    # ──────────────────────────────────────────────────────────────────────────
    # Offline-Analyse (ohne DB — für Tests und lokale Vorschau)
    # ──────────────────────────────────────────────────────────────────────────

    def check_offline(
        self,
        new_chain: InvestigationChain,
        known_chains: list[InvestigationChain],
    ) -> list[SerialMatch]:
        """
        Vergleicht eine neue Chain gegen bekannte Chains ohne DB.
        Für Tests, lokale Reports und Offline-Analyse.

        Returns:
            SerialMatch-Liste — eine Eintrag pro gemeinsamer Adresse,
            mit allen betroffenen Cases aggregiert.
        """
        new_records   = _extract_addresses_from_chain(new_chain, investigation_id=0)
        # Nur Adressen die KEIN reiner Exchange-Deposit sind — die sind kein Täter-Merkmal
        new_addresses = {
            r.address for r in new_records
            if r.address_role != "EXCHANGE_DEPOSIT"
        }

        # addr → set of matching case_ids
        addr_to_cases: dict[str, set[str]] = {}
        addr_to_conf:  dict[str, str]      = {}
        addr_to_btc:   dict[str, Decimal]  = {}
        priority = {"L1": 4, "L2": 3, "L3": 2, "L4": 1}

        for known in known_chains:
            if known.case_id == new_chain.case_id:
                continue
            known_records   = _extract_addresses_from_chain(known, investigation_id=0)
            known_addresses = {
                r.address for r in known_records
                if r.address_role != "EXCHANGE_DEPOSIT"
            }
            overlap = new_addresses & known_addresses
            for addr in overlap:
                new_conf   = next((r.confidence_level for r in new_records   if r.address == addr), "L3")
                known_conf = next((r.confidence_level for r in known_records if r.address == addr), "L3")
                best_conf  = new_conf if priority.get(new_conf, 0) >= priority.get(known_conf, 0) else known_conf

                if addr not in addr_to_cases:
                    addr_to_cases[addr] = set()
                    addr_to_btc[addr]   = Decimal("0")
                    addr_to_conf[addr]  = best_conf

                addr_to_cases[addr].add(known.case_id)
                addr_to_btc[addr] += Decimal(str(known.fraud_amount_btc or 0))
                # upgrade confidence if better
                if priority.get(best_conf, 0) > priority.get(addr_to_conf[addr], 0):
                    addr_to_conf[addr] = best_conf

        matches: list[SerialMatch] = []
        for addr, cases in addr_to_cases.items():
            matches.append(SerialMatch(
                match_type="SAME_ADDRESS",
                shared_value=addr,
                matching_cases=sorted(cases),
                current_case=new_chain.case_id,
                confidence_level=addr_to_conf[addr],
                total_btc_involved=(
                    addr_to_btc[addr] +
                    Decimal(str(new_chain.fraud_amount_btc or 0))
                ),
            ))
            logger.info(
                f"Offline-Serientäter: {addr[:16]}... in "
                f"'{new_chain.case_id}' + {sorted(cases)}"
            )

        return matches

    def format_matches_report(self, matches: list[SerialMatch], language: str = "de") -> str:
        """Formatiert Serientäter-Matches als lesbaren Text für PDF-Reports."""
        if not matches:
            return "Keine Serientäter-Überschneidungen mit bekannten Fällen gefunden."

        lines = [
            f"{'━' * 55}",
            f"⚠  SERIENTÄTER-WARNUNG: {len(matches)} Überschneidung(en) gefunden",
            f"{'━' * 55}",
        ]

        for i, m in enumerate(matches, 1):
            lines += [
                f"\n[{i}] Typ:       {m.match_type}",
                f"    Wert:      {m.shared_value}",
                f"    Konfidenz: {m.confidence_level}",
                f"    Andere Fälle: {', '.join(m.matching_cases)}",
            ]
            if m.total_btc_involved:
                lines.append(f"    BTC gesamt: {m.total_btc_involved:,.4f} BTC")
            if m.profile_id:
                lines.append(f"    Täter-Profil ID: {m.profile_id}")

        lines += [
            f"\n{'─' * 55}",
            "Empfehlung: Diese Fälle gemeinsam bei den Behörden einreichen.",
            "Serientäter-Verdacht erhöht die Priorität bei Behörden erheblich.",
        ]

        return "\n".join(lines)
