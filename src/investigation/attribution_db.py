"""
Attribution Database — Models, Repository, and Lookup

Provides:
  - AttributionRecord: normalized result of a lookup
  - AttributionRepository: PostgreSQL-backed store (idempotent upserts)
  - AttributionLookup: high-level interface used by the confidence engine
"""

from __future__ import annotations

import enum
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class EntityType(str, enum.Enum):
    EXCHANGE   = "EXCHANGE"
    DARKNET    = "DARKNET"
    MIXER      = "MIXER"
    SANCTIONED = "SANCTIONED"
    FRAUD      = "FRAUD"
    OTHER      = "OTHER"


class SourceKey(str, enum.Enum):
    MANUAL        = "MANUAL"
    OFAC          = "OFAC"
    BITCOINABUSE  = "BITCOINABUSE"
    WALLETEXPLORER = "WALLETEXPLORER"


# ---------------------------------------------------------------------------
# Attribution Record — returned from any lookup
# ---------------------------------------------------------------------------

@dataclass
class AttributionRecord:
    """
    Normalized attribution result.
    Contains everything the confidence engine and report generator need.
    """
    address: str
    entity_name: str
    entity_type: EntityType
    confidence_level: int          # 1–4 maps to ConfidenceLevel
    is_sanctioned: bool
    source_key: str
    source_display_name: str
    source_url: Optional[str]
    is_authoritative: bool
    abuse_category: Optional[str] = None
    report_count: int = 1
    last_updated_at: Optional[datetime] = None
    raw_source_data: Optional[dict] = None

    @property
    def report_label(self) -> str:
        """Human-readable label for PDF report."""
        base = f"{self.entity_name} ({self.entity_type.value})"
        if self.is_sanctioned:
            base += " ⚠ SANKTIONIERT"
        return base

    @property
    def citation(self) -> str:
        """Citation string for forensic report footnote."""
        parts = [f"Quelle: {self.source_display_name}"]
        if self.source_url:
            parts.append(self.source_url)
        if self.last_updated_at:
            parts.append(f"Stand: {self.last_updated_at.strftime('%Y-%m-%d')}")
        return ", ".join(parts)

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "entity_name": self.entity_name,
            "entity_type": self.entity_type.value,
            "confidence_level": self.confidence_level,
            "is_sanctioned": self.is_sanctioned,
            "source_key": self.source_key,
            "source_display_name": self.source_display_name,
            "source_url": self.source_url,
            "is_authoritative": self.is_authoritative,
            "abuse_category": self.abuse_category,
            "report_count": self.report_count,
            "report_label": self.report_label,
            "citation": self.citation,
        }


# ---------------------------------------------------------------------------
# Repository — PostgreSQL persistence (requires asyncpg or psycopg2)
# ---------------------------------------------------------------------------

class AttributionRepository:
    """
    PostgreSQL-backed attribution store.
    All writes are idempotent. Authoritative sources (OFAC, MANUAL)
    are never overwritten by lower-priority automated scrapers.
    """

    UPSERT_SQL = """
        INSERT INTO address_attributions (
            address, source_id, entity_name, entity_type,
            confidence_level, is_sanctioned, abuse_category,
            report_count, raw_source_data, source_updated_at
        )
        SELECT
            %(address)s,
            s.source_id,
            %(entity_name)s,
            %(entity_type)s,
            s.confidence_level,
            %(is_sanctioned)s,
            %(abuse_category)s,
            %(report_count)s,
            %(raw_source_data)s,
            %(source_updated_at)s
        FROM attribution_sources s
        WHERE s.source_key = %(source_key)s
        ON CONFLICT (address, source_id) DO UPDATE SET
            entity_name       = EXCLUDED.entity_name,
            entity_type       = EXCLUDED.entity_type,
            is_sanctioned     = EXCLUDED.is_sanctioned,
            abuse_category    = EXCLUDED.abuse_category,
            report_count      = EXCLUDED.report_count,
            raw_source_data   = EXCLUDED.raw_source_data,
            source_updated_at = EXCLUDED.source_updated_at,
            last_updated_at   = NOW()
        WHERE NOT (
            SELECT is_authoritative FROM attribution_sources
            WHERE source_key = %(source_key)s
        ) OR %(source_key)s IN ('MANUAL', 'OFAC')
        RETURNING attribution_id;
    """

    LOOKUP_BEST_SQL = """
        SELECT
            address, entity_name, entity_type, confidence_level,
            is_sanctioned, abuse_category, report_count,
            source_key, source_display_name, source_url,
            is_authoritative, last_updated_at, raw_source_data
        FROM address_attribution_best
        WHERE address = %s;
    """

    LOOKUP_ALL_SQL = """
        SELECT
            aa.address, aa.entity_name, aa.entity_type, aa.confidence_level,
            aa.is_sanctioned, aa.abuse_category, aa.report_count,
            s.source_key, s.display_name AS source_display_name,
            s.source_url, s.is_authoritative, aa.last_updated_at,
            aa.raw_source_data
        FROM address_attributions aa
        JOIN attribution_sources s ON aa.source_id = s.source_id
        WHERE aa.address = %s
        ORDER BY s.priority ASC;
    """

    UPDATE_CURSOR_SQL = """
        INSERT INTO attribution_ingest_cursor
            (source_key, last_fetched_at, last_count, last_status, updated_at)
        VALUES (%(source_key)s, NOW(), %(count)s, %(status)s, NOW())
        ON CONFLICT (source_key) DO UPDATE SET
            last_fetched_at = NOW(),
            last_count      = %(count)s,
            last_status     = %(status)s,
            last_error      = %(error)s,
            updated_at      = NOW();
    """

    def __init__(self, conn):
        """
        conn: psycopg2 connection (sync) or asyncpg connection (async).
        For now we use psycopg2 to match the existing project stack.
        """
        self._conn = conn

    def upsert(
        self,
        address: str,
        source_key: str,
        entity_name: str,
        entity_type: str,
        is_sanctioned: bool = False,
        abuse_category: Optional[str] = None,
        report_count: int = 1,
        raw_source_data: Optional[dict] = None,
        source_updated_at: Optional[datetime] = None,
    ) -> Optional[int]:
        """Insert or update one attribution. Returns attribution_id or None."""
        with self._conn.cursor() as cur:
            cur.execute(self.UPSERT_SQL, {
                "address": address,
                "source_key": source_key,
                "entity_name": entity_name,
                "entity_type": entity_type,
                "is_sanctioned": is_sanctioned,
                "abuse_category": abuse_category,
                "report_count": report_count,
                "raw_source_data": json.dumps(raw_source_data) if raw_source_data else None,
                "source_updated_at": source_updated_at,
            })
            row = cur.fetchone()
            return row[0] if row else None

    def bulk_upsert(self, records: list[dict]) -> int:
        """Bulk upsert for ingestion jobs. Returns count of processed rows."""
        count = 0
        for rec in records:
            try:
                self.upsert(**rec)
                count += 1
            except Exception as e:
                logger.warning(f"Upsert failed for {rec.get('address')}: {e}")
        self._conn.commit()
        return count

    def lookup_best(self, address: str) -> Optional[AttributionRecord]:
        """Return the highest-priority attribution for an address."""
        with self._conn.cursor() as cur:
            cur.execute(self.LOOKUP_BEST_SQL, (address,))
            row = cur.fetchone()
            return self._row_to_record(row) if row else None

    def lookup_all(self, address: str) -> list[AttributionRecord]:
        """Return all attributions for an address across all sources."""
        with self._conn.cursor() as cur:
            cur.execute(self.LOOKUP_ALL_SQL, (address,))
            return [self._row_to_record(r) for r in cur.fetchall()]

    def update_cursor(
        self,
        source_key: str,
        count: int,
        status: str = "OK",
        error: Optional[str] = None,
    ) -> None:
        with self._conn.cursor() as cur:
            cur.execute(self.UPDATE_CURSOR_SQL, {
                "source_key": source_key,
                "count": count,
                "status": status,
                "error": error,
            })
        self._conn.commit()

    @staticmethod
    def _row_to_record(row) -> AttributionRecord:
        (address, entity_name, entity_type, confidence_level,
         is_sanctioned, abuse_category, report_count,
         source_key, source_display_name, source_url,
         is_authoritative, last_updated_at, raw_source_data) = row

        return AttributionRecord(
            address=address,
            entity_name=entity_name,
            entity_type=EntityType(entity_type),
            confidence_level=confidence_level,
            is_sanctioned=is_sanctioned,
            source_key=source_key,
            source_display_name=source_display_name,
            source_url=source_url,
            is_authoritative=is_authoritative,
            abuse_category=abuse_category,
            report_count=report_count or 1,
            last_updated_at=last_updated_at,
            raw_source_data=raw_source_data,
        )


# ---------------------------------------------------------------------------
# High-level lookup — used by confidence engine
# ---------------------------------------------------------------------------

class AttributionLookup:
    """
    Thin wrapper around AttributionRepository.
    This is what the confidence engine calls — one method, clean result.
    """

    def __init__(self, repo: AttributionRepository):
        self._repo = repo

    def lookup(self, address: str) -> Optional[AttributionRecord]:
        """
        Returns best attribution for address, or None if unknown.
        Used in build_exchange_hop() to auto-detect exchange addresses.
        """
        return self._repo.lookup_best(address)

    def is_sanctioned(self, address: str) -> bool:
        """Quick OFAC check — used as pre-flight in every tracing run."""
        rec = self._repo.lookup_best(address)
        return rec.is_sanctioned if rec else False

    def get_exchange_name(self, address: str) -> Optional[str]:
        """Returns exchange name if address is a known exchange deposit address."""
        rec = self._repo.lookup_best(address)
        if rec and rec.entity_type == EntityType.EXCHANGE:
            return rec.entity_name
        return None
