from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, TYPE_CHECKING
import json

if TYPE_CHECKING:
    import psycopg
    from psycopg.connection import Connection
else:
    psycopg = Any
    Connection = Any

from afci.config import Settings


@dataclass
class BlockRow:
    height: int
    block_hash: str
    timestamp: datetime


@dataclass
class TxRow:
    txid: str
    block_height: int
    fee_sats: int | None
    vsize: int | None


@dataclass
class TxInputRow:
    txid: str
    vin_index: int
    prev_txid: str | None
    prev_vout: int | None
    address: str | None
    amount_sats: int | None


@dataclass
class TxOutputRow:
    txid: str
    vout_index: int
    address: str | None
    script_type: str | None
    amount_sats: int


def connect(settings: Settings) -> Connection:
    try:
        import psycopg as _psycopg
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "psycopg is required for Postgres ingestion. Install dependencies with `pip install -e .`."
        ) from exc
    return _psycopg.connect(settings.postgres_dsn)


def apply_schema(conn: Connection, schema_path: Path) -> None:
    with conn.cursor() as cur:
        cur.execute(schema_path.read_text())
    conn.commit()


@contextmanager
def tx(conn: Connection) -> Iterator[None]:
    try:
        yield
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()


def upsert_block(cur: psycopg.Cursor, row: BlockRow) -> None:
    cur.execute(
        """
        INSERT INTO blocks (height, hash, timestamp)
        VALUES (%s, %s, %s)
        ON CONFLICT (height)
        DO UPDATE SET hash = EXCLUDED.hash, timestamp = EXCLUDED.timestamp
        """,
        (row.height, row.block_hash, row.timestamp),
    )


def upsert_tx(cur: psycopg.Cursor, row: TxRow) -> None:
    cur.execute(
        """
        INSERT INTO transactions (txid, block_height, fee_sats, vsize)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (txid)
        DO UPDATE SET
          block_height = EXCLUDED.block_height,
          fee_sats = EXCLUDED.fee_sats,
          vsize = EXCLUDED.vsize
        """,
        (row.txid, row.block_height, row.fee_sats, row.vsize),
    )


def upsert_address(cur: psycopg.Cursor, address: str, script_type: str | None) -> None:
    cur.execute(
        """
        INSERT INTO addresses (address, script_type, first_seen, last_seen)
        VALUES (%s, %s, NOW(), NOW())
        ON CONFLICT (address)
        DO UPDATE SET
          script_type = COALESCE(EXCLUDED.script_type, addresses.script_type),
          last_seen = NOW()
        """,
        (address, script_type),
    )


def upsert_tx_input(cur: psycopg.Cursor, row: TxInputRow) -> None:
    cur.execute(
        """
        INSERT INTO tx_inputs (txid, vin_index, prev_txid, prev_vout, address, amount_sats)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (txid, vin_index)
        DO UPDATE SET
          prev_txid = EXCLUDED.prev_txid,
          prev_vout = EXCLUDED.prev_vout,
          address = EXCLUDED.address,
          amount_sats = EXCLUDED.amount_sats
        """,
        (row.txid, row.vin_index, row.prev_txid, row.prev_vout, row.address, row.amount_sats),
    )


def upsert_tx_output(cur: psycopg.Cursor, row: TxOutputRow) -> None:
    cur.execute(
        """
        INSERT INTO tx_outputs (txid, vout_index, address, amount_sats)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (txid, vout_index)
        DO UPDATE SET
          address = EXCLUDED.address,
          amount_sats = EXCLUDED.amount_sats
        """,
        (row.txid, row.vout_index, row.address, row.amount_sats),
    )


def link_spent_outputs_for_tx(cur: psycopg.Cursor, spending_txid: str) -> int:
    cur.execute(
        """
        UPDATE tx_outputs o
        SET spent_by_txid = i.txid
        FROM tx_inputs i
        WHERE i.txid = %s
          AND i.prev_txid = o.txid
          AND i.prev_vout = o.vout_index
          AND (o.spent_by_txid IS DISTINCT FROM i.txid)
        """,
        (spending_txid,),
    )
    return cur.rowcount


def get_ingest_cursor(cur: psycopg.Cursor, cursor_key: str) -> int | None:
    cur.execute("SELECT last_height FROM ingest_cursors WHERE cursor_key = %s", (cursor_key,))
    row = cur.fetchone()
    return int(row[0]) if row else None


def set_ingest_cursor(cur: psycopg.Cursor, cursor_key: str, height: int) -> None:
    cur.execute(
        """
        INSERT INTO ingest_cursors (cursor_key, last_height, updated_at)
        VALUES (%s, %s, %s)
        ON CONFLICT (cursor_key)
        DO UPDATE SET
          last_height = EXCLUDED.last_height,
          updated_at = EXCLUDED.updated_at
        """,
        (cursor_key, height, datetime.now(timezone.utc)),
    )


def insert_risk_assessment(
    cur: psycopg.Cursor,
    *,
    address: str,
    max_hops: int,
    result_limit: int,
    score: float,
    risk_band: str,
    model_name: str,
    model_version: str,
    ruleset_id: str | None,
    ruleset_version: str | None,
    payload: dict[str, Any],
) -> int:
    cur.execute(
        """
        INSERT INTO risk_assessments (
          address, max_hops, result_limit, score, risk_band,
          model_name, model_version, ruleset_id, ruleset_version, payload_json
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
        RETURNING assessment_id
        """,
        (
            address,
            max_hops,
            result_limit,
            score,
            risk_band,
            model_name,
            model_version,
            ruleset_id,
            ruleset_version,
            json.dumps(payload),
        ),
    )
    row = cur.fetchone()
    if not row:
        raise RuntimeError("Failed to persist risk assessment")
    return int(row[0])


def insert_risk_assessment_finding(
    cur: psycopg.Cursor,
    *,
    assessment_id: int,
    finding_type: str,
    reason_code: str,
    base_contribution: float,
    confidence: float,
    effective_contribution: float,
    metadata: dict[str, Any] | None,
) -> None:
    cur.execute(
        """
        INSERT INTO risk_assessment_findings (
          assessment_id, finding_type, reason_code, base_contribution,
          confidence, effective_contribution, metadata_json
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
        """,
        (
            assessment_id,
            finding_type,
            reason_code,
            base_contribution,
            confidence,
            effective_contribution,
            json.dumps(metadata or {}),
        ),
    )
