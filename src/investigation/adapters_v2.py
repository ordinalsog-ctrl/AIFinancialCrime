"""
Blockchain Data Adapter

Abstract interface over three data sources:
  1. BlockstreamAdapter  — live API (blockstream.info), no node needed
  2. FixtureAdapter      — local JSON fixtures, works offline / CI
  3. PostgresAdapter     — your ingested PostgreSQL DB (production)

All adapters implement the same BlockchainAdapter protocol.
The TraceEngine is adapter-agnostic — swap one line to switch sources.

Usage:
    # Development / testing (no node)
    adapter = BlockstreamAdapter()

    # Offline / CI
    adapter = FixtureAdapter("eval/fixtures/")

    # Production (Bitcoin Core ingested)
    adapter = PostgresAdapter(conn)

    # Auto-fallback
    adapter = AdapterChain([BlockstreamAdapter(), FixtureAdapter("eval/fixtures/")])
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

BLOCKSTREAM_BASE = "https://blockstream.info/api"
REQUEST_TIMEOUT  = 15
RATE_LIMIT_SEC   = 0.5   # 2 req/sec — respectful to public API


# ---------------------------------------------------------------------------
# Shared data models (adapter-agnostic)
# ---------------------------------------------------------------------------

class TxData:
    """Normalized transaction data — same shape regardless of source."""

    def __init__(
        self,
        txid: str,
        block_height: Optional[int],
        block_time: Optional[int],
        input_count: int,
        output_count: int,
        inputs: list[dict],   # [{txid, vout, address, value_sat}]
        outputs: list[dict],  # [{n, address, value_sat, spent_by_txid}]
        fee_sat: int = 0,
    ):
        self.txid         = txid
        self.block_height = block_height
        self.block_time   = block_time
        self.input_count  = input_count
        self.output_count = output_count
        self.inputs       = inputs
        self.outputs      = outputs
        self.fee_sat      = fee_sat

    @property
    def confirmed(self) -> bool:
        return self.block_height is not None

    @property
    def timestamp(self) -> Optional[datetime]:
        if self.block_time:
            return datetime.fromtimestamp(self.block_time, tz=timezone.utc)
        return None

    @property
    def total_output_sat(self) -> int:
        return sum(o["value_sat"] for o in self.outputs)

    @property
    def total_output_btc(self) -> Decimal:
        return Decimal(self.total_output_sat) / Decimal("100000000")

    @property
    def dominant_output(self) -> Optional[dict]:
        """Largest output — used for peeling chain analysis."""
        return max(self.outputs, key=lambda o: o["value_sat"]) if self.outputs else None

    def to_dict(self) -> dict:
        return {
            "txid": self.txid,
            "block_height": self.block_height,
            "block_time": self.block_time,
            "input_count": self.input_count,
            "output_count": self.output_count,
            "total_output_sat": self.total_output_sat,
            "fee_sat": self.fee_sat,
            "inputs": self.inputs,
            "outputs": self.outputs,
        }


# ---------------------------------------------------------------------------
# Abstract protocol
# ---------------------------------------------------------------------------

class BlockchainAdapter(ABC):
    """
    All adapters implement this interface.
    TraceEngine depends only on this, never on a concrete adapter.
    """

    @abstractmethod
    def get_tx(self, txid: str) -> Optional[TxData]:
        """Fetch full transaction data."""
        ...

    @abstractmethod
    def get_address_txids(self, address: str, limit: int = 25) -> list[str]:
        """List recent TX IDs for an address."""
        ...

    def get_spending_tx(self, txid: str, vout: int) -> Optional[str]:
        """
        Find the TX that spends output vout of txid.
        Default implementation: scan address TXs (override for efficiency).
        """
        tx = self.get_tx(txid)
        if not tx:
            return None
        for output in tx.outputs:
            if output.get("n") == vout:
                spent_by = output.get("spent_by_txid")
                return spent_by
        return None

    def trace_hops(
        self,
        start_txid: str,
        max_hops: int = 5,
    ) -> list[TxData]:
        """
        Follow the dominant output chain from start_txid.
        Returns ordered list of TxData objects (start TX first).
        """
        result = []
        current_txid = start_txid
        visited = set()

        for _ in range(max_hops + 1):
            if current_txid in visited:
                break
            visited.add(current_txid)

            tx = self.get_tx(current_txid)
            if not tx:
                logger.warning(f"TX not found: {current_txid}")
                break

            result.append(tx)

            # Follow dominant output
            dominant = tx.dominant_output
            if not dominant:
                break

            spent_by = dominant.get("spent_by_txid")
            if not spent_by:
                logger.info(f"Output unspent at {current_txid} — chain ends here.")
                break

            current_txid = spent_by

        return result


# ---------------------------------------------------------------------------
# 1. Blockstream Adapter — live public API
# ---------------------------------------------------------------------------

class BlockstreamAdapter(BlockchainAdapter):
    """
    Uses blockstream.info public API.
    No API key required. Rate limit: ~2 req/sec.
    Suitable for: development, investigation of specific TXs.
    Not suitable for: bulk ingestion.
    """

    def __init__(self, base_url: str = BLOCKSTREAM_BASE):
        self._base = base_url
        self._last_request = 0.0

    def _get(self, path: str) -> Optional[dict]:
        self._rate_limit()
        url = f"{self._base}{path}"
        req = Request(url, headers={
            "User-Agent": "AIFinancialCrime/1.0 (forensic research)"
        })
        try:
            with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return json.loads(resp.read())
        except URLError as e:
            logger.error(f"Blockstream API error [{path}]: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error [{path}]: {e}")
            return None

    def _rate_limit(self):
        elapsed = time.time() - self._last_request
        if elapsed < RATE_LIMIT_SEC:
            time.sleep(RATE_LIMIT_SEC - elapsed)
        self._last_request = time.time()

    def get_tx(self, txid: str) -> Optional[TxData]:
        data = self._get(f"/tx/{txid}")
        if not data:
            return None
        return self._parse_tx(data)

    def get_address_txids(self, address: str, limit: int = 25) -> list[str]:
        data = self._get(f"/address/{address}/txs")
        if not data:
            return []
        return [tx["txid"] for tx in data[:limit]]

    def get_spending_tx(self, txid: str, vout: int) -> Optional[str]:
        data = self._get(f"/tx/{txid}/outspend/{vout}")
        if not data or not data.get("spent"):
            return None
        return data.get("txid")

    def _parse_tx(self, data: dict) -> TxData:
        status = data.get("status", {})
        block_height = status.get("block_height")
        block_time   = status.get("block_time")

        inputs = []
        for vin in data.get("vin", []):
            prevout = vin.get("prevout") or {}
            inputs.append({
                "txid":      vin.get("txid"),
                "vout":      vin.get("vout"),
                "address":   prevout.get("scriptpubkey_address"),
                "value_sat": prevout.get("value", 0),
            })

        outputs = []
        for vout in data.get("vout", []):
            outputs.append({
                "n":            vout.get("n", 0),
                "address":      vout.get("scriptpubkey_address"),
                "value_sat":    vout.get("value", 0),
                "spent_by_txid": None,  # requires separate outspend call
            })

        return TxData(
            txid=data["txid"],
            block_height=block_height,
            block_time=block_time,
            input_count=len(inputs),
            output_count=len(outputs),
            inputs=inputs,
            outputs=outputs,
            fee_sat=data.get("fee", 0),
        )


# ---------------------------------------------------------------------------
# 2. Fixture Adapter — local JSON, works offline
# ---------------------------------------------------------------------------

class FixtureAdapter(BlockchainAdapter):
    """
    Loads TX data from local JSON fixture files.
    Fixture format: one JSON file per TX, named {txid}.json
    Also supports a fixtures index file: index.json

    Use for: CI/CD, offline testing, known fraud case replays.
    """

    def __init__(self, fixture_dir: str = "eval/fixtures"):
        self._dir = Path(fixture_dir)
        self._cache: dict[str, TxData] = {}
        self._addr_index: dict[str, list[str]] = {}
        self._load_all()

    def _load_all(self):
        if not self._dir.exists():
            logger.warning(f"Fixture dir not found: {self._dir}")
            return

        for path in self._dir.glob("*.json"):
            if path.stem == "index":
                continue
            try:
                with open(path) as f:
                    raw = json.load(f)
                # Skip non-TX fixtures (attribution lists, policy files, etc.)
                if not isinstance(raw, dict) or "txid" not in raw:
                    logger.debug(f"Skipping non-TX fixture: {path.name}")
                    continue
                tx = self._from_fixture(raw)
                self._cache[tx.txid] = tx

                # Build address index
                for inp in tx.inputs:
                    addr = inp.get("address")
                    if addr:
                        self._addr_index.setdefault(addr, []).append(tx.txid)
                for out in tx.outputs:
                    addr = out.get("address")
                    if addr:
                        self._addr_index.setdefault(addr, []).append(tx.txid)

            except Exception as e:
                logger.warning(f"Failed to load fixture {path}: {e}")

        logger.info(f"FixtureAdapter: loaded {len(self._cache)} transactions.")

    def get_tx(self, txid: str) -> Optional[TxData]:
        return self._cache.get(txid)

    def get_address_txids(self, address: str, limit: int = 25) -> list[str]:
        return self._addr_index.get(address, [])[:limit]

    @staticmethod
    def _from_fixture(raw: dict) -> TxData:
        """Load from our own fixture format (same as TxData.to_dict())."""
        return TxData(
            txid=raw["txid"],
            block_height=raw.get("block_height"),
            block_time=raw.get("block_time"),
            input_count=raw.get("input_count", len(raw.get("inputs", []))),
            output_count=raw.get("output_count", len(raw.get("outputs", []))),
            inputs=raw.get("inputs", []),
            outputs=raw.get("outputs", []),
            fee_sat=raw.get("fee_sat", 0),
        )

    @classmethod
    def save_fixture(cls, tx: TxData, fixture_dir: str = "eval/fixtures"):
        """Save a TxData to fixture file — use after fetching from Blockstream."""
        path = Path(fixture_dir)
        path.mkdir(parents=True, exist_ok=True)
        with open(path / f"{tx.txid}.json", "w") as f:
            json.dump(tx.to_dict(), f, indent=2)
        logger.info(f"Fixture saved: {tx.txid}.json")


# ---------------------------------------------------------------------------
# 3. Postgres Adapter — wraps your existing TraceEngine
# ---------------------------------------------------------------------------

class PostgresAdapter(BlockchainAdapter):
    """
    Production adapter — queries your ingested PostgreSQL tables.
    Wraps the existing TraceEngine SQL queries.
    """

    TX_META_SQL = """
        SELECT t.txid, t.block_height, t.block_time,
               COUNT(DISTINCT i.input_index) AS input_count,
               COUNT(DISTINCT o.vout) AS output_count
        FROM transactions t
        LEFT JOIN tx_inputs  i ON i.txid = t.txid
        LEFT JOIN tx_outputs o ON o.txid = t.txid
        WHERE t.txid = %s
        GROUP BY t.txid, t.block_height, t.block_time;
    """

    TX_INPUTS_SQL = """
        SELECT prev_txid, prev_vout, address, value_sat
        FROM tx_inputs WHERE txid = %s ORDER BY input_index;
    """

    TX_OUTPUTS_SQL = """
        SELECT vout, address, value_sat, spent_by_txid
        FROM tx_outputs WHERE txid = %s ORDER BY vout;
    """

    ADDRESS_TXS_SQL = """
        SELECT DISTINCT txid FROM tx_outputs
        WHERE address = %s
        ORDER BY txid LIMIT %s;
    """

    def __init__(self, conn):
        self._conn = conn

    def get_tx(self, txid: str) -> Optional[TxData]:
        with self._conn.cursor() as cur:
            cur.execute(self.TX_META_SQL, (txid,))
            row = cur.fetchone()
            if not row:
                return None
            tx_txid, block_height, block_time, input_count, output_count = row

            cur.execute(self.TX_INPUTS_SQL, (txid,))
            inputs = [{"txid": r[0], "vout": r[1], "address": r[2], "value_sat": r[3]}
                      for r in cur.fetchall()]

            cur.execute(self.TX_OUTPUTS_SQL, (txid,))
            outputs = [{"n": r[0], "address": r[1], "value_sat": r[2], "spent_by_txid": r[3]}
                       for r in cur.fetchall()]

        return TxData(
            txid=tx_txid,
            block_height=block_height,
            block_time=block_time,
            input_count=input_count or len(inputs),
            output_count=output_count or len(outputs),
            inputs=inputs,
            outputs=outputs,
        )

    def get_address_txids(self, address: str, limit: int = 25) -> list[str]:
        with self._conn.cursor() as cur:
            cur.execute(self.ADDRESS_TXS_SQL, (address, limit))
            return [r[0] for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# 4. AdapterChain — automatic fallback
# ---------------------------------------------------------------------------

class AdapterChain(BlockchainAdapter):
    """
    Tries adapters in order — falls back to next on failure.
    Example: [BlockstreamAdapter(), FixtureAdapter("eval/fixtures/")]
    """

    def __init__(self, adapters: list[BlockchainAdapter]):
        self._adapters = adapters

    def get_tx(self, txid: str) -> Optional[TxData]:
        for adapter in self._adapters:
            result = adapter.get_tx(txid)
            if result:
                return result
        return None

    def get_address_txids(self, address: str, limit: int = 25) -> list[str]:
        for adapter in self._adapters:
            result = adapter.get_address_txids(address, limit)
            if result:
                return result
        return []
