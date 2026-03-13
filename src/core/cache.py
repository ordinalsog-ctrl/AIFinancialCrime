"""
AIFinancialCrime — Redis Caching Layer
=======================================
Transparenter Cache-Decorator für alle teuren I/O-Operationen:

  1. CachedBlockchainAdapter  — wraps BlockchainAdapter (Blockstream / RPC)
       - get_tx:               TTL 1h   (Transaktionen sind immutable)
       - get_address_txids:    TTL 5min (neue TXs können ankommen)
       - get_spending_tx:      TTL 1h

  2. CachedAttributionDB      — wraps AttributionRepository.lookup_best()
       - lookup_best:          TTL 24h  (Attribution ändert sich selten)
       - batch UTXO-Lookup:    100 parallel (redis pipeline)

  3. cache_result decorator    — generischer Function-Cache via @cache_result(ttl=...)

Design-Prinzipien:
  - Fail-open: wenn Redis nicht erreichbar → direkt an Backend
  - Key-Namespacing: "aifc:tx:<txid>", "aifc:addr:<addr>", "aifc:attr:<addr>"
  - Serialisierung: JSON (human-readable, debuggable)
  - Keine Binär-Abhängigkeiten: läuft auch ohne Redis (graceful degradation)
  - Metrics: Cache Hit/Miss Rate wird an Prometheus gemeldet

Konfiguration (Umgebungsvariablen):
    REDIS_URL=redis://localhost:6379/0   (default)
    REDIS_MAX_CONNECTIONS=20
    REDIS_SOCKET_TIMEOUT=1.0            (schnell scheitern, nicht blockieren)
    CACHE_TX_TTL=3600                   (1h)
    CACHE_ADDR_TTL=300                  (5min)
    CACHE_ATTR_TTL=86400                (24h)

Verwendung:
    from src.core.cache import CachedBlockchainAdapter, CachedAttributionDB

    base_adapter = BlockstreamAdapter()
    adapter = CachedBlockchainAdapter(base_adapter)  # drop-in replacement

    base_repo = AttributionRepository(conn)
    repo = CachedAttributionDB(base_repo)            # drop-in replacement
"""

from __future__ import annotations

import functools
import json
import logging
import os
import time
from typing import Any, Callable, Optional, TypeVar

from src.core.logging_config import get_logger
from src.core.metrics import metrics

logger = get_logger("aifc.cache")

F = TypeVar("F", bound=Callable[..., Any])

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

REDIS_URL             = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
REDIS_MAX_CONNECTIONS = int(os.environ.get("REDIS_MAX_CONNECTIONS", "20"))
REDIS_SOCKET_TIMEOUT  = float(os.environ.get("REDIS_SOCKET_TIMEOUT", "1.0"))

TTL_TX   = int(os.environ.get("CACHE_TX_TTL",   "3600"))    # 1h — immutable
TTL_ADDR = int(os.environ.get("CACHE_ADDR_TTL", "300"))     # 5min — neue TXs
TTL_ATTR = int(os.environ.get("CACHE_ATTR_TTL", "86400"))   # 24h — Attribution
TTL_GENERIC = int(os.environ.get("CACHE_GENERIC_TTL", "600"))  # 10min default

# Key-Namespacing
NS_TX   = "aifc:tx:"
NS_ADDR = "aifc:addr:"
NS_ATTR = "aifc:attr:"
NS_SPENDING = "aifc:spending:"

BATCH_SIZE = 100  # Redis pipeline batch size


# ---------------------------------------------------------------------------
# Redis-Verbindung (lazy, singleton)
# ---------------------------------------------------------------------------

_redis_client = None
_redis_available = None  # None = ungetestet, True/False = bekannt


def _get_redis():
    """
    Gibt Redis-Client zurück. Lazy-init, Fail-open.
    Returns None wenn Redis nicht verfügbar.
    """
    global _redis_client, _redis_available

    if _redis_available is False:
        return None

    if _redis_client is not None:
        return _redis_client

    try:
        import redis
        pool = redis.ConnectionPool.from_url(
            REDIS_URL,
            max_connections=REDIS_MAX_CONNECTIONS,
            socket_timeout=REDIS_SOCKET_TIMEOUT,
            socket_connect_timeout=REDIS_SOCKET_TIMEOUT,
            decode_responses=True,
        )
        client = redis.Redis(connection_pool=pool)
        client.ping()  # Verbindung testen
        _redis_client = client
        _redis_available = True
        logger.info("redis_connected", url=REDIS_URL)
        return _redis_client

    except ImportError:
        logger.warning("redis_not_installed",
                       hint="pip install redis — running without cache")
        _redis_available = False
        return None

    except Exception as e:
        logger.warning("redis_unavailable", error=str(e),
                       hint="Running without cache (fail-open)")
        _redis_available = False
        return None


def flush_cache(pattern: str = "aifc:*") -> int:
    """Löscht alle aifc: Cache-Keys. Für Tests und Deployment."""
    r = _get_redis()
    if not r:
        return 0
    keys = r.keys(pattern)
    if keys:
        return r.delete(*keys)
    return 0


def cache_stats() -> dict:
    """Cache-Statistiken für Health-Endpoint."""
    r = _get_redis()
    if not r:
        return {"available": False}
    try:
        info = r.info("stats")
        key_count = len(r.keys("aifc:*"))
        return {
            "available":   True,
            "key_count":   key_count,
            "hits":        info.get("keyspace_hits", 0),
            "misses":      info.get("keyspace_misses", 0),
            "hit_rate":    _hit_rate(
                info.get("keyspace_hits", 0),
                info.get("keyspace_misses", 0)
            ),
        }
    except Exception as e:
        return {"available": True, "error": str(e)}


def _hit_rate(hits: int, misses: int) -> float:
    total = hits + misses
    return round(hits / total, 4) if total > 0 else 0.0


# ---------------------------------------------------------------------------
# Generischer Decorator
# ---------------------------------------------------------------------------

def cache_result(
    ttl: int = TTL_GENERIC,
    key_prefix: str = "aifc:fn:",
    skip_none: bool = True,
):
    """
    Decorator: cached den Return-Value einer Funktion in Redis.

    Args:
        ttl:        TTL in Sekunden
        key_prefix: Redis Key Prefix
        skip_none:  Wenn True, wird None nicht gecacht (re-fetch bei Miss)

    Beispiel:
        @cache_result(ttl=3600, key_prefix="aifc:blockstream:")
        def get_tx(txid: str) -> Optional[TxData]: ...
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            r = _get_redis()
            if not r:
                return func(*args, **kwargs)

            # Cache-Key aus Funktionsname + Argumenten
            key_parts = [key_prefix + func.__name__]
            key_parts.extend(str(a) for a in args[1:])  # args[0] = self
            key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
            cache_key = ":".join(key_parts)

            try:
                cached = r.get(cache_key)
                if cached is not None:
                    metrics.cache_hit(namespace=key_prefix)
                    return json.loads(cached)
            except Exception as e:
                logger.debug("cache_read_error", key=cache_key, error=str(e))

            result = func(*args, **kwargs)

            if result is not None or not skip_none:
                try:
                    r.setex(cache_key, ttl, json.dumps(result, default=str))
                except Exception as e:
                    logger.debug("cache_write_error", key=cache_key, error=str(e))

            metrics.cache_miss(namespace=key_prefix)
            return result

        return wrapper  # type: ignore
    return decorator


# ---------------------------------------------------------------------------
# 1. CachedBlockchainAdapter
# ---------------------------------------------------------------------------

class CachedBlockchainAdapter:
    """
    Drop-in Ersatz für jeden BlockchainAdapter.
    Wraps beliebigen BlockchainAdapter und cached alle Calls.

    Beispiel:
        adapter = CachedBlockchainAdapter(BlockstreamAdapter())
        # Verhält sich exakt wie BlockstreamAdapter, aber mit Cache
    """

    def __init__(self, backend, tx_ttl: int = TTL_TX, addr_ttl: int = TTL_ADDR):
        self._backend  = backend
        self._tx_ttl   = tx_ttl
        self._addr_ttl = addr_ttl

    # --- get_tx ---

    def get_tx(self, txid: str):
        """Fetch TX — cached 1h (Transaktionen sind immutable)."""
        r = _get_redis()
        if not r:
            return self._backend.get_tx(txid)

        key = NS_TX + txid
        try:
            cached = r.get(key)
            if cached:
                metrics.cache_hit(namespace="tx")
                logger.debug("cache_hit_tx", txid=txid[:16])
                data = json.loads(cached)
                return self._dict_to_txdata(data)
        except Exception as e:
            logger.debug("cache_read_error", key=key, error=str(e))

        metrics.cache_miss(namespace="tx")
        result = self._backend.get_tx(txid)
        if result:
            try:
                r.setex(key, self._tx_ttl, json.dumps(self._txdata_to_dict(result)))
            except Exception as e:
                logger.debug("cache_write_error", key=key, error=str(e))

        return result

    # --- get_address_txids ---

    def get_address_txids(self, address: str, limit: int = 25) -> list[str]:
        """Fetch Address TXIDs — cached 5min (neue TXs können ankommen)."""
        r = _get_redis()
        if not r:
            return self._backend.get_address_txids(address, limit)

        key = NS_ADDR + address + f":{limit}"
        try:
            cached = r.get(key)
            if cached:
                metrics.cache_hit(namespace="addr")
                return json.loads(cached)
        except Exception as e:
            logger.debug("cache_read_error", key=key, error=str(e))

        metrics.cache_miss(namespace="addr")
        result = self._backend.get_address_txids(address, limit)
        if result is not None:
            try:
                r.setex(key, self._addr_ttl, json.dumps(result))
            except Exception as e:
                logger.debug("cache_write_error", key=key, error=str(e))

        return result

    # --- get_spending_tx ---

    def get_spending_tx(self, txid: str, vout: int) -> Optional[str]:
        """Fetch spending TX — cached 1h."""
        r = _get_redis()
        if not r:
            return self._backend.get_spending_tx(txid, vout)

        key = NS_SPENDING + txid + f":{vout}"
        try:
            cached = r.get(key)
            if cached:
                metrics.cache_hit(namespace="spending")
                val = json.loads(cached)
                return val if val != "__none__" else None
        except Exception as e:
            logger.debug("cache_read_error", key=key, error=str(e))

        metrics.cache_miss(namespace="spending")
        result = self._backend.get_spending_tx(txid, vout)
        try:
            # Cache auch None (mit Sentinel) damit wir nicht immer fetchen
            store_val = result if result is not None else "__none__"
            r.setex(key, self._tx_ttl, json.dumps(store_val))
        except Exception as e:
            logger.debug("cache_write_error", key=key, error=str(e))

        return result

    # --- Batch UTXO Lookup (100 parallel) ---

    def batch_get_tx(self, txids: list[str]) -> dict[str, Any]:
        """
        Holt mehrere Transaktionen parallel via Redis Pipeline.
        Cache-Misses werden einzeln vom Backend geholt.

        Returns: {txid: TxData | None}
        """
        if not txids:
            return {}

        r = _get_redis()
        results: dict[str, Any] = {}

        if not r:
            for txid in txids:
                results[txid] = self._backend.get_tx(txid)
            return results

        # Batch-Lookup in Redis-Batches à BATCH_SIZE
        cache_misses: list[str] = []

        for i in range(0, len(txids), BATCH_SIZE):
            batch = txids[i:i + BATCH_SIZE]
            keys = [NS_TX + txid for txid in batch]

            try:
                pipe = r.pipeline(transaction=False)
                for key in keys:
                    pipe.get(key)
                cached_values = pipe.execute()

                for txid, cached in zip(batch, cached_values):
                    if cached:
                        metrics.cache_hit(namespace="tx_batch")
                        data = json.loads(cached)
                        results[txid] = self._dict_to_txdata(data)
                    else:
                        cache_misses.append(txid)

            except Exception as e:
                logger.debug("cache_pipeline_error", error=str(e))
                cache_misses.extend(batch)

        # Cache-Misses vom Backend holen + in Cache schreiben
        for txid in cache_misses:
            metrics.cache_miss(namespace="tx_batch")
            tx = self._backend.get_tx(txid)
            results[txid] = tx
            if tx:
                try:
                    r.setex(NS_TX + txid, self._tx_ttl,
                            json.dumps(self._txdata_to_dict(tx)))
                except Exception:
                    pass

        return results

    # --- Serialisierung ---

    @staticmethod
    def _txdata_to_dict(tx) -> dict:
        """TxData → JSON-serialisierbares Dict."""
        return {
            "txid":    tx.txid,
            "inputs":  [
                {"txid": inp.txid, "vout": inp.vout, "address": inp.address,
                 "value_sat": inp.value_sat}
                for inp in (tx.inputs or [])
            ],
            "outputs": [
                {"vout": out.vout, "address": out.address, "value_sat": out.value_sat,
                 "script_type": out.script_type}
                for out in (tx.outputs or [])
            ],
            "block_height": tx.block_height,
            "timestamp":    tx.timestamp,
            "fee_sat":      tx.fee_sat,
        }

    @staticmethod
    def _dict_to_txdata(data: dict):
        """JSON Dict → TxData (lazy import um Zirkelimporte zu vermeiden)."""
        from src.investigation.adapters_v2 import TxData, TxInput, TxOutput
        inputs = [
            TxInput(
                txid=inp["txid"], vout=inp["vout"],
                address=inp.get("address"), value_sat=inp.get("value_sat")
            )
            for inp in data.get("inputs", [])
        ]
        outputs = [
            TxOutput(
                vout=out["vout"], address=out.get("address"),
                value_sat=out.get("value_sat"), script_type=out.get("script_type")
            )
            for out in data.get("outputs", [])
        ]
        return TxData(
            txid=data["txid"],
            inputs=inputs,
            outputs=outputs,
            block_height=data.get("block_height"),
            timestamp=data.get("timestamp"),
            fee_sat=data.get("fee_sat"),
        )

    # Delegate alle anderen Methoden ans Backend (falls vorhanden)
    def __getattr__(self, name):
        return getattr(self._backend, name)


# ---------------------------------------------------------------------------
# 2. CachedAttributionDB
# ---------------------------------------------------------------------------

class CachedAttributionDB:
    """
    Drop-in Ersatz für AttributionRepository.
    Cached lookup_best() für 24h — Attribution ändert sich selten.

    Cache wird invalidiert wenn:
    - Ein neuer Upsert für die Adresse stattfindet (write-through)
    - TTL abläuft (24h)
    - flush_cache() aufgerufen wird
    """

    def __init__(self, backend, attr_ttl: int = TTL_ATTR):
        self._backend  = backend
        self._attr_ttl = attr_ttl

    def lookup_best(self, address: str):
        """Lookup mit 24h Cache."""
        r = _get_redis()
        if not r:
            return self._backend.lookup_best(address)

        key = NS_ATTR + address
        try:
            cached = r.get(key)
            if cached:
                metrics.cache_hit(namespace="attr")
                data = json.loads(cached)
                if data == "__none__":
                    return None
                return self._dict_to_record(data)
        except Exception as e:
            logger.debug("cache_read_error", key=key, error=str(e))

        metrics.cache_miss(namespace="attr")
        result = self._backend.lookup_best(address)

        try:
            store = "__none__" if result is None else json.dumps(
                self._record_to_dict(result))
            r.setex(key, self._attr_ttl, store)
        except Exception as e:
            logger.debug("cache_write_error", key=key, error=str(e))

        return result

    def batch_lookup(self, addresses: list[str]) -> dict[str, Any]:
        """
        Holt Attribution für mehrere Adressen parallel via Redis Pipeline.
        Returns: {address: AttributionRecord | None}
        """
        if not addresses:
            return {}

        r = _get_redis()
        results: dict[str, Any] = {}

        if not r:
            for addr in addresses:
                results[addr] = self._backend.lookup_best(addr)
            return results

        cache_misses: list[str] = []

        for i in range(0, len(addresses), BATCH_SIZE):
            batch = addresses[i:i + BATCH_SIZE]
            keys = [NS_ATTR + addr for addr in batch]

            try:
                pipe = r.pipeline(transaction=False)
                for key in keys:
                    pipe.get(key)
                cached_values = pipe.execute()

                for addr, cached in zip(batch, cached_values):
                    if cached:
                        metrics.cache_hit(namespace="attr_batch")
                        data = json.loads(cached)
                        results[addr] = None if data == "__none__" else \
                            self._dict_to_record(data)
                    else:
                        cache_misses.append(addr)

            except Exception as e:
                logger.debug("cache_pipeline_error", error=str(e))
                cache_misses.extend(batch)

        # Misses vom Backend
        for addr in cache_misses:
            metrics.cache_miss(namespace="attr_batch")
            rec = self._backend.lookup_best(addr)
            results[addr] = rec
            try:
                store = "__none__" if rec is None else json.dumps(
                    self._record_to_dict(rec))
                r.setex(NS_ATTR + addr, self._attr_ttl, store)
            except Exception:
                pass

        return results

    def upsert(self, address: str, *args, **kwargs):
        """Write-through: upsert + Cache invalidieren."""
        result = self._backend.upsert(address, *args, **kwargs)
        r = _get_redis()
        if r:
            try:
                r.delete(NS_ATTR + address)
            except Exception:
                pass
        return result

    def bulk_upsert(self, records: list[dict]) -> int:
        """Write-through bulk upsert."""
        result = self._backend.bulk_upsert(records)
        r = _get_redis()
        if r and records:
            try:
                keys = [NS_ATTR + rec["address"] for rec in records
                        if "address" in rec]
                if keys:
                    # Pipeline für Batch-Delete
                    pipe = r.pipeline(transaction=False)
                    for key in keys:
                        pipe.delete(key)
                    pipe.execute()
            except Exception:
                pass
        return result

    @staticmethod
    def _record_to_dict(rec) -> dict:
        return {
            "address":                rec.address,
            "entity_name":            rec.entity_name,
            "entity_type":            rec.entity_type,
            "source_key":             rec.source_key,
            "source_confidence_level": rec.source_confidence_level,
            "is_sanctioned":          rec.is_sanctioned,
            "abuse_category":         rec.abuse_category,
        }

    @staticmethod
    def _dict_to_record(data: dict):
        from src.investigation.attribution_db import AttributionRecord
        return AttributionRecord(
            address=data["address"],
            entity_name=data["entity_name"],
            entity_type=data["entity_type"],
            source_key=data["source_key"],
            source_confidence_level=data.get("source_confidence_level", 50),
            is_sanctioned=data.get("is_sanctioned", False),
            abuse_category=data.get("abuse_category"),
        )

    def __getattr__(self, name):
        return getattr(self._backend, name)


# ---------------------------------------------------------------------------
# Factory: get_cached_adapter()
# ---------------------------------------------------------------------------

def get_cached_adapter(backend=None) -> CachedBlockchainAdapter:
    """
    Erstellt einen gecachten Blockchain-Adapter.
    Wenn kein Backend angegeben, wird BlockstreamAdapter verwendet.
    """
    if backend is None:
        from src.investigation.adapters_v2 import BlockstreamAdapter
        backend = BlockstreamAdapter()
    return CachedBlockchainAdapter(backend)


def get_cached_repo(conn) -> CachedAttributionDB:
    """Erstellt einen gecachten AttributionRepository."""
    from src.investigation.attribution_db import AttributionRepository
    return CachedAttributionDB(AttributionRepository(conn))
