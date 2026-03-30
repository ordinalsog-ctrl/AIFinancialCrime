from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_spend_resolution_cache: dict[tuple[str, int], tuple[str, Optional[str]]] = {}


def _get_tx(txid: str, rpc) -> Optional[dict]:
    """TX via RPC, Fallback Blockstream. Reichert RPC-Daten mit Block-Info an."""
    tx_data = None
    try:
        tx_data = rpc.call("getrawtransaction", [txid, True])
    except Exception:
        pass

    if tx_data is not None:
        if not tx_data.get("blockheight") and not tx_data.get("status"):
            block_hash = tx_data.get("blockhash")
            if block_hash:
                try:
                    block_header = rpc.call("getblockheader", [block_hash])
                    block_height = block_header.get("height") or 0
                    block_time = block_header.get("time") or tx_data.get("blocktime", 0)
                    if block_height:
                        tx_data["blockheight"] = block_height
                        tx_data["status"] = {
                            "confirmed": True,
                            "block_height": block_height,
                            "block_time": block_time,
                        }
                        tx_data.setdefault("blocktime", block_time)
                except Exception:
                    pass

        if not tx_data.get("blockheight") and not tx_data.get("status"):
            try:
                url = f"https://blockstream.info/api/tx/{txid}"
                req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/2.0"})
                with urllib.request.urlopen(req, timeout=10) as response:
                    blockstream_tx = json.loads(response.read())
                if blockstream_tx.get("status", {}).get("confirmed"):
                    tx_data["status"] = blockstream_tx["status"]
                    tx_data.setdefault("blocktime", blockstream_tx["status"].get("block_time", 0))
            except Exception:
                pass
        return tx_data

    for attempt in range(3):
        try:
            if attempt > 0:
                time.sleep(1.5 * attempt)
            url = f"https://blockstream.info/api/tx/{txid}"
            req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/2.0"})
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read())
        except Exception as exc:
            if attempt == 2:
                logger.warning(f"Could not get TX {txid[:16]} after 3 attempts: {exc}")
            else:
                logger.debug(f"TX {txid[:16]} attempt {attempt + 1} failed: {exc}")
    return None


def _get_tx_outputs(tx_data: dict) -> list[tuple[str, float]]:
    """Extrahiert (address, btc) aus TX-Outputs."""
    outputs = []
    for vout in tx_data.get("vout", []):
        addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
        val = vout.get("value", 0)
        btc = val if isinstance(val, float) and val < 100 else val / 1e8
        if addr:
            outputs.append((addr, btc))
    return outputs


def _get_tx_block_info(tx_data: dict) -> tuple[int, str]:
    """Block-Hoehe und Zeitstempel aus TX."""
    block_height = tx_data.get("blockheight", 0) or 0
    block_time = tx_data.get("blocktime", 0)
    status = tx_data.get("status", {})
    if status:
        block_height = status.get("block_height", block_height) or block_height
        block_time = status.get("block_time", block_time) or block_time
    if block_time:
        timestamp = datetime.fromtimestamp(block_time, tz=timezone.utc)
        return block_height, timestamp.strftime("%d.%m.%Y %H:%M UTC")
    return block_height, "—"


def _scan_blocks_for_spend(txid: str, vout_idx: int, spend_block_hint: int, rpc) -> Optional[str]:
    """Fallback ohne externen Spend-Index: scannt Folgebloecke nach dem ausgebenden Input."""
    max_blocks = int(os.environ.get("TRACER_SPEND_SCAN_MAX_BLOCKS", "4000"))
    if spend_block_hint <= 0 or max_blocks <= 0:
        return None

    try:
        tip_height = int(rpc.call("getblockcount", []))
    except Exception as exc:
        logger.debug(f"blockcount lookup failed for spend-scan {txid[:16]}:{vout_idx}: {exc}")
        return None

    end_height = min(tip_height, spend_block_hint + max_blocks)
    for height in range(spend_block_hint + 1, end_height + 1):
        try:
            block_hash = rpc.call("getblockhash", [height])
            block = rpc.call("getblock", [block_hash, 2])
        except Exception as exc:
            logger.debug(f"block scan failed height={height} for {txid[:16]}:{vout_idx}: {exc}")
            continue

        for candidate_tx in block.get("tx", []):
            for vin in candidate_tx.get("vin", []):
                if vin.get("txid") == txid and vin.get("vout") == vout_idx:
                    return candidate_tx.get("txid")

    return None


def _get_spending_info(txid: str, vout_idx: int, rpc) -> tuple[str, Optional[str]]:
    """Findet die ausgebende TX oder liefert einen sauberen Spend-Status."""
    cache_key = (txid, vout_idx)
    if cache_key in _spend_resolution_cache:
        return _spend_resolution_cache[cache_key]

    rpc_confirms_spent = False
    spend_block_hint = 0

    try:
        utxo = rpc.call("gettxout", [txid, vout_idx])
        if utxo is not None:
            result = ("unspent", None)
            _spend_resolution_cache[cache_key] = result
            return result
        rpc_confirms_spent = True
    except Exception as exc:
        logger.debug(f"gettxout failed {txid[:16]}:{vout_idx}: {exc}")

    try:
        tx_data = _get_tx(txid, rpc)
        if tx_data:
            spend_block_hint = int(tx_data.get("blockheight") or tx_data.get("status", {}).get("block_height") or 0)
    except Exception as exc:
        logger.debug(f"getrawtransaction failed for spend-hint {txid[:16]}:{vout_idx}: {exc}")

    try:
        url = f"https://blockstream.info/api/tx/{txid}/outspend/{vout_idx}"
        req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/2.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read())
        if data.get("spent"):
            result = ("spent", data.get("txid"))
            _spend_resolution_cache[cache_key] = result
            return result
        if data.get("spent") is False:
            result = ("unspent", None)
            _spend_resolution_cache[cache_key] = result
            return result
    except Exception as exc:
        logger.debug(f"outspend lookup failed {txid[:16]}:{vout_idx}: {exc}")

    spending_txid = _scan_blocks_for_spend(txid, vout_idx, spend_block_hint, rpc)
    if spending_txid:
        result = ("spent", spending_txid)
        _spend_resolution_cache[cache_key] = result
        return result

    if rpc_confirms_spent:
        result = ("spent_unresolved", None)
        _spend_resolution_cache[cache_key] = result
        return result

    result = ("unknown", None)
    _spend_resolution_cache[cache_key] = result
    return result


def _get_victim_amount_from_inputs(fraud_tx: dict, victim_addresses: set, rpc) -> float:
    """Berechnet den gestohlenen Betrag als Summe der Inputs der Opfer-Adressen."""
    total = 0.0
    for vin in fraud_tx.get("vin", []):
        prevout = vin.get("prevout", {})
        addr = prevout.get("scriptpubkey_address") or prevout.get("scriptPubKey", {}).get("address")
        val = prevout.get("value", 0)

        if not addr or not val:
            prev_txid = vin.get("txid")
            prev_vout_idx = vin.get("vout", 0)
            if prev_txid:
                try:
                    prev_tx = rpc.call("getrawtransaction", [prev_txid, True])
                    if prev_tx and prev_vout_idx < len(prev_tx.get("vout", [])):
                        prev_out = prev_tx["vout"][prev_vout_idx]
                        addr = prev_out.get("scriptPubKey", {}).get("address")
                        val = prev_out.get("value", 0)
                except Exception:
                    pass

        if addr and addr in victim_addresses:
            total += val if isinstance(val, float) else val / 1e8

    return total


def _save_tx_to_db(txid: str, tx_data: dict, conn):
    """Speichert TX in PostgreSQL."""
    try:
        block_height, _ = _get_tx_block_info(tx_data)
        block_hash = tx_data.get("blockhash")
        block_time = tx_data.get("blocktime") or tx_data.get("status", {}).get("block_time")
        first_seen = datetime.fromtimestamp(block_time, tz=timezone.utc) if block_time else None

        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM transactions WHERE txid = %s", (txid,))
            if cur.fetchone():
                return

        with conn.cursor() as cur:
            if block_height and block_hash and first_seen:
                cur.execute(
                    """
                    INSERT INTO blocks (height, hash, timestamp)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (height) DO NOTHING
                    """,
                    (block_height, block_hash, first_seen),
                )
            cur.execute(
                """
                INSERT INTO transactions (txid, block_height, first_seen)
                VALUES (%s, %s, %s) ON CONFLICT (txid) DO NOTHING
                """,
                (txid, block_height or None, first_seen),
            )

            for i, vout in enumerate(tx_data.get("vout", [])):
                addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
                val = vout.get("value", 0)
                sats = int(val * 1e8) if isinstance(val, float) else int(val)
                if addr:
                    cur.execute(
                        """
                        INSERT INTO addresses (address)
                        VALUES (%s)
                        ON CONFLICT (address) DO NOTHING
                        """,
                        (addr,),
                    )
                    cur.execute(
                        """
                        INSERT INTO tx_outputs (txid, vout_index, address, amount_sats)
                        VALUES (%s, %s, %s, %s) ON CONFLICT (txid, vout_index) DO NOTHING
                        """,
                        (txid, i, addr, sats),
                    )

            for vin in tx_data.get("vin", []):
                prev_txid = vin.get("txid")
                prev_vout = vin.get("vout")
                if prev_txid and prev_vout is not None:
                    cur.execute(
                        """
                        UPDATE tx_outputs SET spent_by_txid = %s
                        WHERE txid = %s AND vout_index = %s AND spent_by_txid IS NULL
                        """,
                        (txid, prev_txid, prev_vout),
                    )

        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.warning(f"DB save failed for {txid[:16]}: {exc}")
