"""
AIFinancialCrime — Report Endpoint v4
======================================
FOKUSSIERTER ANALYSE-FLOW

Prinzip: NUR der direkte Pfad des gestohlenen Geldes wird verfolgt.

Flow:
  1. User wählt seine Opfer-Adressen (Inputs der Fraud-TX)
  2. Betrag = Summe der ausgewählten Input-UTXOs (via RPC prevout lookup)
  3. Empfänger-Adresse = Output der Fraud-TX (automatisch erkannt)
  4. Chain: Empfänger → nächste TX → nächste TX → bis Exchange oder unspent
     - Pro Hop wird NUR der Output verfolgt der dem gestohlenen Betrag entspricht
       (größter Output oder der der weitergesendet wird)
     - Verzweigungen werden NICHT verfolgt
  5. Jede Adresse in der Chain auf Exchange geprüft
  6. Bei Exchange: Chain endet, Freeze Request wird generiert
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import pathlib
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Optional

import psycopg2
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router_report = APIRouter(prefix="/intel", tags=["forensic-report"])


# ---------------------------------------------------------------------------
# Exchange Intel Agent Client (Stufe 1 — nach lokaler DB, vor WalletExplorer)
# ---------------------------------------------------------------------------

_exchange_intel_session = None  # urllib3-freie Singleton-Verbindung


def _exchange_intel_lookup(address: str) -> Optional[dict]:
    """
    Prüft Adresse im BTC Exchange Intel Agent (1.76M Adressen, 26 Entities).
    Schnell, lokal, keine externen API-Calls.
    Konfiguration: EXCHANGE_INTEL_API_URL + EXCHANGE_INTEL_API_KEY
    """
    base_url = os.environ.get("EXCHANGE_INTEL_API_URL", "").rstrip("/")
    if not base_url:
        return None
    api_key = os.environ.get("EXCHANGE_INTEL_API_KEY", "")
    try:
        url = f"{base_url}/v1/address/{address}"
        headers = {"User-Agent": "AIFinancialCrime/2.0"}
        if api_key:
            headers["X-API-Key"] = api_key
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        if not data.get("found"):
            return None
        entity = data.get("entity") or ""
        canonical = next(
            (name for key, name in KNOWN_EXCHANGES.items() if key in entity.lower()),
            entity
        )
        source_type = data.get("best_source_type", "exchange_intel")
        confidence = "L1" if source_type in ("official_por", "seed") else "L2"
        logger.debug(f"INTEL-HIT: {address[:20]} → {canonical} (source={source_type})")
        return {
            "exchange": canonical,
            "label": f"{canonical} ({source_type})",
            "wallet_id": "",
            "source": f"exchange-intel/{source_type}",
            "confidence": confidence,
            "is_sanctioned": False,
        }
    except Exception as e:
        logger.debug(f"ExchangeIntel lookup failed {address[:20]}: {e}")
        return None


# ---------------------------------------------------------------------------
# DB-basierte Exchange-Erkennung (Stufe 0 — VOR allen API-Calls)
# ---------------------------------------------------------------------------

def _get_db_conn():
    """Holt die globale DB-Verbindung aus main.py."""
    from main import get_db
    return get_db()


def _db_exchange_lookup(address: str) -> Optional[dict]:
    """
    Prüft Adresse in der lokalen PostgreSQL-Datenbank (address_attributions).
    Schnellste Prüfung — kein API-Call, keine Latenz.
    Enthält Seed-Daten (bekannte Hot/Cold Wallets) + persistent gespeicherte API-Ergebnisse.
    """
    try:
        conn = _get_db_conn()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT aa.entity_name, aa.entity_type, s.source_key, aa.confidence_level,
                       aa.is_sanctioned, aa.raw_source_data
                FROM address_attributions aa
                JOIN attribution_sources s ON aa.source_id = s.source_id
                WHERE aa.address = %s AND aa.entity_type = 'EXCHANGE'
                ORDER BY s.priority ASC
                LIMIT 1
            """, (address,))
            row = cur.fetchone()
        if row:
            entity_name, entity_type, source_key, conf_level, is_sanctioned, raw_data = row
            # Kanonischen Namen verwenden falls vorhanden
            canonical = next(
                (name for key, name in KNOWN_EXCHANGES.items() if key in entity_name.lower()),
                entity_name
            )
            logger.debug(f"DB-HIT: {address[:20]} → {canonical} (source={source_key})")
            return {
                "exchange": canonical,
                "label": f"{canonical} (DB: {source_key})",
                "wallet_id": "",
                "source": f"local-db/{source_key}",
                "confidence": "L1" if conf_level == 1 else "L2",
                "is_sanctioned": bool(is_sanctioned),
            }
    except Exception as e:
        logger.debug(f"DB lookup failed for {address[:20]}: {e}")
    return None


def _db_persist_attribution(address: str, exchange_name: str, source_key: str,
                            raw_data: Optional[dict] = None) -> None:
    """
    Speichert API-Ergebnis persistent in der Datenbank.
    So wird jede WalletExplorer/Blockchair-Erkennung dauerhaft verfügbar.
    """
    try:
        conn = _get_db_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO address_attributions (
                    address, source_id, entity_name, entity_type,
                    confidence_level, is_sanctioned, raw_source_data
                )
                SELECT %s, s.source_id, %s, 'EXCHANGE', s.confidence_level, FALSE, %s
                FROM attribution_sources s WHERE s.source_key = %s
                ON CONFLICT (address, source_id) DO UPDATE SET
                    entity_name = EXCLUDED.entity_name,
                    last_updated_at = NOW()
            """, (address, exchange_name, json.dumps(raw_data) if raw_data else None, source_key))
        conn.commit()
        logger.debug(f"DB-PERSIST: {address[:20]} → {exchange_name} (source={source_key})")
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logger.debug(f"DB persist failed for {address[:20]}: {e}")

OUTPUT_DIR = pathlib.Path.home() / "AIFinancialCrime-Cases" / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Request Model
# ---------------------------------------------------------------------------

class ReportRequest(BaseModel):
    case_id: Optional[str] = None
    victim_name: str
    victim_email: Optional[str] = ""
    victim_country: Optional[str] = "Deutschland"
    incident_date: str
    discovery_date: Optional[str] = ""
    wallet_type: Optional[str] = "Hardware"
    wallet_brand: Optional[str] = ""
    seed_digital: Optional[str] = "unbekannt"
    description: Optional[str] = ""
    fraud_txid: str
    fraud_amount_btc: str
    fraud_amount_eur: Optional[str] = ""
    victim_addresses: list[str] = []
    recipient_address: str
    additional_notes: Optional[str] = ""
    manual_attributions: dict[str, str] = {}  # {address: exchange_name}


# ---------------------------------------------------------------------------
# Exchange Attribution
# ---------------------------------------------------------------------------

KNOWN_EXCHANGES = {
    "huobi": "Huobi", "binance": "Binance", "coinbase": "Coinbase",
    "kraken": "Kraken", "bitfinex": "Bitfinex", "okx": "OKX",
    "poloniex": "Poloniex", "kucoin": "KuCoin", "bybit": "Bybit",
    "bitstamp": "Bitstamp", "gemini": "Gemini", "bittrex": "Bittrex",
    "bitmex": "BitMEX", "gate.io": "Gate.io", "htx": "Huobi",
    "gate": "Gate.io", "bitget": "Bitget", "mexc": "MEXC",
}

EXCHANGE_COMPLIANCE = {
    "Huobi": "compliance@huobi.com",
    "Binance": "law_enforcement@binance.com",
    "Coinbase": "compliance@coinbase.com",
    "Kraken": "compliance@kraken.com",
    "Poloniex": "support@poloniex.com",
    "OKX": "compliance@okx.com",
    "Bybit": "compliance@bybit.com",
    "Bitstamp": "legal@bitstamp.net",
    "Bitfinex": "compliance@bitfinex.com",
    "Gate.io": "compliance@gate.io",
}

_attribution_cache: dict[str, dict] = {}


def _walletexplorer_lookup(address: str) -> Optional[dict]:
    try:
        url = (f"https://www.walletexplorer.com/api/1/address"
               f"?address={address}&from=0&count=1&caller=AIFinancialCrime")
        req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/2.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        if not data.get("found") or not data.get("label"):
            return None
        label_raw = data["label"]
        exchange_name = next(
            (name for key, name in KNOWN_EXCHANGES.items() if key in label_raw.lower()),
            label_raw
        )
        return {
            "exchange": exchange_name,
            "label": label_raw,
            "wallet_id": data.get("wallet_id", ""),
            "source": "walletexplorer",
            "confidence": "L2",
        }
    except Exception as e:
        logger.debug(f"WalletExplorer failed {address[:20]}: {e}")
        return None


def _blockchair_lookup(address: str) -> Optional[dict]:
    api_key = os.environ.get("BLOCKCHAIR_API_KEY")
    if not api_key:
        return None
    try:
        url = f"https://api.blockchair.com/bitcoin/dashboards/address/{address}?key={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/2.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        addr_data = data.get("data", {}).get(address, {}).get("address", {})
        tag = addr_data.get("tag")
        if not tag:
            return None
        exchange_name = next(
            (name for key, name in KNOWN_EXCHANGES.items() if key in tag.lower()),
            tag
        )
        return {"exchange": exchange_name, "label": tag, "wallet_id": "", "source": "blockchair", "confidence": "L2"}
    except Exception as e:
        logger.debug(f"Blockchair failed {address[:20]}: {e}")
        return None


def _chainalysis_check(address: str) -> bool:
    api_key = os.environ.get("CHAINALYSIS_API_KEY")
    if not api_key:
        return False
    try:
        url = f"https://public.chainalysis.com/api/v1/address/{address}"
        req = urllib.request.Request(url, headers={
            "X-API-Key": api_key, "Accept": "application/json",
            "User-Agent": "AIFinancialCrime/2.0",
        })
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        return bool(data.get("identifications"))
    except Exception:
        return False


def _lookup_address_exchange(addr: str, call_counter: list) -> Optional[dict]:
    """Hilfsfunktion: Prüft einzelne Adresse auf Exchange via Cache → DB → WalletExplorer → Blockchair."""
    if addr in _attribution_cache:
        cached = _attribution_cache[addr]
        if cached.get("exchange"):
            return cached
        return None
    # Stufe 0: Lokale DB (kein API-Call-Budget verbraucht)
    db_result = _db_exchange_lookup(addr)
    if db_result:
        _attribution_cache[addr] = {**db_result, "_downstream_checked": True}
        return db_result
    # Stufe 1: Exchange Intel Agent (1.76M Adressen, lokal)
    intel_result = _exchange_intel_lookup(addr)
    if intel_result:
        _attribution_cache[addr] = {**intel_result, "_downstream_checked": True}
        _db_persist_attribution(addr, intel_result["exchange"], "EXCHANGE_INTEL",
                                {"source": intel_result.get("source"), "label": intel_result.get("label")})
        return intel_result
    if call_counter[0] >= 6:
        return None
    call_counter[0] += 1
    time.sleep(0.15)
    result = _walletexplorer_lookup(addr)
    if not result:
        result = _blockchair_lookup(addr)
    if result:
        _attribution_cache[addr] = {**result, "is_sanctioned": False, "_downstream_checked": True}
        # Persistent speichern
        if result.get("exchange"):
            source_key = "WALLETEXPLORER" if result.get("source") == "walletexplorer" else "BLOCKCHAIR"
            _db_persist_attribution(addr, result["exchange"], source_key,
                                    {"label": result.get("label"), "wallet_id": result.get("wallet_id")})
    return result


def _downstream_exchange_lookup(address: str) -> Optional[dict]:
    """
    Erkennt Exchange-Deposit-Adressen durch Downstream-Analyse (bis 2 Hops).

    Beweiskette Hop 1:
      Adresse → Sweep-TX → bekannte Exchange-Adresse

    Beweiskette Hop 2 (wenn Hop 1 fehlschlägt):
      Adresse → Sweep-TX → Zwischen-Adresse → weitere TX → bekannte Exchange-Adresse
      Typisch für Binance: Deposit → interne Collection-Wallet → Binance Hot Wallet

    Quelle: Direkte On-Chain-Analyse via Blockstream API.
    Forensische Einordnung: L2 (forensisch belegt, nicht mathematisch beweisbar).
    """
    call_counter = [0]
    try:
        url = f"https://blockstream.info/api/address/{address}/txs"
        req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/2.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            txs = json.loads(r.read())

        # === HOP 1: Direkte Outputs der Spending-TX prüfen ===
        hop1_intermediate = []  # (out_addr) für Hop-2-Analyse gesammelt
        for tx in txs[:5]:
            is_spending = any(
                vin.get("prevout", {}).get("scriptpubkey_address") == address
                for vin in tx.get("vin", [])
            )
            if not is_spending:
                continue

            for vout in tx.get("vout", [])[:10]:
                out_addr = vout.get("scriptpubkey_address")
                if not out_addr or out_addr == address:
                    continue

                result = _lookup_address_exchange(out_addr, call_counter)
                if result and result.get("exchange"):
                    return {
                        "exchange": result["exchange"],
                        "label": f"{result['exchange']} Deposit-Adresse",
                        "wallet_id": result.get("wallet_id", ""),
                        "source": "downstream-analysis",
                        "confidence": "L2",
                    }
                hop1_intermediate.append(out_addr)

        # === HOP 2: Outputs der Zwischen-Adressen prüfen ===
        # Beweiskette: Adresse → TX_A → Zwischen-Adresse → TX_B → Exchange
        for inter_addr in hop1_intermediate[:4]:
            if call_counter[0] >= 12:
                break
            try:
                url2 = f"https://blockstream.info/api/address/{inter_addr}/txs"
                req2 = urllib.request.Request(url2, headers={"User-Agent": "AIFinancialCrime/2.0"})
                with urllib.request.urlopen(req2, timeout=8) as r2:
                    txs2 = json.loads(r2.read())

                for tx2 in txs2[:3]:
                    is_spending2 = any(
                        vin.get("prevout", {}).get("scriptpubkey_address") == inter_addr
                        for vin in tx2.get("vin", [])
                    )
                    if not is_spending2:
                        continue

                    for vout2 in tx2.get("vout", [])[:8]:
                        out_addr2 = vout2.get("scriptpubkey_address")
                        if not out_addr2 or out_addr2 in (address, inter_addr):
                            continue

                        result2 = _lookup_address_exchange(out_addr2, call_counter)
                        if result2 and result2.get("exchange"):
                            return {
                                "exchange": result2["exchange"],
                                "label": f"{result2['exchange']} Deposit-Adresse (2-Hop)",
                                "wallet_id": result2.get("wallet_id", ""),
                                "source": "downstream-analysis-2hop",
                                "confidence": "L2",
                            }
            except Exception:
                continue

    except Exception as e:
        logger.debug(f"Downstream exchange lookup failed {address[:20]}: {e}")
    return None


def _check_address(address: str, use_downstream: bool = True) -> dict:
    """Prüft Adresse auf Exchange-Attribution und Sanctions. Mit intelligentem Cache.

    Args:
        use_downstream: Wenn False, wird NUR WalletExplorer + Blockchair geprüft
                       (direkte Erkennung). Downstream-Analyse wird übersprungen.
                       Verwenden im Tracer-Output-Scan, damit Deposit-Adressen
                       nicht vorzeitig als Exchange markiert werden und die
                       L1-Kette bis zur tatsächlichen Exchange-Adresse weiterläuft.

    Cache-Logik:
        - Exchange gefunden → immer cachen (definitives Ergebnis)
        - Kein Exchange + use_downstream=True → cachen mit _downstream_checked=True
        - Kein Exchange + use_downstream=False → cachen mit _downstream_checked=False
        - Späterer Aufruf mit use_downstream=True prüft ob Downstream schon lief:
          Wenn nicht → erneut prüfen mit Downstream-Analyse
    """
    if address in _attribution_cache:
        cached = _attribution_cache[address]
        # Wenn bereits Exchange gefunden → immer zurückgeben
        if cached.get("exchange"):
            return cached
        # Wenn Downstream gewünscht aber noch nicht gelaufen → durchfallen
        if use_downstream and not cached.get("_downstream_checked"):
            pass  # Erneut prüfen mit Downstream
        else:
            return cached

    result = {"exchange": None, "is_sanctioned": False, "source": None,
              "label": None, "wallet_id": None, "confidence": "L1"}

    # 0. Lokale DB — Seed-Daten + persistent gespeicherte API-Ergebnisse (KEIN API-Call)
    attribution = _db_exchange_lookup(address)

    # 1. Exchange Intel Agent — 1.76M Adressen, lokal (KEIN externer API-Call)
    if not attribution:
        attribution = _exchange_intel_lookup(address)
        if attribution and attribution.get("exchange"):
            _db_persist_attribution(address, attribution["exchange"], "EXCHANGE_INTEL",
                                    {"source": attribution.get("source"), "label": attribution.get("label")})

    # 2. WalletExplorer (direkte Erkennung)
    if not attribution:
        attribution = _walletexplorer_lookup(address)
        if attribution and attribution.get("exchange"):
            _db_persist_attribution(address, attribution["exchange"], "WALLETEXPLORER",
                                    {"label": attribution.get("label"), "wallet_id": attribution.get("wallet_id")})
    if not attribution:
        time.sleep(0.2)
        # 3. Blockchair (API-Key erforderlich)
        attribution = _blockchair_lookup(address)
        if attribution and attribution.get("exchange"):
            _db_persist_attribution(address, attribution["exchange"], "BLOCKCHAIR",
                                    {"label": attribution.get("label")})
    if not attribution and use_downstream:
        time.sleep(0.3)
        # 3. Downstream-Analyse: Spending-TX auf bekannte Exchange prüfen
        #    Beweiskette: Adresse → Sweep-TX → bekannte Exchange-Adresse (L2)
        attribution = _downstream_exchange_lookup(address)
    if attribution:
        result.update(attribution)

    result["is_sanctioned"] = _chainalysis_check(address)
    result["_downstream_checked"] = use_downstream
    _attribution_cache[address] = result
    return result


def _apply_manual_attributions(manual_attributions: dict[str, str]) -> None:
    """Schreibt manuelle Exchange-Attributionen in den Cache (höchste Priorität)."""
    for address, exchange_name in manual_attributions.items():
        canonical = next((v for k, v in KNOWN_EXCHANGES.items() if k in exchange_name.lower()), exchange_name)
        compliance_email = EXCHANGE_COMPLIANCE.get(canonical, "")
        _attribution_cache[address] = {
            "exchange": canonical,
            "label": f"{canonical} (manuell bestätigt)",
            "wallet_id": "",
            "source": "manual",
            "confidence": "L2",
            "is_sanctioned": False,
            "compliance_email": compliance_email,
        }


# ---------------------------------------------------------------------------
# TX-Daten holen
# ---------------------------------------------------------------------------

def _get_tx(txid: str, rpc) -> Optional[dict]:
    """TX via RPC, Fallback Blockstream. Reichert RPC-Daten mit Block-Info an."""
    tx_data = None
    try:
        tx_data = rpc.call("getrawtransaction", [txid, True])
    except Exception:
        pass

    if tx_data is not None:
        # RPC liefert kein blockheight — von Blockstream nachladen
        if not tx_data.get("blockheight") and not tx_data.get("status"):
            try:
                url = f"https://blockstream.info/api/tx/{txid}"
                req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/2.0"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    bs = json.loads(r.read())
                if bs.get("status", {}).get("confirmed"):
                    tx_data["status"] = bs["status"]
                    tx_data.setdefault("blocktime", bs["status"].get("block_time", 0))
            except Exception:
                pass
        return tx_data

    # Blockstream Fallback mit Retry bei Rate-Limit
    for attempt in range(3):
        try:
            if attempt > 0:
                time.sleep(1.5 * attempt)  # Backoff bei Retry
            url = f"https://blockstream.info/api/tx/{txid}"
            req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/2.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except Exception as e:
            if attempt == 2:
                logger.warning(f"Could not get TX {txid[:16]} after 3 attempts: {e}")
            else:
                logger.debug(f"TX {txid[:16]} attempt {attempt+1} failed: {e}")
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
    """Block-Höhe und Zeitstempel aus TX."""
    block_height = tx_data.get("blockheight", 0) or 0
    block_time = tx_data.get("blocktime", 0)
    status = tx_data.get("status", {})
    if status:
        block_height = status.get("block_height", block_height) or block_height
        block_time = status.get("block_time", block_time) or block_time
    if block_time:
        ts = datetime.fromtimestamp(block_time, tz=timezone.utc)
        return block_height, ts.strftime("%d.%m.%Y %H:%M UTC")
    return block_height, "—"


def _get_spending_txid(txid: str, vout_idx: int, rpc) -> Optional[str]:
    """Findet die TX die einen bestimmten Output ausgibt."""
    # Via RPC: gettxout = None bedeutet ausgegeben
    try:
        utxo = rpc.call("gettxout", [txid, vout_idx])
        if utxo is not None:
            return None  # Noch unspent
    except Exception:
        pass

    # Via Blockstream: outspend endpoint
    try:
        url = f"https://blockstream.info/api/tx/{txid}/outspend/{vout_idx}"
        req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/2.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        if data.get("spent"):
            return data.get("txid")
    except Exception as e:
        logger.debug(f"outspend lookup failed {txid[:16]}:{vout_idx}: {e}")

    return None


def _get_victim_amount_from_inputs(fraud_tx: dict, victim_addresses: set, rpc) -> float:
    """
    Berechnet den gestohlenen Betrag als Summe der Inputs der Opfer-Adressen.
    Holt prevout-Werte via separaten RPC-Calls.
    """
    total = 0.0
    for vin in fraud_tx.get("vin", []):
        # Blockstream Format: prevout direkt vorhanden
        prevout = vin.get("prevout", {})
        addr = prevout.get("scriptpubkey_address") or prevout.get("scriptPubKey", {}).get("address")
        val = prevout.get("value", 0)

        if not addr or not val:
            # RPC Format: prevout via separaten Lookup
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
        block_time = tx_data.get("blocktime") or tx_data.get("status", {}).get("block_time")
        first_seen = datetime.fromtimestamp(block_time, tz=timezone.utc) if block_time else None

        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM transactions WHERE txid = %s", (txid,))
            if cur.fetchone():
                return

        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO transactions (txid, block_height, first_seen)
                VALUES (%s, %s, %s) ON CONFLICT (txid) DO NOTHING
            """, (txid, block_height or None, first_seen))

            for i, vout in enumerate(tx_data.get("vout", [])):
                addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
                val = vout.get("value", 0)
                sats = int(val * 1e8) if isinstance(val, float) else int(val)
                if addr:
                    cur.execute("""
                        INSERT INTO tx_outputs (txid, vout_index, address, amount_sats)
                        VALUES (%s, %s, %s, %s) ON CONFLICT (txid, vout_index) DO NOTHING
                    """, (txid, i, addr, sats))

            for i, vin in enumerate(tx_data.get("vin", [])):
                prev_txid = vin.get("txid")
                prev_vout = vin.get("vout")
                if prev_txid and prev_vout is not None:
                    cur.execute("""
                        UPDATE tx_outputs SET spent_by_txid = %s
                        WHERE txid = %s AND vout_index = %s AND spent_by_txid IS NULL
                    """, (txid, prev_txid, prev_vout))

        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.warning(f"DB save failed for {txid[:16]}: {e}")


# ---------------------------------------------------------------------------
# Fokussiertes Chain-Tracing
# ---------------------------------------------------------------------------

def _trace_victim_chain(fraud_txid: str, recipient_address: str, rpc, conn, max_hops: int = 8) -> list:
    """
    Verfolgt den Pfad des gestohlenen Geldes ab der Empfänger-Adresse.

    Korrekte Logik fuer Splits:
    - Queue: (from_txid, tracked_address, tracked_amount, hop_idx)
    - Verfolgt ALLE Outputs einer TX die ueber Dust-Limit liegen
    - Jeder Pfad endet bei Exchange, Pooling oder unspent UTXO
    - visited_spending_txids verhindert Schleifen

    WICHTIG: Der erste Queue-Eintrag (recipient_address direkt aus fraud_txid) wird
    NIE durch den Exchange-Cache-Check abgebrochen. Mindestens 1 L1-Hop muss
    immer verfolgt werden, auch wenn recipient_address als Exchange bekannt ist.
    """
    hops = []
    visited_spending_txids = set()

    # Betrag der Empfaenger-Adresse aus Fraud-TX ermitteln
    fraud_tx_data = _get_tx(fraud_txid, rpc)
    recipient_amount = 0.0
    if fraud_tx_data:
        for vout in fraud_tx_data.get("vout", []):
            addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
            if addr == recipient_address:
                val = vout.get("value", 0)
                recipient_amount = val if isinstance(val, float) and val < 100 else val / 1e8
                break

    queue = [(fraud_txid, recipient_address, recipient_amount, 1)]

    while queue and len(hops) < max_hops:
        current_txid, current_address, from_amount, hop_idx = queue.pop(0)
        logger.info(f"  TRACER: hop={hop_idx}, addr={current_address[:20]}..., txid={current_txid[:16]}, queue_remaining={len(queue)}")

        current_tx = _get_tx(current_txid, rpc)
        if not current_tx:
            logger.info(f"  TRACER: TX nicht gefunden, skip")
            continue
        _save_tx_to_db(current_txid, current_tx, conn)

        # Output-Index der current_address in current_tx finden
        vout_idx = None
        actual_from_amount = from_amount
        for i, vout in enumerate(current_tx.get("vout", [])):
            addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
            if addr == current_address:
                vout_idx = i
                val = vout.get("value", 0)
                actual_from_amount = val if isinstance(val, float) and val < 100 else val / 1e8
                break

        if vout_idx is None:
            logger.info(f"  TRACER: vout_idx None für {current_address[:20]}, skip")
            continue

        # Prüfe ob current_address selbst als Exchange bekannt ist (Deposit-Adresse)
        # AUSNAHME: Für den allerersten Schritt (recipient_address direkt aus fraud_txid)
        # NIEMALS abbrechen — wir wollen den L1-Hop zur ersten Weiterleitung immer sehen.
        is_initial_step = (current_address == recipient_address and current_txid == fraud_txid)
        cached_attr = _attribution_cache.get(current_address, {})
        if cached_attr.get("exchange") and not is_initial_step:
            logger.info(f"  TRACER: EARLY EXIT — {current_address[:20]} im Cache als {cached_attr.get('exchange')}")
            # Vorherigen Hop als Exchange-Einzahlung aktualisieren falls vorhanden
            if hops:
                for hop in reversed(hops):
                    if any(a == current_address for a, _ in hop.get("to_addresses", [])):
                        hop["confidence"] = "L2"
                        hop["confidence_label"] = "Forensisch belegt"
                        hop["exchange"] = cached_attr["exchange"]
                        hop["exchange_wallet_id"] = cached_attr.get("wallet_id", "")
                        hop["exchange_source"] = cached_attr.get("source", "")
                        hop["label"] = f"Exchange-Einzahlung -> {cached_attr['exchange']}"
                        hop["method"] = f"Downstream-Analyse ({cached_attr.get('label', '')})"
                        hop["notes"] += f" Adresse als {cached_attr['exchange']} Deposit-Adresse identifiziert."
                        hop["chain_end_reason"] = "exchange"
                        break
            continue  # Exchange erkannt → nicht weiter tracen

        # Spending TX finden
        spending_txid = _get_spending_txid(current_txid, vout_idx, rpc)
        logger.info(f"  TRACER: spending_txid={spending_txid[:16] if spending_txid else 'None'} für {current_txid[:16]}:{vout_idx}")
        if not spending_txid:
            # UTXO noch nicht ausgegeben — Exchange-Check der Adresse selbst
            check = _check_address(current_address)
            if check.get("exchange") and hops:
                for hop in reversed(hops):
                    if any(a == current_address for a, _ in hop.get("to_addresses", [])):
                        hop["confidence"] = "L2"
                        hop["confidence_label"] = "Forensisch belegt"
                        hop["exchange"] = check["exchange"]
                        hop["exchange_wallet_id"] = check.get("wallet_id", "")
                        hop["exchange_source"] = check.get("source", "")
                        hop["label"] = f"Exchange-Einzahlung -> {check['exchange']}"
                        hop["method"] = f"WalletExplorer Attribution ({check.get('label', '')})"
                        hop["notes"] += f" Adresse als {check['exchange']} identifiziert."
                        hop["chain_end_reason"] = "exchange"
                        break
            else:
                # Kein Exchange — UTXO ist unspent → forensisch interessant (Mittel liegen noch)
                if hops:
                    for hop in reversed(hops):
                        if any(a == current_address for a, _ in hop.get("to_addresses", [])):
                            hop["chain_end_reason"] = "unspent"
                            hop["notes"] += (
                                f" UTXO an {current_address[:20]}... ist noch nicht ausgegeben "
                                f"(Stand: Analyse-Zeitpunkt). Mittel möglicherweise noch verfügbar."
                            )
                            break
            continue

        if spending_txid in visited_spending_txids:
            logger.info(f"  TRACER: SKIP — {spending_txid[:16]} already visited")
            continue
        visited_spending_txids.add(spending_txid)

        spending_tx = _get_tx(spending_txid, rpc)
        if not spending_tx:
            logger.warning(f"  TRACER: spending_tx {spending_txid[:16]} konnte nicht geladen werden, skip")
            continue
        _save_tx_to_db(spending_txid, spending_tx, conn)

        to_block, ts_str = _get_tx_block_info(spending_tx)
        to_outputs = _get_tx_outputs(spending_tx)

        # Alle Outputs auf Exchange und Sanctions pruefen
        # WICHTIG: current_address (= Change-Output) NICHT auf Exchange prüfen.
        # Sonst wird der Täter selbst als Exchange markiert weil er Geld AN eine
        # Exchange sendet, und die Downstream-Analyse ihn fälschlich als Deposit-Adresse flaggt.
        exchange_hits = {}
        sanctioned = False
        for addr, _ in to_outputs:
            if addr == current_address:
                continue  # Change-Output: niemals als Exchange behandeln
            # NUR direkte Erkennung (WalletExplorer/Blockchair) — KEINE Downstream-Analyse.
            # So werden Deposit-Adressen nicht vorzeitig als Exchange markiert und
            # die L1-Kette läuft bis zur tatsächlichen Exchange-Adresse weiter.
            check = _check_address(addr, use_downstream=False)
            if check.get("exchange"):
                exchange_hits[addr] = check
            if check.get("is_sanctioned"):
                sanctioned = True

        # Pooling-Erkennung: Wenn Output-Beträge deutlich größer als tracked amount
        # → fremde Funds wurden zusammengeführt → L1 nicht mehr haltbar → Tracing stoppen
        dust_limit = 0.00000546
        max_output = max((btc for _, btc in to_outputs), default=0)
        pooling_detected = (
            actual_from_amount > 0
            and max_output > actual_from_amount * 3.0
            and not exchange_hits  # Exchange-Erkennung hat Vorrang
        )

        # Relevante Outputs: Exchange-Outputs + alle Outputs über Dust-Limit
        # Bei Pooling: nur anzeigen, nicht weiter verfolgen
        # Limit: max 5 nicht-Exchange Outputs verfolgen (Top N nach Betrag)
        # → verhindert Queue-Explosion bei TXs mit vielen Outputs
        MAX_BRANCH_OUTPUTS = 5
        relevant_outputs = []
        non_exchange_outputs = []
        for addr, btc in to_outputs:
            if addr == current_address:
                # Change-Output: als non-exchange einfügen, wird immer verfolgt
                non_exchange_outputs.append((addr, btc, False))
            elif addr in exchange_hits:
                relevant_outputs.append((addr, btc, True))
            elif btc > dust_limit:
                non_exchange_outputs.append((addr, btc, False))

        # Top N non-exchange Outputs nach Betrag, damit wir den Hauptpfad nicht verlieren
        non_exchange_outputs.sort(key=lambda x: x[1], reverse=True)
        relevant_outputs.extend(non_exchange_outputs[:MAX_BRANCH_OUTPUTS])

        if not relevant_outputs and to_outputs:
            best = max(to_outputs, key=lambda x: x[1])
            relevant_outputs = [(best[0], best[1], False)]

        display_outputs = [(addr, btc) for addr, btc, _ in relevant_outputs]

        if exchange_hits:
            ex_names = ", ".join(set(c["exchange"] for c in exchange_hits.values()))
            label = f"Exchange-Einzahlung -> {ex_names}"
            first_ex = next(iter(exchange_hits.values()))
            method = f"WalletExplorer Attribution ({first_ex.get('label', '')})"
            notes = f"Gestohlene Mittel fliessen zu {ex_names}. Identifiziert via {first_ex['source']}."
            confidence = "L2"
        elif pooling_detected:
            label = "Konsolidierung — Weiterleitung nicht eindeutig zuordenbar"
            method = "Direkter UTXO-Link (Eingang), Pooling erkannt (Ausgang)"
            notes = (
                f"Eingehender Betrag {actual_from_amount:.8f} BTC wurde mit Fremdmitteln "
                f"konsolidiert (Output: {max_output:.8f} BTC). "
                f"Mathematische Zuordnung der gestohlenen Mittel ab diesem Punkt nicht mehr möglich. "
                f"Wahrscheinlich Exchange-internes Wallet oder Mixing-Service."
            )
            confidence = "L2"
        else:
            label = "UTXO Weiterleitung"
            method = "Direkter UTXO-Link"
            notes = "Automatisch erkannt via Pi-Node + Blockstream."
            confidence = "L1"

        if sanctioned:
            notes += " SANKTIONIERTE ADRESSE (OFAC SDN)."

        # Kettenende-Grund bestimmen
        if exchange_hits:
            chain_end_reason = "exchange"          # Mittel auf Exchange eingezahlt → Kette endet
        elif pooling_detected:
            chain_end_reason = "pooling"           # Fremdfunds zusammengeführt → L1 nicht mehr haltbar
        else:
            chain_end_reason = None                # Kette läuft weiter

        hop = {
            "hop": hop_idx,
            "label": label,
            "txid": spending_txid,
            "block": to_block or 0,
            "timestamp": ts_str,
            "from_addresses": [(current_address, actual_from_amount)],
            "to_addresses": display_outputs,
            "fee_btc": None,
            "confidence": confidence,
            "confidence_label": "Forensisch belegt" if confidence == "L2" else "Mathematisch bewiesen",
            "method": method,
            "notes": notes,
            "is_sanctioned": sanctioned,
            "chain_end_reason": chain_end_reason,
        }

        if exchange_hits:
            first_ex_addr = next(iter(exchange_hits))
            first_ex = exchange_hits[first_ex_addr]
            hop["exchange"] = first_ex["exchange"]
            hop["exchange_wallet_id"] = first_ex.get("wallet_id", "")
            hop["exchange_source"] = first_ex.get("source", "")

        hops.append(hop)
        logger.info(f"  TRACER: HOP {hop_idx} gebaut: {label[:50]}, exchange_hits={list(exchange_hits.keys())[:3]}, pooling={pooling_detected}")

        # Nicht-Exchange Outputs weiterverfolgen — außer bei Pooling (L1 nicht mehr haltbar)
        if not pooling_detected:
            for addr, btc, is_exchange in relevant_outputs:
                if not is_exchange:
                    logger.info(f"  TRACER: QUEUE += ({spending_txid[:16]}, {addr[:20]}, {btc:.8f}, hop={hop_idx + 1})")
                    queue.append((spending_txid, addr, btc, hop_idx + 1))
        else:
            logger.info(f"  TRACER: POOLING — keine Weiterleitung")

    # Duplikate entfernen und neu nummerieren
    seen = set()
    unique_hops = []
    for hop in sorted(hops, key=lambda h: (h["hop"], h["txid"])):
        key = (hop["txid"], hop["from_addresses"][0][0] if hop["from_addresses"] else "")
        if key not in seen:
            seen.add(key)
            unique_hops.append(hop)
    for i, hop in enumerate(unique_hops):
        hop["hop"] = i + 1

    return unique_hops



# ---------------------------------------------------------------------------
# Exchanges aus Hops
# ---------------------------------------------------------------------------

def _build_exchanges(all_hops: list) -> list:
    """Baut Exchange-Liste aus allen Hops.

    WICHTIG: Pro Exchange-Adresse ein separater Eintrag (nicht pro Exchange-Name).
    Wenn 2 verschiedene Adressen zu Huobi gehören, erscheinen 2 Einträge in der
    Zusammenfassung. So sieht man alle Pfade auf einen Blick.
    Für den Freeze-Request wird nach Exchange-Name gruppiert.
    """
    seen_addrs = set()
    entries = []

    source_notes = {
        "walletexplorer": (
            "Adresse wurde durch WalletExplorer Wallet-Cluster-Analyse "
            "der Exchange zugeordnet."
        ),
        "blockchair": (
            "Adresse wurde durch Blockchair Blockchain-Intelligence-Datenbank "
            "als Exchange-Adresse identifiziert."
        ),
        "downstream-analysis": (
            "Adresse wurde als Exchange-Deposit-Adresse identifiziert: "
            "Die Spending-TX dieser Adresse leitet Mittel nachweislich an eine "
            "durch WalletExplorer/Blockchair bestätigte Exchange-Adresse weiter "
            "(On-Chain Downstream-Analyse, 1-Hop)."
        ),
        "downstream-analysis-2hop": (
            "Adresse wurde als Exchange-Deposit-Adresse identifiziert: "
            "Die Mittel fliessen über eine Zwischen-Adresse nachweislich zu einer "
            "durch WalletExplorer/Blockchair bestätigten Exchange-Adresse "
            "(On-Chain Downstream-Analyse, 2-Hop)."
        ),
        "manual": (
            "Exchange-Zuordnung wurde manuell durch den forensischen Analysten "
            "bestätigt und eingetragen."
        ),
    }

    for hop in all_hops:
        name = hop.get("exchange")
        if not name:
            continue

        # Exchange-Adresse aus den Outputs finden
        ex_addr = ""
        ex_btc = 0.0
        for addr, btc in hop.get("to_addresses", []):
            check = _attribution_cache.get(addr, {})
            if check.get("exchange") == name:
                ex_addr = addr
                ex_btc = btc
                break
        if not ex_addr and hop.get("to_addresses"):
            ex_addr = hop["to_addresses"][0][0]
            ex_btc = hop["to_addresses"][0][1]

        # Deduplizierung nach Adresse (nicht nach Exchange-Name)
        if ex_addr in seen_addrs:
            continue
        seen_addrs.add(ex_addr)

        ex_source = hop.get("exchange_source", "walletexplorer")
        entries.append({
            "name": name,
            "address": ex_addr,
            "wallet_id": hop.get("exchange_wallet_id", ""),
            "label": name,
            "tx_count": None,
            "confidence": "L2",
            "compliance_email": EXCHANGE_COMPLIANCE.get(
                name, f"compliance@{name.lower().replace(' ', '').replace('.', '')}.com"
            ),
            "compliance_url": "",
            "btc_involved": ex_btc,
            "note": source_notes.get(ex_source, f"Identifiziert via {ex_source}."),
        })

    return entries


# ---------------------------------------------------------------------------
# PDF Generierung
# ---------------------------------------------------------------------------

def _generate_pdf(case_id: str, req: ReportRequest, hop0: dict, hops: list, exchanges: list) -> str:
    import src.investigation.generate_case_report as gcr
    from reportlab.platypus import SimpleDocTemplate, Spacer, PageBreak
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm

    gcr.CASE = {
        "case_id":          case_id,
        "victim_name":      req.victim_name,
        "victim_contact":   req.victim_email or "",
        "incident_date":    req.incident_date,
        "discovery_date":   req.discovery_date or "",
        "fraud_amount":     req.fraud_amount_btc,
        "fraud_amount_eur": req.fraud_amount_eur or "—",
        "wallet_type":      f"{req.wallet_brand} ({req.wallet_type})",
        "generated_at":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    gcr.HOPS = [hop0] + hops
    gcr.EXCHANGES_IDENTIFIED = exchanges

    styles = gcr._styles()
    report_hash = hashlib.sha256((str(gcr.HOPS) + str(gcr.CASE)).encode()).hexdigest()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=gcr.MARGIN, rightMargin=gcr.MARGIN,
                            topMargin=18*mm, bottomMargin=16*mm)
    on_page = gcr._page_template(case_id, gcr.CASE["generated_at"])

    story = []
    story += gcr._cover(styles)
    story.append(PageBreak())
    story += gcr._methodology(styles)
    story.append(Spacer(1, 8))
    story += gcr._chain_of_custody(styles)
    story.append(PageBreak())
    story += gcr._transaction_graph(styles)
    story.append(PageBreak())
    story += gcr._recommended_actions(styles)
    story.append(Spacer(1, 8))
    story += gcr._integrity(report_hash, styles)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

    pdf_path = str(OUTPUT_DIR / f"{case_id}_Forensischer_Analysebericht.pdf")
    with open(pdf_path, "wb") as f:
        f.write(buf.getvalue())
    return pdf_path


def _generate_freeze_requests(case_id: str, exchanges: list) -> list:
    """Generiert EIN Freeze-Request-PDF pro Exchange (gruppiert nach Name).

    Wenn mehrere Adressen zur selben Exchange gehören (z.B. 2x Huobi),
    wird EIN Freeze-Request mit allen Adressen und dem Gesamtbetrag erstellt.
    """
    import src.investigation.generate_case_report as gcr
    styles = gcr._styles()

    # Gruppierung: alle Adressen und Beträge pro Exchange-Name zusammenführen
    grouped: dict[str, dict] = {}
    for ex in exchanges:
        name = ex["name"]
        if name not in grouped:
            grouped[name] = {**ex, "all_addresses": [(ex["address"], ex["btc_involved"])]}
        else:
            grouped[name]["btc_involved"] += ex.get("btc_involved", 0)
            grouped[name]["all_addresses"].append((ex["address"], ex["btc_involved"]))
            # Mehrere Adressen in der Notiz erwähnen
            grouped[name]["note"] = (
                f"{len(grouped[name]['all_addresses'])} Deposit-Adressen dieser Exchange identifiziert. "
                f"Gesamtbetrag: {grouped[name]['btc_involved']:.8f} BTC."
            )

    paths = []
    for name, ex in grouped.items():
        path = str(OUTPUT_DIR / f"{case_id}_Freeze_Request_{name}.pdf")
        try:
            gcr._freeze_request(ex, styles, path)
            paths.append(path)
        except Exception as e:
            logger.warning(f"Freeze request failed for {name}: {e}")
    return paths


# ---------------------------------------------------------------------------
# Hauptendpoint
# ---------------------------------------------------------------------------

@router_report.post("/generate-report")
async def generate_report(req: ReportRequest):
    """
    Forensische Analyse — fokussiert auf den Pfad des gestohlenen Geldes.
    """
    _attribution_cache.clear()
    if req.manual_attributions:
        _apply_manual_attributions(req.manual_attributions)

    case_id = req.case_id or (
        f"AIFC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-"
        f"{str(uuid.uuid4())[:8].upper()}"
    )

    try:
        conn = _get_conn()
        rpc = _get_rpc()

        logger.info(f"Analyse: {case_id}, txid={req.fraud_txid[:16]}")

        # 1. Fraud-TX holen
        fraud_tx = _get_tx(req.fraud_txid, rpc)
        if not fraud_tx:
            raise HTTPException(status_code=400, detail=f"TX nicht gefunden: {req.fraud_txid[:16]}")

        _save_tx_to_db(req.fraud_txid, fraud_tx, conn)

        # 2. Block-Info der Fraud-TX
        hop0_block, hop0_ts = _get_tx_block_info(fraud_tx)

        # 3. Gestohlenen Betrag = Output an Empfänger-Adresse (tatsächlich gestohlen)
        # Fallback: Summe der Opfer-Inputs (nur wenn kein Recipient-Output gefunden)
        victim_set = set(req.victim_addresses)
        recipient_output_btc = 0.0
        for vout in fraud_tx.get("vout", []):
            addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
            if addr == req.recipient_address:
                val = vout.get("value", 0)
                recipient_output_btc = val if isinstance(val, float) and val < 100 else val / 1e8
                break
        if recipient_output_btc > 0:
            req.fraud_amount_btc = f"{recipient_output_btc:.8f}"
        else:
            # Fallback: Summe der Opfer-Inputs
            actual_amount = _get_victim_amount_from_inputs(fraud_tx, victim_set, rpc)
            if actual_amount > 0:
                req.fraud_amount_btc = f"{actual_amount:.8f}"

        # 4. Alle Outputs der Fraud-TX auf Exchange prüfen
        # WICHTIG: recipient_address NICHT hier prüfen — wird im Tracer separat behandelt.
        # Sonst landet sie im Cache als Exchange und der Tracer bricht sofort ab.
        direct_exchanges = {}
        fraud_tx_outputs = _get_tx_outputs(fraud_tx)
        for addr, btc in fraud_tx_outputs:
            if addr == req.recipient_address:
                continue  # Täter-Adresse: Exchange-Prüfung erfolgt im Tracer
            check = _check_address(addr)
            if check.get("exchange"):
                direct_exchanges[addr] = {**check, "btc": btc}

        # 5. Hop 0 bauen
        # From: ausgewählte Opfer-Adressen mit individuellen Beträgen
        from_addresses_hop0 = []
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
                        if prev_tx:
                            prev_out = prev_tx.get("vout", [])[prev_vout_idx] if prev_vout_idx < len(prev_tx.get("vout", [])) else {}
                            addr = prev_out.get("scriptPubKey", {}).get("address")
                            val = prev_out.get("value", 0)
                    except Exception:
                        pass
            if addr and addr in victim_set:
                btc = val if isinstance(val, float) and val < 100 else val / 1e8
                from_addresses_hop0.append((addr, btc))

        if not from_addresses_hop0:
            from_addresses_hop0 = [(a, None) for a in req.victim_addresses]

        # To: Empfänger + direkte Exchange-Outputs
        to_addresses_hop0 = [(req.recipient_address, recipient_output_btc if recipient_output_btc > 0 else float(req.fraud_amount_btc or 0))]
        for addr, info in direct_exchanges.items():
            if addr != req.recipient_address:
                to_addresses_hop0.append((addr, info["btc"]))

        hop0_has_exchange = bool(direct_exchanges)
        hop0_exchange = next(iter(direct_exchanges.values())) if direct_exchanges else None

        hop0_notes = (f"{len(req.victim_addresses)} Opfer-Adresse(n). "
                      f"Gestohlener Betrag: {req.fraud_amount_btc} BTC.")
        if hop0_has_exchange:
            ex_names = ", ".join(set(v["exchange"] for v in direct_exchanges.values()))
            hop0_notes += f" Direkte Exchange-Outputs erkannt: {ex_names}."

        hop0 = {
            "hop": 0,
            "label": f"Diebstahl → {hop0_exchange['exchange']}" if hop0_exchange else "Diebstahl — Konsolidierung",
            "txid": req.fraud_txid,
            "block": hop0_block or 0,
            "timestamp": hop0_ts if hop0_ts != "—" else req.incident_date,
            "from_addresses": from_addresses_hop0,
            "to_addresses": to_addresses_hop0,
            "fee_btc": None,
            "confidence": "L2" if hop0_has_exchange else "L1",
            "confidence_label": "Forensisch belegt" if hop0_has_exchange else "Mathematisch bewiesen",
            "method": f"WalletExplorer Attribution ({hop0_exchange.get('label', '')})" if hop0_exchange else "Direkter UTXO-Link",
            "notes": hop0_notes,
            "is_sanctioned": any(c.get("is_sanctioned") for c in _attribution_cache.values()),
        }
        if hop0_exchange:
            hop0["exchange"] = hop0_exchange["exchange"]
            hop0["exchange_wallet_id"] = hop0_exchange.get("wallet_id", "")
            hop0["exchange_source"] = hop0_exchange.get("source", "")

        # 6. Chain nur ab Empfänger verfolgen (fokussiert, kein Branching)
        hops = _trace_victim_chain(req.fraud_txid, req.recipient_address, rpc, conn)
        conn.close()

        # 7. Exchanges aus allen Hops
        all_hops = [hop0] + hops
        exchanges = _build_exchanges(all_hops)

        # 8. PDF + Freeze Requests
        pdf_path = _generate_pdf(case_id, req, hop0, hops, exchanges)
        freeze_paths = _generate_freeze_requests(case_id, exchanges)

        logger.info(f"{case_id}: {len(all_hops)} hops, exchanges: {[e['name'] for e in exchanges]}")

        return JSONResponse({
            "case_id": case_id,
            "status": "success",
            "hops_found": len(all_hops),
            "exchanges_identified": [e["name"] for e in exchanges],
            "actual_amount_btc": req.fraud_amount_btc,
            "sanctioned_addresses": sum(1 for h in all_hops if h.get("is_sanctioned")),
            "freeze_requests_generated": len(freeze_paths),
            "pdf_download_url": f"/api/intel/report-pdf/{case_id}",
            "freeze_request_urls": list({f"/api/intel/freeze-pdf/{case_id}/{ex['name']}" for ex in exchanges}),
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Fehler {case_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


def _get_rpc():
    from src.afci.ingest.bitcoin_rpc import BitcoinRpcClient
    return BitcoinRpcClient(
        url=os.environ.get("BITCOIN_RPC_URL", "http://192.168.178.93:8332"),
        user=os.environ.get("BITCOIN_RPC_USER", "aifc"),
        password=os.environ.get("BITCOIN_RPC_PASSWORD", "CHANGE_ME"),
    )


def _get_conn():
    return psycopg2.connect(os.environ["POSTGRES_DSN"])


@router_report.get("/report-pdf/{case_id}")
async def download_report(case_id: str):
    path = OUTPUT_DIR / f"{case_id}_Forensischer_Analysebericht.pdf"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report nicht gefunden")
    return FileResponse(str(path), media_type="application/pdf",
                        filename=f"{case_id}_Analysebericht.pdf")


@router_report.get("/freeze-pdf/{case_id}/{exchange}")
async def download_freeze(case_id: str, exchange: str):
    path = OUTPUT_DIR / f"{case_id}_Freeze_Request_{exchange}.pdf"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Freeze Request nicht gefunden")
    return FileResponse(str(path), media_type="application/pdf",
                        filename=f"{case_id}_Freeze_{exchange}.pdf")
