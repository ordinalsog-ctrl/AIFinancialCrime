"""
AIFinancialCrime — Report Endpoint v3
======================================
KOMPLETTER NEUBAU — Globale saubere Architektur

Analyse-Flow:
  1. TX via RPC holen → alle Inputs/Outputs
  2. Ausgewählte Opfer-Adressen identifizieren → korrekten Betrag aus Inputs berechnen
  3. Von Empfänger-Adresse aus Chain VOLLSTÄNDIG via RPC verfolgen (unabhängig von DB)
  4. Jede Adresse gegen WalletExplorer + Blockchair + Chainalysis prüfen
  5. Alle TXs in DB speichern
  6. PDF + Freeze Requests generieren

Prinzip:
  - RPC ist die Quelle der Wahrheit (Pi-Node)
  - DB ist Cache/Persistenz
  - Exchange-Attribution für JEDE Adresse in der Chain
  - Betrag immer aus tatsächlichen UTXOs berechnet
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
    fraud_amount_btc: str  # Wird überschrieben durch tatsächliche UTXO-Berechnung
    fraud_amount_eur: Optional[str] = ""
    victim_addresses: list[str] = []  # Vom User ausgewählte Opfer-Adressen
    recipient_address: str
    additional_notes: Optional[str] = ""


# ---------------------------------------------------------------------------
# Infrastruktur
# ---------------------------------------------------------------------------

def _get_rpc():
    from src.afci.ingest.bitcoin_rpc import BitcoinRpcClient
    return BitcoinRpcClient(
        url=os.environ.get("BITCOIN_RPC_URL", "http://192.168.178.93:8332"),
        user=os.environ.get("BITCOIN_RPC_USER", "aifc"),
        password=os.environ.get("BITCOIN_RPC_PASSWORD", "CHANGE_ME"),
    )


def _get_conn():
    return psycopg2.connect(os.environ["POSTGRES_DSN"])


# ---------------------------------------------------------------------------
# Exchange Attribution — für jede Adresse
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

# Cache für Attribution-Lookups (vermeidet doppelte API-Calls)
_attribution_cache: dict[str, dict] = {}


def _walletexplorer_lookup(address: str) -> Optional[dict]:
    """WalletExplorer Attribution — kostenlos, gute Exchange-Abdeckung."""
    try:
        url = (f"https://www.walletexplorer.com/api/1/address"
               f"?address={address}&from=0&count=1&caller=AIFinancialCrime")
        req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/2.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        if not data.get("found") or not data.get("label"):
            return None
        label_raw = data["label"]
        label_lower = label_raw.lower()
        exchange_name = next(
            (name for key, name in KNOWN_EXCHANGES.items() if key in label_lower),
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
    """Blockchair Attribution — mit API Key."""
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
        tag_lower = tag.lower()
        exchange_name = next(
            (name for key, name in KNOWN_EXCHANGES.items() if key in tag_lower),
            tag
        )
        return {
            "exchange": exchange_name,
            "label": tag,
            "wallet_id": "",
            "source": "blockchair",
            "confidence": "L2",
        }
    except Exception as e:
        logger.debug(f"Blockchair failed {address[:20]}: {e}")
        return None


def _chainalysis_check(address: str) -> bool:
    """Chainalysis Sanctions Check — OFAC SDN."""
    api_key = os.environ.get("CHAINALYSIS_API_KEY")
    if not api_key:
        return False
    try:
        url = f"https://public.chainalysis.com/api/v1/address/{address}"
        req = urllib.request.Request(url, headers={
            "X-API-Key": api_key,
            "Accept": "application/json",
            "User-Agent": "AIFinancialCrime/2.0",
        })
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        return bool(data.get("identifications"))
    except Exception:
        return False


def _check_address(address: str) -> dict:
    """
    Vollständige Adress-Prüfung mit Cache.
    Gibt dict zurück: {exchange, is_sanctioned, source, label, wallet_id, confidence}
    """
    if address in _attribution_cache:
        return _attribution_cache[address]

    result = {
        "exchange": None,
        "is_sanctioned": False,
        "source": None,
        "label": None,
        "wallet_id": None,
        "confidence": "L1",
    }

    # 1. WalletExplorer
    attribution = _walletexplorer_lookup(address)
    if not attribution:
        time.sleep(0.2)
        # 2. Blockchair als Fallback
        attribution = _blockchair_lookup(address)

    if attribution:
        result.update(attribution)

    # 3. Sanctions Check
    result["is_sanctioned"] = _chainalysis_check(address)

    _attribution_cache[address] = result
    return result


# ---------------------------------------------------------------------------
# TX-Daten via RPC holen
# ---------------------------------------------------------------------------

def _get_tx_via_rpc(txid: str, rpc) -> Optional[dict]:
    """Holt vollständige TX-Daten via Bitcoin RPC."""
    try:
        raw = rpc.call("getrawtransaction", [txid, True])
        return raw
    except Exception as e:
        logger.warning(f"RPC getrawtransaction failed for {txid[:16]}: {e}")
        return None


def _get_tx_via_blockstream(txid: str) -> Optional[dict]:
    """Fallback: TX-Daten via Blockstream API holen."""
    try:
        url = f"https://blockstream.info/api/tx/{txid}"
        req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/2.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        logger.warning(f"Blockstream failed for {txid[:16]}: {e}")
        return None


def _calculate_victim_amount(tx_data: dict, victim_addresses: list[str], rpc=None) -> float:
    """
    Berechnet den tatsächlichen gestohlenen Betrag.
    
    Strategie:
    1. Prüfe ob Inputs prevout-Daten haben (Blockstream Format)
    2. Falls nicht: hole prevout via RPC für jede Input-TX
    3. Fallback: summiere alle Outputs der TX (Gesamt-Output)
    """
    total = 0.0
    victim_set = set(victim_addresses)
    
    for vin in tx_data.get("vin", []):
        # Blockstream Format — prevout direkt vorhanden
        prevout = vin.get("prevout", {})
        addr = prevout.get("scriptpubkey_address") or prevout.get("scriptPubKey", {}).get("address")
        
        if not addr and rpc and vin.get("txid"):
            # RPC Format — prevout via separaten Lookup holen
            try:
                prev_txid = vin["txid"]
                prev_vout = vin["vout"]
                prev_tx = rpc.call("getrawtransaction", [prev_txid, True])
                if prev_tx:
                    prev_out = prev_tx.get("vout", [])[prev_vout] if prev_vout < len(prev_tx.get("vout", [])) else {}
                    addr = prev_out.get("scriptPubKey", {}).get("address")
                    if addr in victim_set:
                        val = prev_out.get("value", 0)
                        total += val
                        continue
            except Exception as e:
                logger.debug(f"prevout lookup failed: {e}")
        
        if addr and addr in victim_set:
            val = prevout.get("value", 0)
            if val == 0 and rpc and vin.get("txid"):
                try:
                    prev_txid = vin["txid"]
                    prev_vout = vin.get("vout", 0)
                    prev_tx = rpc.call("getrawtransaction", [prev_txid, True])
                    if prev_tx and prev_vout < len(prev_tx.get("vout", [])):
                        val = prev_tx["vout"][prev_vout].get("value", 0)
                except Exception:
                    pass
            total += val
    
    return total


def _get_tx_block_info(tx_data: dict) -> tuple[int, str]:
    """Extrahiert Block-Höhe und Timestamp aus TX-Daten."""
    # RPC Format
    block_height = tx_data.get("blockheight", 0) or 0
    block_time = tx_data.get("blocktime", 0)
    
    # Blockstream Format
    status = tx_data.get("status", {})
    if status:
        block_height = status.get("block_height", block_height)
        block_time = status.get("block_time", block_time)
    
    if block_time:
        ts = datetime.fromtimestamp(block_time, tz=timezone.utc)
        ts_str = ts.strftime("%d.%m.%Y %H:%M UTC")
    else:
        ts_str = "—"
    
    return block_height, ts_str


# ---------------------------------------------------------------------------
# Chain Tracing — vollständig via RPC
# ---------------------------------------------------------------------------

def _save_tx_to_db(txid: str, tx_data: dict, conn):
    """Speichert TX in DB (best-effort)."""
    try:
        from src.afci.ingest.run_ingest import ingest_tx_by_txid
        from src.afci.db.postgres import link_spent_outputs_for_tx, tx as db_tx
        
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM transactions WHERE txid = %s", (txid,))
            if cur.fetchone():
                return
        
        # Block-Info
        block_height, _ = _get_tx_block_info(tx_data)
        block_time = tx_data.get("blocktime") or tx_data.get("status", {}).get("block_time")
        
        first_seen = None
        if block_time:
            first_seen = datetime.fromtimestamp(block_time, tz=timezone.utc)
        
        with db_tx(conn):
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO transactions (txid, block_height, first_seen)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (txid) DO NOTHING
                """, (txid, block_height or None, first_seen))
                
                # Outputs speichern
                vout_list = tx_data.get("vout", [])
                for i, vout in enumerate(vout_list):
                    # RPC Format
                    addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
                    value = vout.get("value", 0)
                    if isinstance(value, float) and value < 1:
                        amount_sats = int(value * 1e8)
                    else:
                        amount_sats = int(value)
                    
                    if addr:
                        cur.execute("""
                            INSERT INTO tx_outputs (txid, vout_index, address, amount_sats)
                            VALUES (%s, %s, %s, %s)
                            ON CONFLICT (txid, vout_index) DO NOTHING
                        """, (txid, i, addr, amount_sats))
                
                # Inputs speichern
                vin_list = tx_data.get("vin", [])
                for i, vin in enumerate(vin_list):
                    prev_txid = vin.get("txid")
                    prev_vout = vin.get("vout")
                    prevout = vin.get("prevout", {})
                    addr = prevout.get("scriptPubKey", {}).get("address") or prevout.get("scriptpubkey_address")
                    value = prevout.get("value", 0)
                    if isinstance(value, float) and value < 1:
                        amount_sats = int(value * 1e8)
                    else:
                        amount_sats = int(value)
                    
                    if prev_txid:
                        cur.execute("""
                            INSERT INTO tx_inputs (txid, vin_index, prev_txid, prev_vout, address, amount_sats)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (txid, vin_index) DO NOTHING
                        """, (txid, i, prev_txid, prev_vout, addr, amount_sats))
                        
                        # spent_by_txid in tx_outputs setzen
                        if prev_txid and prev_vout is not None:
                            cur.execute("""
                                UPDATE tx_outputs
                                SET spent_by_txid = %s
                                WHERE txid = %s AND vout_index = %s
                            """, (txid, prev_txid, prev_vout))
    
    except Exception as e:
        logger.warning(f"DB save failed for {txid[:16]}: {e}")


def _trace_full_chain(fraud_txid: str, recipient_address: str, rpc, conn, max_hops: int = 10) -> list:
    """
    Verfolgt die KOMPLETTE Chain ab der Fraud-TX.
    
    Strategie:
    1. Fraud-TX holen → Outputs identifizieren
    2. Für jeden Output: nächste TX via RPC holen
    3. Rekursiv weitermachen bis Exchange gefunden oder max_hops erreicht
    4. Jede Adresse auf Exchange/Sanctions prüfen
    5. Alle TXs in DB speichern
    """
    hops = []
    visited_txids = set()
    visited_txids.add(fraud_txid)
    
    # Start: Alle Outputs der Fraud-TX verfolgen
    # Wir verfolgen den recipient_address Output
    queue = [(fraud_txid, recipient_address, 1)]
    
    while queue and len(hops) < max_hops:
        from_txid, tracked_address, hop_idx = queue.pop(0)
        
        if hop_idx > max_hops:
            break
        
        # TX holen (RPC zuerst, dann Blockstream als Fallback)
        from_tx = _get_tx_via_rpc(from_txid, rpc)
        if not from_tx:
            from_tx = _get_tx_via_blockstream(from_txid)
        if not from_tx:
            logger.warning(f"Could not get TX data for {from_txid[:16]}")
            continue
        
        # TX in DB speichern
        _save_tx_to_db(from_txid, from_tx, conn)
        
        # Finde den Output mit der tracked_address
        vout_list = from_tx.get("vout", [])
        
        for vout_idx, vout in enumerate(vout_list):
            addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
            if addr != tracked_address:
                continue
            
            value = vout.get("value", 0)
            amount_btc = value if isinstance(value, float) and value < 100 else value / 1e8
            
            # Finde die TX die diesen Output ausgibt
            # Via RPC: gettxout prüfen ob UTXO noch unspent
            spending_txid = None
            try:
                utxo = rpc.call("gettxout", [from_txid, vout_idx])
                if utxo is None:
                    # Output wurde ausgegeben — wir müssen die spending TX finden
                    # Via Blockstream API (RPC hat kein direktes "find spending tx")
                    bstream_url = f"https://blockstream.info/api/tx/{from_txid}/outspend/{vout_idx}"
                    req = urllib.request.Request(bstream_url, headers={"User-Agent": "AIFinancialCrime/2.0"})
                    with urllib.request.urlopen(req, timeout=10) as r:
                        spend_data = json.loads(r.read())
                    if spend_data.get("spent"):
                        spending_txid = spend_data.get("txid")
            except Exception as e:
                logger.debug(f"Could not find spending TX for {from_txid[:16]}:{vout_idx}: {e}")
            
            if not spending_txid or spending_txid in visited_txids:
                # UTXO unspent oder bereits besucht — Adresse prüfen
                check = _check_address(tracked_address)
                if check.get("exchange") and len(hops) > 0:
                    # Letzen Hop als Exchange markieren
                    if hops:
                        hops[-1]["confidence"] = "L2"
                        hops[-1]["confidence_label"] = "Forensisch belegt"
                        hops[-1]["exchange"] = check["exchange"]
                        hops[-1]["exchange_wallet_id"] = check.get("wallet_id", "")
                        hops[-1]["exchange_source"] = check.get("source", "")
                        hops[-1]["label"] = f"Exchange-Einzahlung → {check['exchange']}"
                        hops[-1]["method"] = f"WalletExplorer/Blockchair Attribution ({check.get('label', '')})"
                        hops[-1]["notes"] += f" Adresse identifiziert als {check['exchange']} via {check['source']}."
                continue
            
            visited_txids.add(spending_txid)
            
            # Spending TX holen
            spending_tx = _get_tx_via_rpc(spending_txid, rpc)
            if not spending_tx:
                spending_tx = _get_tx_via_blockstream(spending_txid)
            if not spending_tx:
                continue
            
            _save_tx_to_db(spending_txid, spending_tx, conn)
            
            # Block-Info der Spending TX
            to_block, ts_str = _get_tx_block_info(spending_tx)
            
            # Alle Outputs der Spending TX
            to_outputs = []
            for out in spending_tx.get("vout", []):
                out_addr = out.get("scriptPubKey", {}).get("address") or out.get("scriptpubkey_address")
                out_val = out.get("value", 0)
                out_btc = out_val if isinstance(out_val, float) and out_val < 100 else out_val / 1e8
                if out_addr:
                    to_outputs.append((out_addr, out_btc))
            
            # Exchange/Sanctions für alle Output-Adressen prüfen
            exchange_hit = None
            any_sanctioned = False
            
            for out_addr, _ in to_outputs[:10]:
                check = _check_address(out_addr)
                if check.get("exchange") and not exchange_hit:
                    exchange_hit = check
                    exchange_hit["address"] = out_addr
                if check.get("is_sanctioned"):
                    any_sanctioned = True
            
            # Hop bauen
            confidence = "L2" if exchange_hit else "L1"
            confidence_label = "Forensisch belegt" if exchange_hit else "Mathematisch bewiesen"
            
            if exchange_hit:
                label = f"Exchange-Einzahlung → {exchange_hit['exchange']}"
                method = f"WalletExplorer/Blockchair Attribution ({exchange_hit.get('label', '')})"
                notes = (f"Automatisch erkannt via Pi-Node + WalletExplorer. "
                         f"Adresse {exchange_hit['address'][:20]}... identifiziert als "
                         f"{exchange_hit['exchange']} via {exchange_hit['source']}. "
                         f"Wallet-ID: {exchange_hit.get('wallet_id') or '—'}.")
            else:
                label = "UTXO Weiterleitung"
                method = "Direkter UTXO-Link"
                notes = "Automatisch erkannt via lokalen Bitcoin-Node (Pi 5)."
            
            if any_sanctioned:
                notes += " ⚠ SANKTIONIERTE ADRESSE (OFAC SDN)."
            
            hop = {
                "hop": hop_idx,
                "label": label,
                "txid": spending_txid,
                "block": to_block or 0,
                "timestamp": ts_str,
                "from_addresses": [(tracked_address, amount_btc)],
                "to_addresses": to_outputs,
                "fee_btc": None,
                "confidence": confidence,
                "confidence_label": confidence_label,
                "method": method,
                "notes": notes,
                "is_sanctioned": any_sanctioned,
            }
            
            if exchange_hit:
                hop["exchange"] = exchange_hit["exchange"]
                hop["exchange_wallet_id"] = exchange_hit.get("wallet_id", "")
                hop["exchange_source"] = exchange_hit.get("source", "")
            
            hops.append(hop)
            
            # Alle Outputs weiterverfolgen (außer bekannte Exchanges)
            for out_addr, _ in to_outputs:
                if not out_addr:
                    continue
                # Nicht weiterverfolgen wenn Exchange identifiziert
                cached = _attribution_cache.get(out_addr, {})
                if cached.get("exchange"):
                    continue
                queue.append((spending_txid, out_addr, hop_idx + 1))
            
            break  # Pro Output nur einmal
    
    return hops


# ---------------------------------------------------------------------------
# Exchanges aus Hops extrahieren
# ---------------------------------------------------------------------------

def _build_exchanges(hops: list) -> list:
    """Extrahiert eindeutige Exchanges aus allen Hops für Report-Header."""
    seen = {}
    for hop in hops:
        name = hop.get("exchange")
        if not name or name in seen:
            continue
        # Exchange-Adresse aus to_addresses finden
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
        
        seen[name] = {
            "name": name,
            "address": ex_addr,
            "wallet_id": hop.get("exchange_wallet_id", "WalletExplorer"),
            "label": name,
            "tx_count": None,
            "confidence": "L2",
            "compliance_email": EXCHANGE_COMPLIANCE.get(
                name, f"compliance@{name.lower().replace(' ', '').replace('.', '')}.com"
            ),
            "compliance_url": "",
            "btc_involved": ex_btc,
            "note": f"Identifiziert via {hop.get('exchange_source', 'WalletExplorer')}.",
        }
    return list(seen.values())


# ---------------------------------------------------------------------------
# PDF Generierung
# ---------------------------------------------------------------------------

def _generate_pdf(case_id: str, req: ReportRequest, hop0: dict, hops: list, exchanges: list) -> str:
    """Generiert PDF via generate_case_report.py."""
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
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=gcr.MARGIN, rightMargin=gcr.MARGIN,
        topMargin=18 * mm, bottomMargin=16 * mm,
    )
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
    """Generiert Freeze-Request PDFs für alle identifizierten Exchanges."""
    import src.investigation.generate_case_report as gcr
    styles = gcr._styles()
    paths = []
    for ex in exchanges:
        path = str(OUTPUT_DIR / f"{case_id}_Freeze_Request_{ex['name']}.pdf")
        try:
            gcr._freeze_request(ex, styles, path)
            paths.append(path)
        except Exception as e:
            logger.warning(f"Freeze request failed for {ex['name']}: {e}")
    return paths


# ---------------------------------------------------------------------------
# Hauptendpoint
# ---------------------------------------------------------------------------

@router_report.post("/generate-report")
async def generate_report(req: ReportRequest):
    """
    Vollständige forensische Analyse.
    
    Flow:
    1. Fraud-TX via RPC/Blockstream holen
    2. Tatsächlichen gestohlenen Betrag aus Opfer-Adressen berechnen
    3. Chain vollständig verfolgen (RPC-first, Blockstream als Fallback)
    4. Jede Adresse auf Exchange + Sanctions prüfen
    5. PDF + Freeze Requests generieren
    """
    # Cache leeren für neue Analyse
    _attribution_cache.clear()
    
    case_id = req.case_id or (
        f"AIFC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-"
        f"{str(uuid.uuid4())[:8].upper()}"
    )

    try:
        conn = _get_conn()
        rpc = _get_rpc()

        logger.info(f"Analyse gestartet: {case_id}, txid={req.fraud_txid[:16]}")

        # 1. Fraud-TX holen
        fraud_tx = _get_tx_via_rpc(req.fraud_txid, rpc)
        if not fraud_tx:
            fraud_tx = _get_tx_via_blockstream(req.fraud_txid)
        if not fraud_tx:
            raise HTTPException(status_code=400, detail=f"TX {req.fraud_txid[:16]}... nicht gefunden")

        # 2. TX in DB speichern
        _save_tx_to_db(req.fraud_txid, fraud_tx, conn)

        # 3. Block-Info für Hop 0
        hop0_block, hop0_ts = _get_tx_block_info(fraud_tx)

        # 4. Tatsächlichen Betrag berechnen — via RPC prevout lookup
        actual_amount = _calculate_victim_amount(fraud_tx, req.victim_addresses, rpc=rpc)
        if actual_amount > 0:
            req.fraud_amount_btc = f"{actual_amount:.8f}"
        
        # 5. ALLE Outputs der Fraud-TX auf Exchange prüfen
        all_outputs_checks = {}
        for vout in fraud_tx.get("vout", []):
            addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
            if addr:
                check = _check_address(addr)
                all_outputs_checks[addr] = check
        
        # Primärer Empfänger
        recipient_check = all_outputs_checks.get(req.recipient_address, _check_address(req.recipient_address))
        
        # Direkte Exchange-Outputs in Hop 0 einfließen lassen
        direct_exchanges = {
            addr: check for addr, check in all_outputs_checks.items()
            if check.get("exchange")
        }

        # 6. Hop 0 bauen
        hop0_confidence = "L2" if recipient_check.get("exchange") else "L1"
        hop0_notes = (f"{len(req.victim_addresses)} Opfer-Adressen. "
                      f"Vollständiger Saldo abgezogen.")
        if recipient_check.get("exchange"):
            hop0_notes += (f" Empfänger direkt als {recipient_check['exchange']} "
                           f"identifiziert via {recipient_check.get('source', 'WalletExplorer')}.")
        if recipient_check.get("is_sanctioned"):
            hop0_notes += " ⚠ SANKTIONIERTE ADRESSE (OFAC SDN)."

        # Korrekte Input-Beträge aus TX-Daten
        from_addresses_hop0 = []
        for vin in fraud_tx.get("vin", []):
            prevout = vin.get("prevout", {})
            addr = prevout.get("scriptPubKey", {}).get("address") or prevout.get("scriptpubkey_address")
            val = prevout.get("value", 0)
            btc = val if isinstance(val, float) and val < 100 else val / 1e8
            if addr and addr in req.victim_addresses:
                from_addresses_hop0.append((addr, btc))
        
        if not from_addresses_hop0:
            from_addresses_hop0 = [(a, None) for a in req.victim_addresses]

        # Alle Outputs der Fraud-TX als to_addresses
        hop0_to_addresses = []
        for vout in fraud_tx.get("vout", []):
            addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
            val = vout.get("value", 0)
            btc = val if isinstance(val, float) and val < 100 else val / 1e8
            if addr:
                hop0_to_addresses.append((addr, btc))
        if not hop0_to_addresses:
            hop0_to_addresses = [(req.recipient_address, float(req.fraud_amount_btc or 0))]

        # Confidence: L2 wenn irgendein Output eine Exchange ist
        hop0_confidence = "L2" if direct_exchanges else "L1"
        hop0_label = "Diebstahl — Konsolidierung"
        if direct_exchanges:
            ex_names = ", ".join(set(c["exchange"] for c in direct_exchanges.values()))
            hop0_label = f"Diebstahl → {ex_names}"
            hop0_notes += f" Direkte Exchange-Outputs: {ex_names}."

        hop0 = {
            "hop": 0,
            "label": hop0_label,
            "txid": req.fraud_txid,
            "block": hop0_block or 0,
            "timestamp": hop0_ts if hop0_ts != "—" else req.incident_date,
            "from_addresses": from_addresses_hop0,
            "to_addresses": hop0_to_addresses,
            "fee_btc": None,
            "confidence": hop0_confidence,
            "confidence_label": "Forensisch belegt" if hop0_confidence == "L2" else "Mathematisch bewiesen",
            "method": f"WalletExplorer/Blockchair Attribution" if direct_exchanges else "Direkter UTXO-Link",
            "notes": hop0_notes,
            "is_sanctioned": any(c.get("is_sanctioned") for c in all_outputs_checks.values()),
        }
        # Erste Exchange als primäre Exchange für Hop 0
        if direct_exchanges:
            first_ex = next(iter(direct_exchanges.values()))
            hop0["exchange"] = first_ex["exchange"]
            hop0["exchange_wallet_id"] = first_ex.get("wallet_id", "")
            hop0["exchange_source"] = first_ex.get("source", "")

        # 7. Chain vollständig tracen
        hops = _trace_full_chain(req.fraud_txid, req.recipient_address, rpc, conn)
        conn.close()

        # 8. Exchanges aus allen Hops (inkl. hop0) extrahieren
        all_hops = [hop0] + hops
        exchanges = _build_exchanges(all_hops)

        # 9. PDF + Freeze Requests
        pdf_path = _generate_pdf(case_id, req, hop0, hops, exchanges)
        freeze_paths = _generate_freeze_requests(case_id, exchanges)

        sanctioned_count = sum(1 for h in all_hops if h.get("is_sanctioned"))

        logger.info(f"{case_id}: {len(all_hops)} hops, {len(exchanges)} exchanges identified")

        return JSONResponse({
            "case_id": case_id,
            "status": "success",
            "hops_found": len(all_hops),
            "exchanges_identified": [e["name"] for e in exchanges],
            "sanctioned_addresses": sanctioned_count,
            "actual_amount_btc": req.fraud_amount_btc,
            "freeze_requests_generated": len(freeze_paths),
            "pdf_download_url": f"/api/intel/report-pdf/{case_id}",
            "freeze_request_urls": [
                f"/api/intel/freeze-pdf/{case_id}/{ex['name']}"
                for ex in exchanges
            ],
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analyse fehlgeschlagen {case_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


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
