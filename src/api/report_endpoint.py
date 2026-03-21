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


def _check_address(address: str) -> dict:
    """Prüft Adresse auf Exchange-Attribution und Sanctions. Mit Cache."""
    if address in _attribution_cache:
        return _attribution_cache[address]

    result = {"exchange": None, "is_sanctioned": False, "source": None,
              "label": None, "wallet_id": None, "confidence": "L1"}

    attribution = _walletexplorer_lookup(address)
    if not attribution:
        time.sleep(0.2)
        attribution = _blockchair_lookup(address)
    if attribution:
        result.update(attribution)

    result["is_sanctioned"] = _chainalysis_check(address)
    _attribution_cache[address] = result
    return result


# ---------------------------------------------------------------------------
# TX-Daten holen
# ---------------------------------------------------------------------------

def _get_tx(txid: str, rpc) -> Optional[dict]:
    """TX via RPC, Fallback Blockstream."""
    try:
        return rpc.call("getrawtransaction", [txid, True])
    except Exception:
        pass
    try:
        url = f"https://blockstream.info/api/tx/{txid}"
        req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/2.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        logger.warning(f"Could not get TX {txid[:16]}: {e}")
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
    - Verfolgt ALLE Outputs einer TX die >= 10% des Eingangsbetrags sind
    - Jeder Pfad endet bei Exchange oder unspent UTXO
    - visited_spending_txids verhindert Schleifen
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

        current_tx = _get_tx(current_txid, rpc)
        if not current_tx:
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
            continue

        # Spending TX finden
        spending_txid = _get_spending_txid(current_txid, vout_idx, rpc)
        if not spending_txid:
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
                        break
            continue

        if spending_txid in visited_spending_txids:
            continue
        visited_spending_txids.add(spending_txid)

        spending_tx = _get_tx(spending_txid, rpc)
        if not spending_tx:
            continue
        _save_tx_to_db(spending_txid, spending_tx, conn)

        to_block, ts_str = _get_tx_block_info(spending_tx)
        to_outputs = _get_tx_outputs(spending_tx)

        # Alle Outputs auf Exchange und Sanctions pruefen
        exchange_hits = {}
        sanctioned = False
        for addr, _ in to_outputs:
            check = _check_address(addr)
            if check.get("exchange"):
                exchange_hits[addr] = check
            if check.get("is_sanctioned"):
                sanctioned = True

        # Relevante Outputs: Exchange-Outputs + Outputs >= 10% des from_amount
        threshold = max(actual_from_amount * 0.10, 0.0001)
        relevant_outputs = []
        for addr, btc in to_outputs:
            if addr in exchange_hits:
                relevant_outputs.append((addr, btc, True))
            elif btc >= threshold:
                relevant_outputs.append((addr, btc, False))

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
        else:
            label = "UTXO Weiterleitung"
            method = "Direkter UTXO-Link"
            notes = "Automatisch erkannt via Pi-Node + Blockstream."
            confidence = "L1"

        if sanctioned:
            notes += " SANKTIONIERTE ADRESSE (OFAC SDN)."

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
        }

        if exchange_hits:
            first_ex_addr = next(iter(exchange_hits))
            first_ex = exchange_hits[first_ex_addr]
            hop["exchange"] = first_ex["exchange"]
            hop["exchange_wallet_id"] = first_ex.get("wallet_id", "")
            hop["exchange_source"] = first_ex.get("source", "")

        hops.append(hop)

        # Nicht-Exchange Outputs weiterverfolgen
        if not exchange_hits:
            for addr, btc, is_exchange in relevant_outputs:
                if not is_exchange:
                    queue.append((spending_txid, addr, btc, hop_idx + 1))

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
    seen = {}
    for hop in all_hops:
        name = hop.get("exchange")
        if not name or name in seen:
            continue
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
    Forensische Analyse — fokussiert auf den Pfad des gestohlenen Geldes.
    """
    _attribution_cache.clear()

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

        # 3. Gestohlenen Betrag berechnen
        # = Summe der Inputs der ausgewählten Opfer-Adressen via RPC prevout
        victim_set = set(req.victim_addresses)
        actual_amount = _get_victim_amount_from_inputs(fraud_tx, victim_set, rpc)
        if actual_amount > 0:
            req.fraud_amount_btc = f"{actual_amount:.8f}"
        else:
            # Fallback: Output an Empfänger-Adresse
            for vout in fraud_tx.get("vout", []):
                addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
                if addr == req.recipient_address:
                    val = vout.get("value", 0)
                    req.fraud_amount_btc = f"{val if isinstance(val, float) else val/1e8:.8f}"
                    break

        # 4. Alle Outputs der Fraud-TX auf Exchange prüfen
        direct_exchanges = {}
        fraud_tx_outputs = _get_tx_outputs(fraud_tx)
        for addr, btc in fraud_tx_outputs:
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
        to_addresses_hop0 = [(req.recipient_address, float(req.fraud_amount_btc or 0))]
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
            "freeze_request_urls": [f"/api/intel/freeze-pdf/{case_id}/{ex['name']}" for ex in exchanges],
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
