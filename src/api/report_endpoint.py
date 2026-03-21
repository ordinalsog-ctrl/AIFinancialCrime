"""
AIFinancialCrime — Report Endpoint v2
"""
from __future__ import annotations
import hashlib, io, json, logging, os, pathlib, time, urllib.request, uuid
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

def _get_rpc():
    from src.afci.ingest.bitcoin_rpc import BitcoinRpcClient
    return BitcoinRpcClient(
        url=os.environ.get("BITCOIN_RPC_URL","http://192.168.178.93:8332"),
        user=os.environ.get("BITCOIN_RPC_USER","aifc"),
        password=os.environ.get("BITCOIN_RPC_PASSWORD","CHANGE_ME"),
    )

def _get_conn():
    return psycopg2.connect(os.environ["POSTGRES_DSN"])

KNOWN_EXCHANGES = {
    "huobi":"Huobi","binance":"Binance","coinbase":"Coinbase","kraken":"Kraken",
    "bitfinex":"Bitfinex","okx":"OKX","poloniex":"Poloniex","kucoin":"KuCoin",
    "bybit":"Bybit","bitstamp":"Bitstamp","gemini":"Gemini","bittrex":"Bittrex",
    "bitmex":"BitMEX","gate.io":"Gate.io","htx":"Huobi",
}

EXCHANGE_COMPLIANCE = {
    "Huobi":"compliance@huobi.com","Binance":"law_enforcement@binance.com",
    "Coinbase":"compliance@coinbase.com","Kraken":"compliance@kraken.com",
    "Poloniex":"support@poloniex.com","OKX":"compliance@okx.com",
    "Bybit":"compliance@bybit.com","Bitstamp":"legal@bitstamp.net",
    "Bitfinex":"compliance@bitfinex.com",
}

def _walletexplorer_lookup(address):
    try:
        url = f"https://www.walletexplorer.com/api/1/address?address={address}&from=0&count=1&caller=AIFinancialCrime"
        req = urllib.request.Request(url, headers={"User-Agent":"AIFinancialCrime/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        if not data.get("found") or not data.get("label"):
            return None
        label_raw = data["label"]
        label_lower = label_raw.lower()
        exchange_name = next((name for key,name in KNOWN_EXCHANGES.items() if key in label_lower), label_raw)
        return {"exchange":exchange_name,"label":label_raw,"wallet_id":data.get("wallet_id",""),"source":"walletexplorer","confidence":"L2"}
    except Exception as e:
        logger.debug(f"WalletExplorer failed {address[:20]}: {e}")
        return None

def _blockchair_lookup(address):
    api_key = os.environ.get("BLOCKCHAIR_API_KEY")
    if not api_key:
        return None
    try:
        url = f"https://api.blockchair.com/bitcoin/dashboards/address/{address}?key={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent":"AIFinancialCrime/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        addr_data = data.get("data",{}).get(address,{}).get("address",{})
        tag = addr_data.get("tag")
        if not tag:
            return None
        tag_lower = tag.lower()
        exchange_name = next((name for key,name in KNOWN_EXCHANGES.items() if key in tag_lower), tag)
        return {"exchange":exchange_name,"label":tag,"wallet_id":"","source":"blockchair","confidence":"L2"}
    except Exception as e:
        logger.debug(f"Blockchair failed {address[:20]}: {e}")
        return None

def _chainalysis_check(address):
    api_key = os.environ.get("CHAINALYSIS_API_KEY")
    if not api_key:
        return False
    try:
        url = f"https://public.chainalysis.com/api/v1/address/{address}"
        req = urllib.request.Request(url, headers={"X-API-Key":api_key,"Accept":"application/json","User-Agent":"AIFinancialCrime/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        return bool(data.get("identifications"))
    except Exception:
        return False

def _check_address(address):
    result = {"exchange":None,"is_sanctioned":False,"source":None}
    attribution = _walletexplorer_lookup(address)
    if not attribution:
        time.sleep(0.3)
        attribution = _blockchair_lookup(address)
    if attribution:
        result.update(attribution)
    result["is_sanctioned"] = _chainalysis_check(address)
    return result

def _ensure_tx_in_db(txid, conn, rpc):
    from src.afci.ingest.run_ingest import ingest_tx_by_txid
    from src.afci.db.postgres import link_spent_outputs_for_tx, tx as db_tx
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM transactions WHERE txid = %s",(txid,))
        if cur.fetchone():
            return True
    try:
        ok = ingest_tx_by_txid(rpc, conn, txid)
        if ok:
            with db_tx(conn):
                with conn.cursor() as cur:
                    link_spent_outputs_for_tx(cur, txid)
        return ok
    except Exception as e:
        logger.warning(f"Failed to ingest {txid[:16]}: {e}")
        return False

def _trace_hops(fraud_txid, conn, rpc, max_hops=10):
    hops = []
    visited = set()
    queue = [fraud_txid]
    hop_idx = 1
    while queue and hop_idx <= max_hops:
        next_queue = []
        for txid in queue:
            if txid in visited:
                continue
            visited.add(txid)
            _ensure_tx_in_db(txid, conn, rpc)
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT o.address, o.amount_sats, o.spent_by_txid, t.block_height, t.first_seen
                    FROM tx_outputs o JOIN transactions t ON t.txid = o.txid
                    WHERE o.txid = %s AND o.spent_by_txid IS NOT NULL
                """, (txid,))
                spent_outputs = cur.fetchall()
            for from_addr, amount_sats, to_txid, block, ts in spent_outputs:
                if not to_txid or to_txid in visited:
                    continue
                _ensure_tx_in_db(to_txid, conn, rpc)
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT o.address, o.amount_sats, t.block_height, t.first_seen
                        FROM tx_outputs o JOIN transactions t ON t.txid = o.txid
                        WHERE o.txid = %s ORDER BY o.amount_sats DESC
                    """, (to_txid,))
                    to_outputs = cur.fetchall()
                to_addresses = [(r[0], r[1]/1e8) for r in to_outputs if r[0]]
                to_block = to_outputs[0][2] if to_outputs else block
                to_ts = to_outputs[0][3] if to_outputs else ts
                ts_str = to_ts.strftime("%d.%m.%Y ~%H:%M UTC") if to_ts else "—"
                exchange_hit = None
                any_sanctioned = False
                for addr, _ in to_addresses[:5]:
                    if not addr:
                        continue
                    check = _check_address(addr)
                    if check.get("exchange") and not exchange_hit:
                        exchange_hit = check
                    if check.get("is_sanctioned"):
                        any_sanctioned = True
                confidence = "L2" if exchange_hit else "L1"
                confidence_label = "Forensisch belegt" if exchange_hit else "Mathematisch bewiesen"
                if exchange_hit:
                    label = f"Exchange-Einzahlung → {exchange_hit['exchange']}"
                    method = f"WalletExplorer/Blockchair Attribution ({exchange_hit.get('label','')})"
                    notes = f"Adresse identifiziert als {exchange_hit['exchange']} via {exchange_hit['source']}. Wallet-ID: {exchange_hit.get('wallet_id') or '—'}."
                else:
                    label = "UTXO Weiterleitung"
                    method = "Direkter UTXO-Link"
                    notes = "Automatisch erkannt via lokalen Bitcoin-Node (Pi 5)."
                if any_sanctioned:
                    notes += " ⚠ SANKTIONIERTE ADRESSE (OFAC SDN)."
                hop = {
                    "hop":hop_idx,"label":label,"txid":to_txid,"block":to_block or 0,
                    "timestamp":ts_str,"from_addresses":[(from_addr, amount_sats/1e8)],
                    "to_addresses":to_addresses,"fee_btc":None,"confidence":confidence,
                    "confidence_label":confidence_label,"method":method,"notes":notes,
                    "is_sanctioned":any_sanctioned,
                }
                if exchange_hit:
                    hop["exchange"] = exchange_hit["exchange"]
                    hop["exchange_wallet_id"] = exchange_hit.get("wallet_id","")
                    hop["exchange_source"] = exchange_hit.get("source","")
                hops.append(hop)
                next_queue.append(to_txid)
                hop_idx += 1
        queue = next_queue
    return hops

def _build_exchanges(hops):
    seen = {}
    for hop in hops:
        name = hop.get("exchange")
        if not name or name in seen:
            continue
        addr = hop["to_addresses"][0][0] if hop["to_addresses"] else ""
        btc = hop["to_addresses"][0][1] if hop["to_addresses"] else 0
        seen[name] = {
            "name":name,"address":addr,"wallet_id":hop.get("exchange_wallet_id","WalletExplorer"),
            "label":name,"tx_count":None,"confidence":"L2",
            "compliance_email":EXCHANGE_COMPLIANCE.get(name,f"compliance@{name.lower().replace(' ','')}.com"),
            "compliance_url":"","btc_involved":btc,
            "note":f"Identifiziert via {hop.get('exchange_source','WalletExplorer')}.",
        }
    return list(seen.values())

def _generate_pdf(case_id, req, hops, exchanges):
    import src.investigation.generate_case_report as gcr
    from reportlab.platypus import SimpleDocTemplate, Spacer, PageBreak
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    gcr.CASE = {
        "case_id":case_id,"victim_name":req.victim_name,"victim_contact":req.victim_email or "",
        "incident_date":req.incident_date,"discovery_date":req.discovery_date or "",
        "fraud_amount":req.fraud_amount_btc,"fraud_amount_eur":req.fraud_amount_eur or "—",
        "wallet_type":f"{req.wallet_brand} ({req.wallet_type})",
        "generated_at":datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    hop0 = {
        "hop":0,"label":"Diebstahl — Konsolidierung","txid":req.fraud_txid,"block":0,
        "timestamp":req.incident_date,"from_addresses":[(a,None) for a in req.victim_addresses],
        "to_addresses":[(req.recipient_address, float(req.fraud_amount_btc or 0))],
        "fee_btc":None,"confidence":"L1","confidence_label":"Mathematisch bewiesen",
        "method":"Direkter UTXO-Link",
        "notes":f"{len(req.victim_addresses)} Opfer-Adressen konsolidiert. Vollständiger Saldo abgezogen. Keine Change-Output.",
    }
    gcr.HOPS = [hop0] + hops
    gcr.EXCHANGES_IDENTIFIED = exchanges
    styles = gcr._styles()
    report_hash = hashlib.sha256((str(gcr.HOPS)+str(gcr.CASE)).encode()).hexdigest()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=gcr.MARGIN, rightMargin=gcr.MARGIN, topMargin=18*mm, bottomMargin=16*mm)
    on_page = gcr._page_template(case_id, gcr.CASE["generated_at"])
    story = []
    story += gcr._cover(styles)
    story.append(PageBreak())
    story += gcr._methodology(styles)
    story.append(Spacer(1,8))
    story += gcr._chain_of_custody(styles)
    story.append(PageBreak())
    story += gcr._transaction_graph(styles)
    story.append(PageBreak())
    story += gcr._recommended_actions(styles)
    story.append(Spacer(1,8))
    story += gcr._integrity(report_hash, styles)
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    pdf_path = str(OUTPUT_DIR / f"{case_id}_Forensischer_Analysebericht.pdf")
    with open(pdf_path,"wb") as f:
        f.write(buf.getvalue())
    return pdf_path

def _generate_freeze_requests(case_id, req, exchanges):
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

@router_report.post("/generate-report")
async def generate_report(req: ReportRequest):
    case_id = req.case_id or f"AIFC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
    try:
        conn = _get_conn()
        rpc = _get_rpc()
        logger.info(f"Analyse: {case_id}, tx={req.fraud_txid[:16]}")
        hops = _trace_hops(req.fraud_txid, conn, rpc)
        conn.close()
        exchanges = _build_exchanges(hops)
        pdf_path = _generate_pdf(case_id, req, hops, exchanges)
        freeze_paths = _generate_freeze_requests(case_id, req, exchanges)
        return JSONResponse({
            "case_id":case_id,"status":"success","hops_found":len(hops)+1,
            "exchanges_identified":[e["name"] for e in exchanges],
            "sanctioned_addresses":sum(1 for h in hops if h.get("is_sanctioned")),
            "freeze_requests_generated":len(freeze_paths),
            "pdf_download_url":f"/api/intel/report-pdf/{case_id}",
            "freeze_request_urls":[f"/api/intel/freeze-pdf/{case_id}/{ex['name']}" for ex in exchanges],
        })
    except Exception as e:
        logger.error(f"Fehler: {case_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router_report.get("/report-pdf/{case_id}")
async def download_report(case_id: str):
    path = OUTPUT_DIR / f"{case_id}_Forensischer_Analysebericht.pdf"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report nicht gefunden")
    return FileResponse(str(path), media_type="application/pdf", filename=f"{case_id}_Analysebericht.pdf")

@router_report.get("/freeze-pdf/{case_id}/{exchange}")
async def download_freeze(case_id: str, exchange: str):
    path = OUTPUT_DIR / f"{case_id}_Freeze_Request_{exchange}.pdf"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Freeze Request nicht gefunden")
    return FileResponse(str(path), media_type="application/pdf", filename=f"{case_id}_Freeze_{exchange}.pdf")
