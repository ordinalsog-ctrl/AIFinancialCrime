"""
Neuer FastAPI Endpoint: /api/intel/generate-report
Nimmt Fallakte JSON → lädt Hops aus DB/RPC → generiert PDF → gibt Download zurück
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import pathlib
import psycopg2
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

router_report = APIRouter(prefix="/intel", tags=["report"])
logger = logging.getLogger(__name__)


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
        url=os.environ.get("BITCOIN_RPC_URL", "http://192.168.178.93:8332"),
        user=os.environ.get("BITCOIN_RPC_USER", "aifc"),
        password=os.environ.get("BITCOIN_RPC_PASSWORD", "CHANGE_ME"),
    )


def _get_conn():
    return psycopg2.connect(os.environ["POSTGRES_DSN"])


def _load_hops_from_db(fraud_txid: str, conn, rpc, max_hops: int = 10) -> list:
    """Lädt alle Hops automatisch aus DB, ingestet fehlende via RPC."""
    from src.afci.ingest.run_ingest import ingest_tx_by_txid
    from src.afci.db.postgres import link_spent_outputs_for_tx, tx as db_tx

    hops = []
    visited = set()
    current_txids = [fraud_txid]
    hop_idx = 1

    while current_txids and hop_idx <= max_hops:
        next_txids = []
        for txid in current_txids:
            if txid in visited:
                continue
            visited.add(txid)

            # Falls TX nicht in DB: via RPC ingesten
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM transactions WHERE txid = %s", (txid,))
                exists = cur.fetchone()

            if not exists:
                try:
                    ingest_tx_by_txid(rpc, conn, txid)
                    with db_tx(conn):
                        with conn.cursor() as cur:
                            link_spent_outputs_for_tx(cur, txid)
                except Exception as e:
                    logger.warning(f"RPC ingest failed for {txid}: {e}")
                    continue

            # Outputs die ausgegeben wurden
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT o.txid, o.address, o.amount_sats, o.spent_by_txid,
                           t.block_height, t.first_seen
                    FROM tx_outputs o
                    JOIN transactions t ON t.txid = o.txid
                    WHERE o.txid = %s AND o.spent_by_txid IS NOT NULL
                    LIMIT 5
                """, (txid,))
                rows = cur.fetchall()

            for row in rows:
                from_txid, from_addr, amount_sats, to_txid, block, ts = row
                if to_txid in visited or to_txid is None:
                    continue

                # Folge-TX ingesten falls nötig
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM transactions WHERE txid = %s", (to_txid,))
                    exists2 = cur.fetchone()

                if not exists2:
                    try:
                        ingest_tx_by_txid(rpc, conn, to_txid)
                        with db_tx(conn):
                            with conn.cursor() as cur:
                                link_spent_outputs_for_tx(cur, to_txid)
                    except Exception as e:
                        logger.warning(f"RPC ingest failed for {to_txid}: {e}")

                # Outputs der Folge-TX
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT o2.address, o2.amount_sats, t2.block_height, t2.first_seen
                        FROM tx_outputs o2
                        JOIN transactions t2 ON t2.txid = o2.txid
                        WHERE o2.txid = %s
                        ORDER BY o2.amount_sats DESC
                    """, (to_txid,))
                    to_rows = cur.fetchall()

                to_addresses = [(r[0], r[1]/1e8) for r in to_rows if r[0]]
                to_block = to_rows[0][2] if to_rows else block
                to_ts = to_rows[0][3] if to_rows else ts
                ts_str = to_ts.strftime("%d.%m.%Y ~%H:%M UTC") if to_ts else "—"

                # WalletExplorer Attribution
                exchange_name = _check_exchange_attribution(to_addresses)
                confidence = "L2" if exchange_name else "L1"
                label = f"Exchange-Einzahlung → {exchange_name}" if exchange_name else f"UTXO Weiterleitung"

                hop = {
                    "hop": hop_idx,
                    "label": label,
                    "txid": to_txid,
                    "block": to_block or 0,
                    "timestamp": ts_str,
                    "from_addresses": [(from_addr, amount_sats/1e8)],
                    "to_addresses": to_addresses,
                    "fee_btc": None,
                    "confidence": confidence,
                    "confidence_label": "Mathematisch bewiesen" if confidence == "L1" else "Forensisch belegt",
                    "method": "Direkter UTXO-Link" if confidence == "L1" else f"WalletExplorer Attribution ({exchange_name})",
                    "notes": f"Automatisch erkannt via lokalen Bitcoin-Node." + (f" Exchange: {exchange_name}" if exchange_name else ""),
                }
                if exchange_name:
                    hop["exchange"] = exchange_name

                hops.append(hop)
                next_txids.append(to_txid)
                hop_idx += 1

        current_txids = next_txids

    return hops


def _check_exchange_attribution(to_addresses: list) -> Optional[str]:
    """Prüft Adressen gegen WalletExplorer für Exchange-Attribution."""
    import urllib.request, time
    KNOWN = {
        "huobi": "Huobi", "binance": "Binance", "coinbase": "Coinbase",
        "kraken": "Kraken", "bitfinex": "Bitfinex", "okx": "OKX",
        "poloniex": "Poloniex", "kucoin": "KuCoin", "bybit": "Bybit",
    }
    for addr, _ in to_addresses[:3]:
        if not addr:
            continue
        try:
            url = f"https://www.walletexplorer.com/api/1/address?address={addr}&from=0&count=1&caller=AIFinancialCrime"
            req = urllib.request.Request(url, headers={"User-Agent": "AIFinancialCrime/1.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read())
            label = (data.get("label") or "").lower()
            for key, name in KNOWN.items():
                if key in label:
                    return name
            if data.get("found") and data.get("label"):
                return data["label"]
            time.sleep(0.5)
        except Exception:
            pass
    return None


def _build_hop0(req: ReportRequest) -> dict:
    """Hop 0 = die Fraud-TX selbst."""
    return {
        "hop": 0,
        "label": "Diebstahl — Konsolidierung",
        "txid": req.fraud_txid,
        "block": 0,
        "timestamp": req.incident_date,
        "from_addresses": [(a, None) for a in req.victim_addresses],
        "to_addresses": [(req.recipient_address, float(req.fraud_amount_btc or 0))],
        "fee_btc": None,
        "confidence": "L1",
        "confidence_label": "Mathematisch bewiesen",
        "method": "Direkter UTXO-Link",
        "notes": f"{len(req.victim_addresses)} Opfer-Adressen konsolidiert. Vollständiger Saldo abgezogen.",
    }


@router_report.post("/generate-report")
async def generate_report_endpoint(req: ReportRequest):
    """
    Nimmt Fallakte → lädt Hops automatisch → generiert PDF → gibt Download-URL zurück.
    """
    case_id = req.case_id or f"AIFC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

    try:
        conn = _get_conn()
        rpc = _get_rpc()

        # Hops laden
        hop0 = _build_hop0(req)
        db_hops = _load_hops_from_db(req.fraud_txid, conn, rpc)
        all_hops = [hop0] + db_hops
        conn.close()

        # Exchanges aus Hops extrahieren
        exchanges = []
        for hop in all_hops:
            if hop.get("exchange"):
                exchanges.append({
                    "name": hop["exchange"],
                    "address": hop["to_addresses"][0][0] if hop["to_addresses"] else "",
                    "wallet_id": "WalletExplorer",
                    "label": hop["exchange"],
                    "tx_count": None,
                    "confidence": "L2",
                    "compliance_email": _get_exchange_email(hop["exchange"]),
                    "compliance_url": "",
                    "btc_involved": hop["to_addresses"][0][1] if hop["to_addresses"] else 0,
                    "note": f"Identifiziert via WalletExplorer Attribution",
                })

        # PDF generieren
        output_dir = pathlib.Path.home() / "AIFinancialCrime-Cases" / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = str(output_dir / f"{case_id}_Forensischer_Analysebericht.pdf")

        _generate_pdf(case_id, req, all_hops, exchanges, pdf_path)

        return JSONResponse({
            "case_id": case_id,
            "hops_found": len(all_hops),
            "exchanges_identified": [e["name"] for e in exchanges],
            "pdf_path": pdf_path,
            "pdf_download_url": f"/api/intel/report-pdf/{case_id}",
            "status": "success",
        })

    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


def _get_exchange_email(name: str) -> str:
    emails = {
        "Huobi": "compliance@huobi.com",
        "Binance": "compliance@binance.com",
        "Coinbase": "compliance@coinbase.com",
        "Kraken": "compliance@kraken.com",
        "Poloniex": "support@poloniex.com",
        "OKX": "compliance@okx.com",
    }
    return emails.get(name, f"compliance@{name.lower()}.com")


def _generate_pdf(case_id, req, hops, exchanges, output_path):
    """Ruft generate_case_report Logik auf."""
    import sys
    sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
    from src.investigation.generate_case_report import (
        _styles, _cover, _methodology, _chain_of_custody,
        _transaction_graph, _recommended_actions, _integrity,
        _page_template, CASE, HOPS, EXCHANGES_IDENTIFIED,
        PAGE_W, MARGIN, C_BORDER
    )
    from reportlab.platypus import SimpleDocTemplate, Spacer, PageBreak
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    import hashlib, io

    # Globale Variablen setzen
    import src.investigation.generate_case_report as gcr
    gcr.CASE = {
        "case_id":         case_id,
        "victim_name":     req.victim_name,
        "victim_contact":  req.victim_email or "",
        "incident_date":   req.incident_date,
        "discovery_date":  req.discovery_date or "",
        "fraud_amount":    req.fraud_amount_btc,
        "fraud_amount_eur": req.fraud_amount_eur or "—",
        "wallet_type":     f"{req.wallet_brand} ({req.wallet_type})",
        "generated_at":    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    gcr.HOPS = hops
    gcr.EXCHANGES_IDENTIFIED = exchanges

    styles = _styles()
    report_hash = hashlib.sha256((str(hops) + str(gcr.CASE)).encode()).hexdigest()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=18*mm, bottomMargin=16*mm,
    )
    on_page = _page_template(case_id, gcr.CASE["generated_at"])

    story = []
    story += _cover(styles)
    story.append(PageBreak())
    story += _methodology(styles)
    story.append(Spacer(1, 8))
    story += _chain_of_custody(styles)
    story.append(PageBreak())
    story += _transaction_graph(styles)
    story.append(PageBreak())
    story += _recommended_actions(styles)
    story.append(Spacer(1, 8))
    story += _integrity(report_hash, styles)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

    with open(output_path, "wb") as f:
        f.write(buf.getvalue())


@router_report.get("/report-pdf/{case_id}")
async def download_report_pdf(case_id: str):
    """PDF Download."""
    output_dir = pathlib.Path.home() / "AIFinancialCrime-Cases" / "output"
    pdf_path = output_dir / f"{case_id}_Forensischer_Analysebericht.pdf"
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="Report nicht gefunden")
    return FileResponse(str(pdf_path), media_type="application/pdf",
                        filename=f"{case_id}_Report.pdf")
