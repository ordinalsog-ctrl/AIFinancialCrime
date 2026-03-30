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
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Optional

import psycopg2
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from src.api.report_helpers import (
    EXCHANGE_COMPLIANCE,
    _build_flow_graph,
    _canonical_exchange_name,
    _confidence_from_source_type,
    _extract_exchange_intel_entity_name,
    _is_acam_burdenable_attribution,
)
from src.api.report_trace_helpers import trace_victim_chain as _trace_victim_chain_impl
from src.api.report_tx_helpers import (
    _get_spending_info,
    _get_tx,
    _get_tx_block_info,
    _get_tx_outputs,
    _get_victim_amount_from_inputs,
    _save_tx_to_db,
    _spend_resolution_cache,
)

logger = logging.getLogger(__name__)

router_report = APIRouter(prefix="/intel", tags=["forensic-report"])


# ---------------------------------------------------------------------------
# Exchange Intel Agent Client (zentrale Exchange-Erkennung)
# ---------------------------------------------------------------------------

def _exchange_intel_lookup(address: str) -> Optional[dict]:
    """
    Prüft Adresse im BTC Exchange Intel Agent.
    Der Agent ist die zentrale Instanz fuer Exchange-Erkennung und darf
    bei DB-Miss selbst live weitere Quellen aufloesen.
    Konfiguration: EXCHANGE_INTEL_API_URL + EXCHANGE_INTEL_API_KEY
    """
    base_url = os.environ.get("EXCHANGE_INTEL_API_URL", "").rstrip("/")
    if not base_url:
        return None
    api_key = os.environ.get("EXCHANGE_INTEL_API_KEY", "")
    candidate_bases = [base_url]
    if "://localhost" in base_url:
        candidate_bases.append(base_url.replace("://localhost", "://127.0.0.1"))

    try:
        headers = {"User-Agent": "AIFinancialCrime/2.0"}
        if api_key:
            headers["X-API-Key"] = api_key

        data = None
        last_error = None
        for candidate_base in candidate_bases:
            url = f"{candidate_base}/v1/address/{address}?live_resolve=true"
            req = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    data = json.loads(r.read())
                break
            except Exception as inner_exc:
                last_error = inner_exc
                continue

        if data is None:
            raise last_error or RuntimeError("exchange intel unavailable")
        if not data.get("found"):
            return None
        source_type = data.get("best_source_type", "exchange_intel")
        _, confidence = _confidence_from_source_type(source_type)
        entity_name = _extract_exchange_intel_entity_name(data)
        canonical = _canonical_exchange_name(entity_name) if entity_name else "Unknown Exchange"
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

OUTPUT_DIR = pathlib.Path.home() / "AIFinancialCrime-Cases" / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Request Model
# ---------------------------------------------------------------------------

class ReportRequest(BaseModel):
    case_id: Optional[str] = None
    victim_name: str
    victim_email: Optional[str] = ""
    victim_country: Optional[str] = "Germany"
    incident_date: str
    discovery_date: Optional[str] = ""
    wallet_type: Optional[str] = "Hardware"
    wallet_brand: Optional[str] = ""
    seed_digital: Optional[str] = "unknown"
    description: Optional[str] = ""
    fraud_txid: str
    fraud_amount_btc: str
    fraud_amount_eur: Optional[str] = ""
    victim_addresses: list[str] = []
    recipient_address: str
    additional_notes: Optional[str] = ""
    manual_attributions: dict[str, str] = {}  # {address: exchange_name}


_attribution_cache: dict[str, dict] = {}


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



def _check_address(address: str, use_downstream: bool = True) -> dict:
    """Prueft Adresse auf Exchange-Attribution ueber den Agenten und auf Sanctions.

    `use_downstream` bleibt nur fuer Rueckwaertskompatibilitaet in der Signatur.
    Die Exchange-Erkennung selbst ist zentral im Agenten gebuendelt.
    """
    _ = use_downstream
    if address in _attribution_cache:
        return _attribution_cache[address]

    result = {"exchange": None, "is_sanctioned": False, "source": None,
              "label": None, "wallet_id": None, "confidence": "L1"}
    attribution = _exchange_intel_lookup(address)
    if attribution:
        result.update(attribution)

    result["is_sanctioned"] = _chainalysis_check(address)
    result["_downstream_checked"] = True
    _attribution_cache[address] = result
    return result


def _apply_manual_attributions(manual_attributions: dict[str, str]) -> None:
    """Schreibt manuelle Exchange-Attributionen in den Cache (höchste Priorität)."""
    for address, exchange_name in manual_attributions.items():
        canonical = _canonical_exchange_name(exchange_name)
        compliance_email = EXCHANGE_COMPLIANCE.get(canonical, "")
        _attribution_cache[address] = {
            "exchange": canonical,
            "label": f"{canonical} (manually confirmed)",
            "wallet_id": "",
            "source": "manual",
            "confidence": "L2",
            "is_sanctioned": False,
            "compliance_email": compliance_email,
        }


# ---------------------------------------------------------------------------
# Fokussiertes Chain-Tracing
# ---------------------------------------------------------------------------

def _trace_victim_chain(fraud_txid: str, recipient_address: str, rpc, conn, max_hops: int = 8) -> list:
    return _trace_victim_chain_impl(
        fraud_txid,
        recipient_address,
        rpc,
        conn,
        get_tx=_get_tx,
        save_tx_to_db=_save_tx_to_db,
        get_tx_block_info=_get_tx_block_info,
        get_spending_info=_get_spending_info,
        get_tx_outputs=_get_tx_outputs,
        check_address=_check_address,
        is_acam_burdenable_attribution=_is_acam_burdenable_attribution,
        attribution_cache=_attribution_cache,
        logger=logger,
        max_hops=max_hops,
    )



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
        "exchange-intel/wallet_label": (
            "Address attribution was provided by the BTC Exchange Intel Agent "
            "using an external wallet-label source."
        ),
        "exchange-intel/seed": (
            "Address attribution was provided by the local BTC Exchange Intel Agent "
            "using a curated exchange seed."
        ),
        "exchange-intel/official_por": (
            "Address attribution was provided by the local BTC Exchange Intel Agent "
            "using an official proof-of-reserves dataset."
        ),
        "exchange-intel/public_dataset": (
            "Address attribution was provided by the BTC Exchange Intel Agent "
            "using a public address dataset."
        ),
        "exchange-intel/public_tagpack": (
            "Address attribution was provided by the BTC Exchange Intel Agent "
            "using a public tag pack."
        ),
        "exchange-intel/community_label": (
            "Address attribution was provided by the BTC Exchange Intel Agent "
            "using a public community source."
        ),
        "exchange-intel/address_lookup": (
            "Address attribution was provided by the BTC Exchange Intel Agent "
            "through live address resolution against an external source."
        ),
        "local-db/EXCHANGE_INTEL": (
            "Address attribution was loaded locally from a previously verified "
            "BTC Exchange Intel Agent result."
        ),
        "manual": (
            "Exchange attribution was manually confirmed and entered by the analyst."
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
            "note": source_notes.get(ex_source, f"Identified via {ex_source}."),
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

    wallet_brand = (req.wallet_brand or "").strip()
    wallet_type = (req.wallet_type or "").strip()
    if wallet_brand and wallet_type:
        wallet_label = f"{wallet_brand} ({wallet_type})"
    else:
        wallet_label = wallet_brand or wallet_type or "—"

    gcr.CASE = {
        "case_id":          case_id,
        "victim_name":      req.victim_name,
        "victim_contact":   req.victim_email or "",
        "incident_date":    req.incident_date,
        "discovery_date":   req.discovery_date or "",
        "fraud_amount":     req.fraud_amount_btc,
        "fraud_amount_eur": (req.fraud_amount_eur or "").strip(),
        "wallet_type":      wallet_label,
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
    _spend_resolution_cache.clear()
    if req.manual_attributions:
        _apply_manual_attributions(req.manual_attributions)

    case_id = req.case_id or (
        f"AIFC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-"
        f"{str(uuid.uuid4())[:8].upper()}"
    )

    try:
        conn = _get_conn()
        rpc = _get_rpc()

        logger.info(f"Analysis: {case_id}, txid={req.fraud_txid[:16]}")

        # 1. Fraud-TX holen
        fraud_tx = _get_tx(req.fraud_txid, rpc)
        if not fraud_tx:
            raise HTTPException(status_code=400, detail=f"Transaction not found: {req.fraud_txid[:16]}")

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

        # 4. Direkte Exchange-Treffer auf Fraud-TX prüfen
        # Empfaengeradresse nur DIREKT pruefen (ohne Downstream), damit echte
        # Seed-/PoR-/Wallet-Treffer sauber als Chain-Ende erkannt werden, ohne
        # die frueheren Downstream-Falschpositiven wieder einzufuehren.
        recipient_exchange = _check_address(req.recipient_address, use_downstream=False)
        if not _is_acam_burdenable_attribution(recipient_exchange):
            recipient_exchange = None

        direct_exchanges = {}
        fraud_tx_outputs = _get_tx_outputs(fraud_tx)
        for addr, btc in fraud_tx_outputs:
            if addr == req.recipient_address:
                continue
            check = _check_address(addr)
            if _is_acam_burdenable_attribution(check):
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

        recipient_exchange_info = None
        if recipient_exchange:
            recipient_exchange_info = {
                **recipient_exchange,
                "btc": recipient_output_btc if recipient_output_btc > 0 else float(req.fraud_amount_btc or 0),
            }

        hop0_exchange_addresses = sorted(
            set(([req.recipient_address] if recipient_exchange_info else []) + list(direct_exchanges.keys()))
        )
        hop0_has_exchange = bool(direct_exchanges or recipient_exchange_info)
        hop0_exchange = recipient_exchange_info or (next(iter(direct_exchanges.values())) if direct_exchanges else None)

        hop0_notes = (
            f"{len(req.victim_addresses)} victim address(es). "
            f"Stolen amount: {req.fraud_amount_btc} BTC."
        )
        if recipient_exchange_info:
            hop0_notes += (
                f" Recipient address directly identified as exchange infrastructure: {recipient_exchange_info['exchange']}. "
                "Subsequent nodes remain visible for context, without weakening the corroborated exchange attribution at this point."
            )
        elif hop0_has_exchange:
            ex_names = ", ".join(set(v["exchange"] for v in direct_exchanges.values()))
            hop0_notes += f" Direct exchange outputs identified: {ex_names}."

        hop0 = {
            "hop": 0,
            "label": f"Theft → {hop0_exchange['exchange']}" if hop0_exchange else "Theft — Consolidation",
            "txid": req.fraud_txid,
            "block": hop0_block or 0,
            "timestamp": hop0_ts if hop0_ts != "—" else req.incident_date,
            "from_addresses": from_addresses_hop0,
            "to_addresses": to_addresses_hop0,
            "fee_btc": None,
            "confidence": "L2" if hop0_has_exchange else "L1",
            "confidence_label": "Forensically corroborated" if hop0_has_exchange else "Mathematically proven",
            "method": (
                f"Direct exchange attribution ({hop0_exchange.get('label', '')})"
                if hop0_exchange
                else "Direct UTXO link"
            ),
            "notes": hop0_notes,
            "is_sanctioned": any(c.get("is_sanctioned") for c in _attribution_cache.values()),
            "chain_end_reason": None,
            "exchange_addresses": hop0_exchange_addresses,
        }
        if hop0_exchange:
            hop0["exchange"] = hop0_exchange["exchange"]
            hop0["exchange_wallet_id"] = hop0_exchange.get("wallet_id", "")
            hop0["exchange_source"] = hop0_exchange.get("source", "")

        # 6. Chain nur ab Empfänger verfolgen (fokussiert, kein Branching)
        hops = _trace_victim_chain(req.fraud_txid, req.recipient_address, rpc, conn)
        if recipient_exchange_info and not hops:
            hop0["chain_end_reason"] = "exchange"
        conn.close()

        # 7. Exchanges aus allen Hops
        all_hops = [hop0] + hops
        exchanges = _build_exchanges(all_hops)
        graph_payload = _build_flow_graph(req.victim_addresses, req.recipient_address, all_hops)

        # 8. PDF + Freeze Requests
        pdf_path = _generate_pdf(case_id, req, hop0, hops, exchanges)
        freeze_paths = _generate_freeze_requests(case_id, exchanges)

        logger.info(f"{case_id}: {len(all_hops)} hops, exchanges: {[e['name'] for e in exchanges]}")

        return JSONResponse({
            "case_id": case_id,
            "status": "success",
            "hops_found": len(all_hops),
            "hops": all_hops,
            "graph": graph_payload,
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
        logger.error(f"Error {case_id}: {e}", exc_info=True)
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
