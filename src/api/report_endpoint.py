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
            "label": f"{canonical} (manuell bestätigt)",
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
        if _is_acam_burdenable_attribution(cached_attr) and not is_initial_step:
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
        spend_state, spending_txid = _get_spending_info(current_txid, vout_idx, rpc)
        logger.info(
            f"  TRACER: spend_state={spend_state}, spending_txid={spending_txid[:16] if spending_txid else 'None'} "
            f"für {current_txid[:16]}:{vout_idx}"
        )
        if spend_state == "unspent":
            # UTXO noch nicht ausgegeben — Exchange-Check der Adresse selbst
            check = _check_address(current_address)
            if _is_acam_burdenable_attribution(check) and hops:
                for hop in reversed(hops):
                    if any(a == current_address for a, _ in hop.get("to_addresses", [])):
                        hop["confidence"] = "L2"
                        hop["confidence_label"] = "Forensisch belegt"
                        hop["exchange"] = check["exchange"]
                        hop["exchange_wallet_id"] = check.get("wallet_id", "")
                        hop["exchange_source"] = check.get("source", "")
                        hop["label"] = f"Exchange-Einzahlung -> {check['exchange']}"
                        hop["method"] = f"Exchange Intel Agent Attribution ({check.get('label', '')})"
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
        if spend_state in {"spent_unresolved", "unknown"}:
            resolution_note = (
                " Der Output ist nachweislich weiterverwendet, aber die ausgebende TX konnte "
                "mit der aktuellen Spend-Aufloesung nicht eindeutig geladen werden."
                if spend_state == "spent_unresolved"
                else
                " Die Spend-Aufloesung war technisch unvollstaendig; der naechste Hop konnte nicht "
                "zuverlaessig ermittelt werden."
            )
            if hops:
                for hop in reversed(hops):
                    if any(a == current_address for a, _ in hop.get("to_addresses", [])):
                        hop["chain_end_reason"] = "lookup_incomplete"
                        hop["notes"] += resolution_note
                        break
            else:
                block_height, ts_str = _get_tx_block_info(current_tx)
                hops.append({
                    "hop": hop_idx,
                    "label": "Weiterleitung technisch nicht vollstaendig aufgeloest",
                    "txid": current_txid,
                    "block": block_height or 0,
                    "timestamp": ts_str,
                    "from_addresses": [(current_address, actual_from_amount)],
                    "to_addresses": [(current_address, actual_from_amount)],
                    "fee_btc": None,
                    "confidence": "L1",
                    "confidence_label": "Mathematisch bewiesen",
                    "method": "Direkter UTXO-Link bis Empfaenger; Spend-Aufloesung unvollstaendig",
                    "notes": (
                        "Der Eingang auf diese Adresse ist on-chain bewiesen."
                        + resolution_note
                        + " Der Bericht ist an dieser Stelle technisch unvollstaendig und darf nicht als unspent gelesen werden."
                    ),
                    "is_sanctioned": False,
                    "chain_end_reason": "lookup_incomplete",
                    "exchange_addresses": [],
                })
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
            # Exchange-Erkennung ist zentral im Agenten gebuendelt.
            # Hier wird bewusst keine lokale Downstream-Heuristik mehr benutzt.
            check = _check_address(addr, use_downstream=False)
            if _is_acam_burdenable_attribution(check):
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
            method = f"Exchange Intel Agent Attribution ({first_ex.get('label', '')})"
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
            "exchange_addresses": list(exchange_hits.keys()),
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
        "exchange-intel/wallet_label": (
            "Adresse wurde ueber den BTC Exchange Intel Agent aus einer "
            "externen Wallet-Label-Quelle einer Exchange zugeordnet."
        ),
        "exchange-intel/seed": (
            "Adresse wurde ueber den lokalen BTC Exchange Intel Agent "
            "als kuratierter Exchange-Seed identifiziert."
        ),
        "exchange-intel/official_por": (
            "Adresse wurde ueber den lokalen BTC Exchange Intel Agent "
            "aus einem offiziellen Proof-of-Reserves-Datensatz identifiziert."
        ),
        "exchange-intel/public_dataset": (
            "Adresse wurde ueber den BTC Exchange Intel Agent aus einem "
            "oeffentlichen Adressdatensatz identifiziert."
        ),
        "exchange-intel/public_tagpack": (
            "Adresse wurde ueber den BTC Exchange Intel Agent aus einem "
            "oeffentlichen TagPack identifiziert."
        ),
        "exchange-intel/community_label": (
            "Adresse wurde ueber den BTC Exchange Intel Agent aus einer "
            "oeffentlichen Community-Quelle identifiziert."
        ),
        "exchange-intel/address_lookup": (
            "Adresse wurde ueber den BTC Exchange Intel Agent per Live-Adressauflösung "
            "aus einer externen Quelle identifiziert."
        ),
        "local-db/EXCHANGE_INTEL": (
            "Adresse wurde lokal aus einem zuvor verifizierten Treffer des "
            "BTC Exchange Intel Agent geladen."
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

        hop0_notes = (f"{len(req.victim_addresses)} Opfer-Adresse(n). "
                      f"Gestohlener Betrag: {req.fraud_amount_btc} BTC.")
        if recipient_exchange_info:
            hop0_notes += (
                f" Empfaenger-Adresse direkt als Exchange erkannt: {recipient_exchange_info['exchange']}. "
                "Nachgelagerte Knoten werden weiterhin informativ ausgewiesen, "
                "ohne die belastbare Exchange-Zuordnung an diesem Punkt zu relativieren."
            )
        elif hop0_has_exchange:
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
            "method": (
                f"Direkte Exchange-Attribution ({hop0_exchange.get('label', '')})"
                if hop0_exchange
                else "Direkter UTXO-Link"
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
