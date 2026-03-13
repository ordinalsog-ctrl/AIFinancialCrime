"""
AIFinancialCrime — Bulk Attribution Phase 3
============================================
Drei neue Ingesters die Phase 1+2 ergänzen:

  4. OFACSdnIngester         — OFAC SDN XML täglich auto-sync
                               Bitcoin-Adressen aus offizieller Sanktionsliste
                               Quelle: treasury.gov/ofac/downloads/sdn.xml
                               → entity_type="sanctioned", is_sanctioned=True, L1

  5. WalletExplorerIngester  — WalletExplorer.com Exchange-Cluster-Adressen
                               Bekannte Exchange-Wallets aus öffentlichem Explorer
                               Rate-limited: 1 req/2s, max 500 Adressen/Exchange
                               → entity_type="exchange", L2

  6. AttributionDecayJob     — Konfidenz-Decay für alte unbestätigte Einträge
                               L3/L4 Einträge älter als 180 Tage werden degradiert
                               Verhindert dass veraltete Attributionen Reports beeinflussen
                               Täglich als Cronjob laufen lassen

Scheduling-Empfehlung (crontab auf Pi):
    0 3 * * *  python -m scripts.run_bulk_attribution_import --phase3-daily
    0 4 * * 0  python -m scripts.run_bulk_attribution_import --decay

Verwendung:
    repo = AttributionRepository(db_conn)

    # OFAC täglich
    OFACSdnIngester(repo).run()

    # WalletExplorer einmalig / wöchentlich
    WalletExplorerIngester(repo).run(exchanges=["Binance", "Coinbase", "Kraken"])

    # Decay täglich
    AttributionDecayJob(repo).run()
"""

from __future__ import annotations

import re
import time
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

from src.investigation.attribution_db import AttributionRepository
from src.core.logging_config import get_logger
from src.core.metrics import metrics

logger = get_logger("aifc.attribution.phase3")

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

OFAC_SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"
OFAC_SDN_ALT = "https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml"

WALLETEXPLORER_BASE = "https://www.walletexplorer.com"

# Bekannte WalletExplorer Exchange-IDs (wallet_id → kanonischer Name)
WALLETEXPLORER_EXCHANGES: dict[str, str] = {
    "0059098c0163b8b":  "Binance",
    "001fca31ae3979ad": "Coinbase",
    "00000000006a89ae": "Kraken",
    "00000000007a4e52": "Bitfinex",
    "000000000030e2b6": "Bitstamp",
    "0000000000ddb5b2": "OKX",
    "000000000064cfbd": "Huobi",
    "0000000000a46e04": "Poloniex",
    "000000000027a0b0": "BTC-e",        # sanctioned
    "000000000022b9a8": "Mt.Gox",       # defunct
    "0000000000c56f34": "BTC38",
    "000000000056ecca": "LocalBitcoins",
    "000000000043a3a0": "Bithumb",
    "00000000003a7b0e": "BitMEX",
    "000000000070a8a3": "Gemini",
    "000000000083c98e": "Bybit",
}

# Exchanges die als "high-risk" markiert werden sollen
HIGH_RISK_EXCHANGES = {"BTC-e", "Mt.Gox", "LocalBitcoins"}

# Decay-Parameter
DECAY_THRESHOLD_DAYS = 180        # Einträge älter als X Tage
DECAY_SOURCE_KEYS = {             # Nur diese Sources werden degradiert
    "community_list",
    "blockchair_labels",
    "walletexplorer",
}
DECAY_CONFIDENCE_REDUCTION = 5   # DB-Konfidenz-Wert um X reduzieren


# ===========================================================================
# 4. OFAC SDN Ingester
# ===========================================================================

class OFACSdnIngester:
    """
    Importiert Bitcoin-Adressen aus der OFAC Specially Designated Nationals Liste.

    Die OFAC SDN XML enthält alle sanktionierten Entities. Wir extrahieren:
    - Entities mit Digital Currency Addresses (BITCOIN type)
    - Setzen is_sanctioned=True und entity_type="sanctioned"
    - Confidence L1 (offizielle Regierungsquelle)

    Update-Logik:
    - Läuft täglich (die XML wird von OFAC laufend aktualisiert)
    - Idempotent via ON CONFLICT DO UPDATE
    - Speichert SDN-ID + Programm als raw_source_data für Rückverfolgbarkeit
    """

    SOURCE_KEY = "ofac_sdn"
    ENTITY_TYPE = "sanctioned"

    def __init__(self, repo: AttributionRepository):
        self._repo = repo

    def _fetch_xml(self) -> Optional[ET.Element]:
        """Lädt OFAC SDN XML. Versucht beide URLs."""
        for url in [OFAC_SDN_URL, OFAC_SDN_ALT]:
            try:
                req = Request(url, headers={"User-Agent": "AIFinancialCrime/1.0"})
                with urlopen(req, timeout=60) as resp:
                    data = resp.read()
                logger.info("ofac_xml_fetched", url=url, bytes=len(data))
                return ET.fromstring(data)
            except (URLError, HTTPError) as e:
                logger.warning("ofac_fetch_failed", url=url, error=str(e))
                continue
        return None

    def _parse_bitcoin_addresses(self, root: ET.Element) -> list[dict]:
        """
        Parst alle Bitcoin-Adressen aus dem SDN XML.

        XML-Struktur (vereinfacht):
        <sdnList>
          <sdnEntry>
            <uid>12345</uid>
            <lastName>ENTITY NAME</lastName>
            <sdnType>Individual|Entity</sdnType>
            <programList><program>CYBER2</program></programList>
            <idList>
              <id>
                <idType>Digital Currency Address - BITCOIN</idType>
                <idNumber>1ABC...</idNumber>
              </id>
            </idList>
          </sdnEntry>
        </sdnList>
        """
        records = []
        ns = ""

        # Namespace-Erkennung
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        for entry in root.findall(f"{ns}sdnEntry"):
            uid_el = entry.find(f"{ns}uid")
            name_el = entry.find(f"{ns}lastName")
            sdn_type_el = entry.find(f"{ns}sdnType")

            uid = uid_el.text if uid_el is not None else "?"
            name = name_el.text if name_el is not None else "Unknown"
            sdn_type = sdn_type_el.text if sdn_type_el is not None else "Entity"

            # Programme
            programs = []
            prog_list = entry.find(f"{ns}programList")
            if prog_list is not None:
                for prog in prog_list.findall(f"{ns}program"):
                    if prog.text:
                        programs.append(prog.text)

            # Bitcoin-Adressen aus idList
            id_list = entry.find(f"{ns}idList")
            if id_list is None:
                continue

            for id_el in id_list.findall(f"{ns}id"):
                id_type_el = id_el.find(f"{ns}idType")
                id_num_el  = id_el.find(f"{ns}idNumber")

                if id_type_el is None or id_num_el is None:
                    continue

                id_type = id_type_el.text or ""
                id_num  = (id_num_el.text or "").strip()

                # Nur Bitcoin-Adressen
                if "BITCOIN" not in id_type.upper():
                    continue

                # Validierung: Bitcoin-Adresse muss 26-62 Zeichen haben
                if not (26 <= len(id_num) <= 62):
                    continue

                records.append({
                    "address":          id_num,
                    "source_key":       self.SOURCE_KEY,
                    "entity_name":      name,
                    "entity_type":      self.ENTITY_TYPE,
                    "is_sanctioned":    True,
                    "abuse_category":   "OFAC_SANCTIONED",
                    "source_updated_at": datetime.now(timezone.utc),
                    "raw_source_data":  {
                        "sdn_uid":    uid,
                        "sdn_type":   sdn_type,
                        "programs":   programs,
                        "id_type":    id_type,
                    },
                })

        return records

    def run(self) -> int:
        """
        Lädt OFAC SDN XML und importiert alle Bitcoin-Adressen.
        Returns: Anzahl importierter Adressen.
        """
        t0 = time.monotonic()
        logger.info("ofac_ingester_start")

        root = self._fetch_xml()
        if root is None:
            logger.error("ofac_xml_unavailable")
            return 0

        records = self._parse_bitcoin_addresses(root)
        if not records:
            logger.warning("ofac_no_bitcoin_addresses_found")
            return 0

        logger.info("ofac_addresses_parsed", count=len(records))

        imported = self._repo.bulk_upsert(records)

        duration = time.monotonic() - t0
        logger.info("ofac_ingester_complete",
                    imported=imported,
                    duration_s=round(duration, 1))
        metrics.attribution_imported(source="ofac_sdn", count=imported)

        return imported


# ===========================================================================
# 5. WalletExplorer Ingester
# ===========================================================================

class WalletExplorerIngester:
    """
    Scrapt Exchange-Wallet-Adressen von WalletExplorer.com.

    WalletExplorer gruppiert Bitcoin-Adressen in Wallet-Cluster und
    identifiziert viele davon als Exchange-Wallets. Die API ist öffentlich.

    Endpoints:
        GET /api/1/wallet?wallet=<wallet_id>&from=0&count=100&caller=aifc
        → JSON mit addresses[]

    Rate-Limit: 1 Request / 2 Sekunden (konservativ)
    Max: 500 Adressen pro Exchange (Top-Adressen nach Volumen)

    Konfidenz: L2 (öffentliche Quelle, community-verifiziert, nicht offiziell)
    """

    SOURCE_KEY = "walletexplorer"
    ENTITY_TYPE = "exchange"
    MAX_ADDRESSES_PER_EXCHANGE = 500
    PAGE_SIZE = 100
    RATE_LIMIT_SECONDS = 2.0

    def __init__(self, repo: AttributionRepository):
        self._repo = repo
        self._last_request = 0.0

    def _rate_limit(self):
        """Wartet falls nötig um Rate-Limit einzuhalten."""
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.RATE_LIMIT_SECONDS:
            time.sleep(self.RATE_LIMIT_SECONDS - elapsed)
        self._last_request = time.monotonic()

    def _fetch_wallet_page(
        self,
        wallet_id: str,
        from_idx: int,
        count: int = 100,
    ) -> Optional[list[str]]:
        """
        Holt eine Seite Adressen für eine WalletExplorer Wallet-ID.
        Returns: Liste von Bitcoin-Adressen oder None bei Fehler.
        """
        self._rate_limit()

        url = (
            f"{WALLETEXPLORER_BASE}/api/1/wallet"
            f"?wallet={wallet_id}&from={from_idx}&count={count}&caller=aifc"
        )

        try:
            req = Request(url, headers={
                "User-Agent": "AIFinancialCrime/1.0 (forensic research)",
                "Accept": "application/json",
            })
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            addresses = data.get("addresses", [])
            return [a.get("address") for a in addresses if a.get("address")]

        except (URLError, HTTPError, json.JSONDecodeError) as e:
            logger.warning("walletexplorer_fetch_failed",
                           wallet_id=wallet_id, from_idx=from_idx, error=str(e))
            return None

    def _fetch_all_addresses(
        self,
        wallet_id: str,
        exchange_name: str,
    ) -> list[str]:
        """Holt alle Adressen für eine Exchange (bis MAX_ADDRESSES_PER_EXCHANGE)."""
        all_addresses = []
        from_idx = 0

        while len(all_addresses) < self.MAX_ADDRESSES_PER_EXCHANGE:
            batch = self._fetch_wallet_page(wallet_id, from_idx, self.PAGE_SIZE)
            if not batch:
                break

            all_addresses.extend(batch)
            logger.debug("walletexplorer_page_fetched",
                         exchange=exchange_name,
                         page_count=len(batch),
                         total=len(all_addresses))

            if len(batch) < self.PAGE_SIZE:
                break  # Letzte Seite

            from_idx += self.PAGE_SIZE

        return all_addresses[:self.MAX_ADDRESSES_PER_EXCHANGE]

    def run(
        self,
        exchanges: Optional[list[str]] = None,
        wallet_ids: Optional[list[str]] = None,
    ) -> dict[str, int]:
        """
        Importiert Exchange-Adressen von WalletExplorer.

        Args:
            exchanges:  Liste kanonischer Exchange-Namen (z.B. ["Binance", "Kraken"])
                        None = alle bekannten Exchanges
            wallet_ids: Direkte Wallet-IDs (override)

        Returns:
            Dict {exchange_name: imported_count}
        """
        results: dict[str, int] = {}
        t0 = time.monotonic()

        # Target-Exchanges bestimmen
        if wallet_ids:
            targets = {wid: f"Custom_{wid[:8]}" for wid in wallet_ids}
        elif exchanges:
            targets = {
                wid: name
                for wid, name in WALLETEXPLORER_EXCHANGES.items()
                if name in exchanges
            }
        else:
            targets = WALLETEXPLORER_EXCHANGES

        logger.info("walletexplorer_start", exchange_count=len(targets))

        for wallet_id, exchange_name in targets.items():
            logger.info("walletexplorer_exchange_start",
                        exchange=exchange_name, wallet_id=wallet_id)

            addresses = self._fetch_all_addresses(wallet_id, exchange_name)
            if not addresses:
                logger.warning("walletexplorer_no_addresses", exchange=exchange_name)
                results[exchange_name] = 0
                continue

            is_high_risk = exchange_name in HIGH_RISK_EXCHANGES

            records = [
                {
                    "address":          addr,
                    "source_key":       self.SOURCE_KEY,
                    "entity_name":      exchange_name,
                    "entity_type":      self.ENTITY_TYPE,
                    "is_sanctioned":    False,
                    "abuse_category":   "high_risk_exchange" if is_high_risk else None,
                    "source_updated_at": datetime.now(timezone.utc),
                    "raw_source_data":  {
                        "wallet_id":   wallet_id,
                        "source":      "walletexplorer.com",
                        "high_risk":   is_high_risk,
                    },
                }
                for addr in addresses
                if addr  # Filter leere Strings
            ]

            imported = self._repo.bulk_upsert(records)
            results[exchange_name] = imported
            metrics.attribution_imported(source="walletexplorer", count=imported)

            logger.info("walletexplorer_exchange_complete",
                        exchange=exchange_name,
                        fetched=len(addresses),
                        imported=imported)

        duration = time.monotonic() - t0
        total = sum(results.values())
        logger.info("walletexplorer_complete",
                    total_imported=total,
                    duration_s=round(duration, 1),
                    by_exchange=results)

        return results


# ===========================================================================
# 6. Attribution Decay Job
# ===========================================================================

class AttributionDecayJob:
    """
    Degradiert alte, unbestätigte Attributionen.

    Warum Decay?
    - Exchange-Adressen können sich ändern (Rotation, Compliace-Updates)
    - Community-Listen sind nicht immer akkurat
    - Alte Einträge ohne Re-Bestätigung sollten weniger Gewicht haben
    - Verhindert False Positives in forensischen Reports

    Decay-Logik:
    - Nur L3/L4 Einträge (source_confidence_level <= 40)
    - Nur bestimmte Source-Keys (community_list, blockchair, walletexplorer)
    - Einträge älter als DECAY_THRESHOLD_DAYS
    - Konfidenz-Wert um DECAY_CONFIDENCE_REDUCTION reduzieren
    - Einträge mit confidence < 5 werden als "stale" markiert

    Nicht betroffen:
    - OFAC SDN (is_sanctioned=True) — nie degradieren
    - Manuelle Attributionen (source_key="manual")
    - L1/L2 Einträge (confidence >= 60)
    """

    def __init__(self, repo: AttributionRepository):
        self._repo = repo

    def run(self, dry_run: bool = False) -> dict:
        """
        Führt Decay-Job aus.

        Args:
            dry_run: Wenn True, nur zählen ohne zu ändern.

        Returns:
            {
                "degraded": int,   # Einträge mit reduzierter Konfidenz
                "marked_stale": int,  # Einträge als stale markiert
                "dry_run": bool,
            }
        """
        t0 = time.monotonic()
        cutoff = datetime.now(timezone.utc) - timedelta(days=DECAY_THRESHOLD_DAYS)

        logger.info("decay_job_start",
                    dry_run=dry_run,
                    cutoff=cutoff.isoformat(),
                    threshold_days=DECAY_THRESHOLD_DAYS)

        if not hasattr(self._repo, '_conn'):
            logger.error("decay_job_no_db_conn")
            return {"degraded": 0, "marked_stale": 0, "dry_run": dry_run}

        conn = self._repo._conn

        source_keys_sql = ", ".join(f"'{k}'" for k in DECAY_SOURCE_KEYS)

        # Zähle betroffene Einträge
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT COUNT(*)
                FROM attributions
                WHERE source_key IN ({source_keys_sql})
                  AND is_sanctioned = FALSE
                  AND source_confidence_level <= 40
                  AND (source_updated_at < %s OR source_updated_at IS NULL)
                  AND COALESCE((extra_data->>'stale')::boolean, false) = false
            """, (cutoff,))
            total_affected = cur.fetchone()[0]

        logger.info("decay_job_affected", count=total_affected)

        if dry_run:
            return {
                "degraded": total_affected,
                "marked_stale": 0,
                "dry_run": True,
            }

        # Konfidenz reduzieren
        with conn.cursor() as cur:
            cur.execute(f"""
                UPDATE attributions
                SET source_confidence_level = GREATEST(1,
                    source_confidence_level - %s)
                WHERE source_key IN ({source_keys_sql})
                  AND is_sanctioned = FALSE
                  AND source_confidence_level <= 40
                  AND source_confidence_level > %s
                  AND (source_updated_at < %s OR source_updated_at IS NULL)
                  AND COALESCE((extra_data->>'stale')::boolean, false) = false
            """, (
                DECAY_CONFIDENCE_REDUCTION,
                DECAY_CONFIDENCE_REDUCTION,  # Nur wenn > Reduction (sonst → stale)
                cutoff,
            ))
            degraded = cur.rowcount

        # Einträge mit sehr niedriger Konfidenz als stale markieren
        with conn.cursor() as cur:
            cur.execute(f"""
                UPDATE attributions
                SET extra_data = COALESCE(extra_data, '{{}}'::jsonb)
                    || '{{"stale": true, "stale_at": "{datetime.now(timezone.utc).isoformat()}"}}'::jsonb
                WHERE source_key IN ({source_keys_sql})
                  AND is_sanctioned = FALSE
                  AND source_confidence_level <= %s
                  AND (source_updated_at < %s OR source_updated_at IS NULL)
            """, (DECAY_CONFIDENCE_REDUCTION, cutoff))
            marked_stale = cur.rowcount

        conn.commit()

        duration = time.monotonic() - t0
        result = {
            "degraded":     degraded,
            "marked_stale": marked_stale,
            "dry_run":      False,
        }

        logger.info("decay_job_complete",
                    duration_s=round(duration, 1),
                    **result)
        metrics.attribution_decay(degraded=degraded, stale=marked_stale)

        return result


# ===========================================================================
# Combined Phase 3 Runner
# ===========================================================================

def run_phase3_daily(repo: AttributionRepository) -> dict:
    """
    Täglicher Phase-3-Import. Für Cronjob.

    Reihenfolge:
    1. OFAC SDN (höchste Priorität, überschreibt alles)
    2. WalletExplorer Top-Exchanges
    3. Decay-Job

    Returns: Summary dict
    """
    logger.info("phase3_daily_start")
    results = {}

    # 1. OFAC
    try:
        results["ofac"] = OFACSdnIngester(repo).run()
    except Exception as e:
        logger.error("phase3_ofac_failed", error=str(e))
        results["ofac"] = 0

    # 2. WalletExplorer (nur Top-Exchanges täglich)
    DAILY_EXCHANGES = ["Binance", "Coinbase", "Kraken", "OKX", "Bybit", "Gemini"]
    try:
        we_results = WalletExplorerIngester(repo).run(exchanges=DAILY_EXCHANGES)
        results["walletexplorer"] = sum(we_results.values())
        results["walletexplorer_by_exchange"] = we_results
    except Exception as e:
        logger.error("phase3_walletexplorer_failed", error=str(e))
        results["walletexplorer"] = 0

    # 3. Decay
    try:
        results["decay"] = AttributionDecayJob(repo).run()
    except Exception as e:
        logger.error("phase3_decay_failed", error=str(e))
        results["decay"] = {}

    logger.info("phase3_daily_complete", **{
        k: v for k, v in results.items()
        if k != "walletexplorer_by_exchange"
    })
    return results


def run_phase3_full(repo: AttributionRepository) -> dict:
    """
    Vollständiger Phase-3-Import (alle Exchanges). Für wöchentlichen Job.
    """
    logger.info("phase3_full_start")
    results = {}

    # OFAC
    results["ofac"] = OFACSdnIngester(repo).run()

    # WalletExplorer — alle bekannten Exchanges
    we_results = WalletExplorerIngester(repo).run()
    results["walletexplorer"] = sum(we_results.values())
    results["walletexplorer_by_exchange"] = we_results

    # Decay
    results["decay"] = AttributionDecayJob(repo).run()

    logger.info("phase3_full_complete")
    return results
