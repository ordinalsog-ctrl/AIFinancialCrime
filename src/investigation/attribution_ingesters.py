"""
Attribution Ingesters — one per data source

Each ingester:
  1. Fetches data from its source
  2. Normalizes to the common AttributionRepository format
  3. Bulk-upserts via AttributionRepository
  4. Updates the ingestion cursor

Sources:
  - OFAC SDN List       (XML, official, authoritative)
  - WalletExplorer      (HTML scraping, exchange attribution)
  - Bitcoin Abuse DB    (CSV export, community fraud reports)
  - Manual             (JSON file, your own verified entries)
"""

from __future__ import annotations

import csv
import io
import json
import logging
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

from src.investigation.attribution_db import AttributionRepository

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _fetch_url(url: str, timeout: int = 30) -> bytes:
    req = Request(url, headers={"User-Agent": "AIFinancialCrime/1.0 (forensic research)"})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


# ---------------------------------------------------------------------------
# 1. OFAC SDN Ingester
# ---------------------------------------------------------------------------
# OFAC publishes a structured XML with all sanctioned entities and addresses.
# Bitcoin addresses appear as digitalCurrencyAddress entries.
# This is the most authoritative source — confidence L1.
# ---------------------------------------------------------------------------

OFAC_SDN_URL = "https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml"
OFAC_NS = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ADVANCED_XML"


class OFACIngester:
    SOURCE_KEY = "OFAC"

    def __init__(self, repo: AttributionRepository):
        self._repo = repo

    def run(self) -> int:
        logger.info("OFAC: Starting ingestion...")
        try:
            raw = _fetch_url(OFAC_SDN_URL)
        except URLError as e:
            logger.error(f"OFAC: Failed to fetch SDN list: {e}")
            self._repo.update_cursor(self.SOURCE_KEY, 0, "ERROR", str(e))
            return 0

        records = self._parse(raw)
        count = self._repo.bulk_upsert(records)
        self._repo.update_cursor(self.SOURCE_KEY, count, "OK")
        logger.info(f"OFAC: Ingested {count} Bitcoin address attributions.")
        return count

    def _parse(self, raw: bytes) -> list[dict]:
        """
        Parse OFAC Advanced XML for digitalCurrencyAddress entries.
        Extracts: address, entity name, SDN type, program names.
        """
        records = []
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            logger.error(f"OFAC: XML parse error: {e}")
            return records

        # Namespace-agnostic search
        for entry in root.iter():
            if not entry.tag.endswith("sdnEntry"):
                continue

            # Extract entity name
            name_parts = []
            for n in entry.iter():
                if n.tag.endswith("firstName") and n.text:
                    name_parts.insert(0, n.text.strip())
                elif n.tag.endswith("lastName") and n.text:
                    name_parts.append(n.text.strip())
            entity_name = " ".join(name_parts).strip() or "Unknown OFAC Entity"

            # Extract SDN type
            sdn_type = "OTHER"
            for t in entry.iter():
                if t.tag.endswith("sdnType") and t.text:
                    raw_type = t.text.strip().upper()
                    sdn_type = "SANCTIONED"

            # Extract program(s)
            programs = []
            for p in entry.iter():
                if p.tag.endswith("program") and p.text:
                    programs.append(p.text.strip())

            # Extract Bitcoin addresses
            for id_entry in entry.iter():
                if not id_entry.tag.endswith("id"):
                    continue
                id_type = ""
                id_number = ""
                for child in id_entry:
                    if child.tag.endswith("idType") and child.text:
                        id_type = child.text.strip()
                    elif child.tag.endswith("idNumber") and child.text:
                        id_number = child.text.strip()

                if "Digital Currency Address" in id_type and id_number:
                    # Only process Bitcoin addresses (XBT prefix in OFAC notation)
                    if id_type.endswith("XBT") or id_number.startswith("1") \
                            or id_number.startswith("3") or id_number.startswith("bc1"):
                        records.append({
                            "address": id_number,
                            "source_key": self.SOURCE_KEY,
                            "entity_name": entity_name,
                            "entity_type": "SANCTIONED",
                            "is_sanctioned": True,
                            "abuse_category": "OFAC_SANCTIONED",
                            "report_count": 1,
                            "raw_source_data": {
                                "programs": programs,
                                "id_type": id_type,
                                "sdn_type": sdn_type,
                            },
                            "source_updated_at": datetime.now(timezone.utc),
                        })

        return records


# ---------------------------------------------------------------------------
# 2. WalletExplorer Ingester
# ---------------------------------------------------------------------------
# WalletExplorer maintains a public list of known exchange wallets.
# We use their search API to check individual addresses.
# Note: Full bulk scraping is rate-limited — we use on-demand lookup
# plus a seed list of known exchange clusters.
# ---------------------------------------------------------------------------

WALLETEXPLORER_API = "https://www.walletexplorer.com/api/1/address?address={address}&caller=AIFinancialCrime"

# Seed: known exchange wallet labels from WalletExplorer
# Format: {wallet_id: (display_name, entity_type)}
KNOWN_EXCHANGE_SEEDS = {
    "Binance.com":       ("Binance",       "EXCHANGE"),
    "Coinbase.com":      ("Coinbase",      "EXCHANGE"),
    "Kraken.com":        ("Kraken",        "EXCHANGE"),
    "Bitfinex.com":      ("Bitfinex",      "EXCHANGE"),
    "Bitstamp.net":      ("Bitstamp",      "EXCHANGE"),
    "OKX.com":           ("OKX",           "EXCHANGE"),
    "Huobi.com":         ("Huobi",         "EXCHANGE"),
    "Gemini.com":        ("Gemini",        "EXCHANGE"),
    "KuCoin.com":        ("KuCoin",        "EXCHANGE"),
    "Bybit.com":         ("Bybit",         "EXCHANGE"),
    "BTC-e.com":         ("BTC-e (defunct)", "EXCHANGE"),
    "BestMixer.io":      ("BestMixer",     "MIXER"),
    "Helix":             ("Helix Mixer",   "MIXER"),
    "ChipMixer":         ("ChipMixer",     "MIXER"),
}


class WalletExplorerIngester:
    SOURCE_KEY = "WALLETEXPLORER"

    def __init__(self, repo: AttributionRepository):
        self._repo = repo

    def lookup_address(self, address: str) -> Optional[dict]:
        """
        On-demand lookup for a single address.
        Returns normalized record dict or None if unknown.
        Rate limit: 1 req/sec to be respectful.
        """
        url = WALLETEXPLORER_API.format(address=address)
        try:
            time.sleep(1)  # rate limiting
            raw = _fetch_url(url, timeout=10)
            data = json.loads(raw)
        except (URLError, json.JSONDecodeError) as e:
            logger.warning(f"WalletExplorer: lookup failed for {address}: {e}")
            return None

        wallet_id = data.get("wallet_id", "")
        if not wallet_id:
            return None

        # Match against known exchange seeds
        entity_name = wallet_id
        entity_type = "OTHER"
        for seed_key, (name, etype) in KNOWN_EXCHANGE_SEEDS.items():
            if seed_key.lower() in wallet_id.lower():
                entity_name = name
                entity_type = etype
                break

        return {
            "address": address,
            "source_key": self.SOURCE_KEY,
            "entity_name": entity_name,
            "entity_type": entity_type,
            "is_sanctioned": False,
            "abuse_category": None,
            "report_count": 1,
            "raw_source_data": {"wallet_id": wallet_id, "label": data.get("label", "")},
            "source_updated_at": datetime.now(timezone.utc),
        }

    def run_bulk_lookup(self, addresses: list[str]) -> int:
        """Lookup and store attributions for a list of addresses."""
        records = []
        for addr in addresses:
            rec = self.lookup_address(addr)
            if rec:
                records.append(rec)
        count = self._repo.bulk_upsert(records)
        self._repo.update_cursor(self.SOURCE_KEY, count, "OK")
        return count


# ---------------------------------------------------------------------------
# 3. Bitcoin Abuse Ingester
# ---------------------------------------------------------------------------
# BitcoinAbuse allows CSV export of abuse reports.
# Requires free API key: https://www.bitcoinabuse.com/api-docs
# Each row = one report of a fraudulent address.
# ---------------------------------------------------------------------------

BITCOINABUSE_CSV_URL = "https://www.bitcoinabuse.com/api/download/1d?api_token={api_token}"


class BitcoinAbuseIngester:
    SOURCE_KEY = "BITCOINABUSE"

    ABUSE_TYPE_MAP = {
        "ransomware":           "RANSOMWARE",
        "darknet market":       "DARKNET",
        "bitcoin tumbler":      "MIXER",
        "blackmail/extortion":  "EXTORTION",
        "sextortion":           "EXTORTION",
        "scam":                 "SCAM",
        "other":                "OTHER",
    }

    def __init__(self, repo: AttributionRepository, api_token: str):
        self._repo = repo
        self._api_token = api_token

    def run(self) -> int:
        logger.info("BitcoinAbuse: Starting ingestion...")
        url = BITCOINABUSE_CSV_URL.format(api_token=self._api_token)
        try:
            raw = _fetch_url(url)
        except URLError as e:
            logger.error(f"BitcoinAbuse: Fetch failed: {e}")
            self._repo.update_cursor(self.SOURCE_KEY, 0, "ERROR", str(e))
            return 0

        records = self._parse_csv(raw.decode("utf-8"))
        count = self._repo.bulk_upsert(records)
        self._repo.update_cursor(self.SOURCE_KEY, count, "OK")
        logger.info(f"BitcoinAbuse: Ingested {count} abuse reports.")
        return count

    def _parse_csv(self, csv_text: str) -> list[dict]:
        """
        CSV columns: id, address, abuse_type_id, abuse_type_other,
                     abuser, description, from_country, created_at
        """
        records = []
        # Aggregate by address — one upsert per address with report count
        aggregated: dict[str, dict] = {}

        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            address = row.get("address", "").strip()
            if not address:
                continue

            abuse_raw = row.get("abuse_type_id", "other").lower().strip()
            abuse_category = self.ABUSE_TYPE_MAP.get(abuse_raw, "OTHER")

            if address not in aggregated:
                aggregated[address] = {
                    "address": address,
                    "source_key": self.SOURCE_KEY,
                    "entity_name": f"Reported Fraud Address ({abuse_category})",
                    "entity_type": "FRAUD",
                    "is_sanctioned": False,
                    "abuse_category": abuse_category,
                    "report_count": 0,
                    "raw_source_data": {"abuse_types": [], "countries": []},
                    "source_updated_at": datetime.now(timezone.utc),
                }

            aggregated[address]["report_count"] += 1
            aggregated[address]["raw_source_data"]["abuse_types"].append(abuse_raw)
            country = row.get("from_country", "")
            if country:
                aggregated[address]["raw_source_data"]["countries"].append(country)

        return list(aggregated.values())


# ---------------------------------------------------------------------------
# 4. Manual Ingester
# ---------------------------------------------------------------------------
# Load from a local JSON file — your own verified entries.
# These are treated as authoritative (priority 1, never overwritten).
# Format: list of {address, entity_name, entity_type, notes, ...}
# ---------------------------------------------------------------------------

class ManualIngester:
    SOURCE_KEY = "MANUAL"

    def __init__(self, repo: AttributionRepository, json_path: str):
        self._repo = repo
        self._path = Path(json_path)

    def run(self) -> int:
        if not self._path.exists():
            logger.warning(f"Manual: File not found: {self._path}")
            return 0

        with open(self._path) as f:
            entries = json.load(f)

        records = []
        for entry in entries:
            records.append({
                "address":          entry["address"],
                "source_key":       self.SOURCE_KEY,
                "entity_name":      entry.get("entity_name", "Manual Entry"),
                "entity_type":      entry.get("entity_type", "OTHER"),
                "is_sanctioned":    entry.get("is_sanctioned", False),
                "abuse_category":   entry.get("abuse_category"),
                "report_count":     1,
                "raw_source_data":  entry,
                "source_updated_at": datetime.now(timezone.utc),
            })

        count = self._repo.bulk_upsert(records)
        self._repo.update_cursor(self.SOURCE_KEY, count, "OK")
        logger.info(f"Manual: Loaded {count} entries from {self._path}.")
        return count


# ---------------------------------------------------------------------------
# Orchestrator — run all ingesters
# ---------------------------------------------------------------------------

class AttributionIngestOrchestrator:
    """
    Run all configured ingesters in priority order.
    Called by: scripts/run_attribution_ingest.sh
    """

    def __init__(
        self,
        repo: AttributionRepository,
        bitcoinabuse_api_token: Optional[str] = None,
        manual_json_path: Optional[str] = None,
    ):
        self._repo = repo
        self._token = bitcoinabuse_api_token
        self._manual_path = manual_json_path

    def run_all(self) -> dict[str, int]:
        results = {}

        # 1. Manual first (highest priority, sets baseline)
        if self._manual_path:
            results["MANUAL"] = ManualIngester(self._repo, self._manual_path).run()

        # 2. OFAC (authoritative, official)
        results["OFAC"] = OFACIngester(self._repo).run()

        # 3. BitcoinAbuse (community reports)
        if self._token:
            results["BITCOINABUSE"] = BitcoinAbuseIngester(self._repo, self._token).run()
        else:
            logger.info("BitcoinAbuse: Skipped (no API token configured).")
            results["BITCOINABUSE"] = 0

        # WalletExplorer runs on-demand (per address lookup), not bulk
        results["WALLETEXPLORER"] = 0

        total = sum(results.values())
        logger.info(f"Attribution ingest complete. Total records: {total}. Breakdown: {results}")
        return results
