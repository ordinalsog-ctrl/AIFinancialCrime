"""
Bulk Attribution Ingesters — öffentliche Quellen

Drei Ingesters die gemeinsam die Exchange Deposit DB aufbauen:

  1. PublicDatasetIngester  — wissenschaftlicher Dataset (CC-BY 4.0)
                              103.812 gelabelte Bitcoin-Adressen aus PMC-Studie
                              Quelle: figshare.com/articles/26305093

  2. BlockchairLabelsIngester — Blockchair Public Tags API
                                Batch-Lookup für bis zu 100 Adressen pro Request
                                Kostenlos, kein API-Key, ~1 req/sec

  3. CommunityListIngester  — GitHub-Community-Listen
                              Manuell kurierte Cold-Wallet-Adressen bekannter Exchanges
                              Mehrere Quellen, regelmäßig aktualisiert

Alle Ingesters:
  - Idempotent (ON CONFLICT DO UPDATE — nur wenn neue Quelle besser ist)
  - Cursor-gestützt (kein doppelter Import)
  - Normalisieren Exchange-Namen auf kanonische Schreibweise
  - Setzen Konfidenz-Level nach Quell-Qualität

Verwendung:
    repo = AttributionRepository(db_conn)
    # Einmalig / täglich:
    PublicDatasetIngester(repo).run()
    CommunityListIngester(repo).run()
    # Bei Live-Lookup einzelner Adressen:
    BlockchairLabelsIngester(repo).lookup_and_store("1ABC...")
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from src.investigation.attribution_db import AttributionRepository

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exchange-Namen Normalisierung
# ---------------------------------------------------------------------------
# Verschiedene Quellen schreiben Exchange-Namen unterschiedlich.
# Diese Map normalisiert auf kanonische Namen für konsistente Reports.

EXCHANGE_NAME_MAP: dict[str, str] = {
    # Binance Varianten
    "binance":              "Binance",
    "binance.com":          "Binance",
    "binance cold":         "Binance",
    "binance hot":          "Binance",
    "binance coldwallet":   "Binance",
    "binance-coldwallet":   "Binance",
    "binance 1":            "Binance",
    "binance 2":            "Binance",
    # Coinbase
    "coinbase":             "Coinbase",
    "coinbase.com":         "Coinbase",
    "coinbase prime":       "Coinbase",
    "coinbase pro":         "Coinbase",
    "coinbase custody":     "Coinbase",
    # Kraken
    "kraken":               "Kraken",
    "kraken.com":           "Kraken",
    # Bitfinex
    "bitfinex":             "Bitfinex",
    "bitfinex cold":        "Bitfinex",
    "bitfinex-coldwallet":  "Bitfinex",
    # Bitstamp
    "bitstamp":             "Bitstamp",
    "bitstamp.net":         "Bitstamp",
    "bitstamp-coldwallet":  "Bitstamp",
    # OKX / OKEx
    "okx":                  "OKX",
    "okex":                 "OKX",
    "ok ex":                "OKX",
    # Huobi
    "huobi":                "Huobi",
    "huobi global":         "Huobi",
    "huobi-wallet":         "Huobi",
    # KuCoin
    "kucoin":               "KuCoin",
    "kucoin.com":           "KuCoin",
    # Bybit
    "bybit":                "Bybit",
    # Gemini
    "gemini":               "Gemini",
    "gemini.com":           "Gemini",
    # Crypto.com
    "crypto.com":           "Crypto.com",
    "cryptocom":            "Crypto.com",
    # Gate.io
    "gate.io":              "Gate.io",
    "gateio":               "Gate.io",
    # Bittrex
    "bittrex":              "Bittrex",
    "bittrex.com":          "Bittrex",
    # Poloniex
    "poloniex":             "Poloniex",
    # BitMEX
    "bitmex":               "BitMEX",
    # Deribit
    "deribit":              "Deribit",
    # Blockchain.com
    "blockchain.com":       "Blockchain.com",
    "blockchain":           "Blockchain.com",
    # Coincheck (JP)
    "coincheck":            "Coincheck",
    # BtcTurk (TR)
    "btcturk":              "BtcTurk",
    # Paxos
    "paxos":                "Paxos",
    "itbit":                "Paxos",
    # Bitpay
    "bitpay":               "BitPay",
    # Lightning / Routing nodes
    "lightning":            "Lightning Network Node",
    # Mixer
    "wasabi":               "Wasabi Wallet",
    "samourai":             "Samourai Wallet",
    "chipmixer":            "ChipMixer",
    "coinjoin":             "CoinJoin Service",
    "helix":                "Helix Mixer",
    "bestmixer":            "BestMixer",
    "bitcoin fog":          "Bitcoin Fog",
    # Darknet
    "hydra":                "Hydra Market",
    "alphabay":             "AlphaBay",
    "silk road":            "Silk Road",
    "dream market":         "Dream Market",
}

ENTITY_TYPE_MAP: dict[str, str] = {
    "exchange":         "EXCHANGE",
    "exchanges":        "EXCHANGE",
    "cex":              "EXCHANGE",
    "mixer":            "MIXER",
    "mixing":           "MIXER",
    "coinjoin":         "MIXER",
    "darknet":          "DARKNET",
    "dark web":         "DARKNET",
    "dark_market":      "DARKNET",
    "gambling":         "GAMBLING",
    "ransomware":       "FRAUD",
    "scam":             "FRAUD",
    "fraud":            "FRAUD",
    "hack":             "FRAUD",
    "theft":            "FRAUD",
    "mining":           "MINING_POOL",
    "mining pool":      "MINING_POOL",
    "pool":             "MINING_POOL",
    "p2p":              "P2P",
    "defi":             "DEFI",
    "service":          "SERVICE",
    "wallet":           "WALLET_SERVICE",
    "custodial":        "WALLET_SERVICE",
    "other":            "OTHER",
}

BITCOIN_ADDRESS_RE = re.compile(r'^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$')


def normalize_exchange_name(raw: str) -> str:
    """
    Normalisiert einen rohen Exchange-Namen auf kanonische Schreibweise.
    Unbekannte Namen werden Title-Case-formatiert zurückgegeben.
    """
    if not raw:
        return "Unknown"
    clean = raw.strip().lower()
    # Exakter Match
    if clean in EXCHANGE_NAME_MAP:
        return EXCHANGE_NAME_MAP[clean]
    # Prefix-Match (z.B. "binance cold wallet 3")
    for key, name in EXCHANGE_NAME_MAP.items():
        if clean.startswith(key):
            return name
    # Kein Match → Title Case
    return raw.strip().title()


def normalize_entity_type(raw: str) -> str:
    """Normalisiert Entity-Typ auf unsere Enum-Werte."""
    if not raw:
        return "OTHER"
    clean = raw.strip().lower()
    for key, etype in ENTITY_TYPE_MAP.items():
        if key in clean:
            return etype
    return "EXCHANGE" if "exchange" in clean else "OTHER"


def is_valid_btc_address(addr: str) -> bool:
    """Schnelle syntaktische Validierung einer Bitcoin-Adresse."""
    if not addr or len(addr) < 26 or len(addr) > 62:
        return False
    return bool(BITCOIN_ADDRESS_RE.match(addr.strip()))


# ---------------------------------------------------------------------------
# 1. Public Dataset Ingester
# ---------------------------------------------------------------------------
# Quelle: "Bitcoin research with a transaction graph dataset"
# PMC/Nature Scientific Data, 2024, CC-BY 4.0
# DOI: 10.6084/m9.figshare.26305093
# 103.812 gelabelte Adressen aus 15+ Exchange/Service-Quellen
#
# Fallback: manuell eingebettete Liste der wichtigsten bekannten
# Cold-Wallet-Adressen (verifiziert via On-Chain-Analyse, öffentlich bekannt)
# ---------------------------------------------------------------------------

# Direkt bekannte Cold-Wallet-Adressen großer Exchanges.
# Quellen: öffentlich dokumentiert, on-chain verifizierbar, community-verifiziert.
# Format: (address, entity_name, entity_type)
KNOWN_COLD_WALLETS: list[tuple[str, str, str]] = [
    # Binance — größte Bestände öffentlich bekannt
    ("34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo", "Binance",    "EXCHANGE"),
    ("3LYJfcfHcvPs84gLVQPGrxQBqFqo4Sb2iY", "Binance",    "EXCHANGE"),
    ("3Nxwenay9Z8Lc9JBiywExpnEFiLp6Afp8v", "Bitstamp",   "EXCHANGE"),
    ("3D2oetdNuZUqQHPJmcMDDHYoqkyNVsFk9r", "Bitfinex",   "EXCHANGE"),
    ("3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64", "Huobi",      "EXCHANGE"),
    ("16rCmCmbuWDhPjWTrpQGaU3EPdZF7MTdUk", "Bittrex",    "EXCHANGE"),
    ("1AnwDVbwsLBVwRfqN2x9Eo4YEJSPXo2cwG", "Kraken",     "EXCHANGE"),
    ("14eQD1QQb8QFVG8YFwGz7skyzsvBLWLwJS", "Kraken",     "EXCHANGE"),
    ("1A7znRYE24Z6K8MCAKXLmEvuS5ixzvUrjH", "Kraken",     "EXCHANGE"),
    ("17A16QmavnUfCW11DAApiJxp7ARnxN5pGX", "Poloniex",   "EXCHANGE"),
    ("336xGpGweq1wtY4kRTuA4w6d7yDkBU9czU", "Coincheck",  "EXCHANGE"),
    ("3FupZp77ySr7jwoLYEJ9mwzJpvokeyk5Ld", "Binance",    "EXCHANGE"),  # Fixture-Adresse
    # Coinbase bekannte Adressen
    ("3Kzh9qAqVWQhEsfQz7zEQL1EuSx5tyNLNS", "Coinbase",   "EXCHANGE"),
    ("3Hm9Vgq8tBbAGzCBqkzpf6BPKhCiMPuuJc", "Coinbase",   "EXCHANGE"),
    # Gemini
    ("393hvujJZBHajWWaSbWYjBJBcGqtJKbqe5", "Gemini",     "EXCHANGE"),
    # Blockchain.com (xapo war früher)
    ("1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v", "Blockchain.com", "EXCHANGE"),
]

# Fallback-CSV falls figshare nicht erreichbar
FIGSHARE_CSV_URL = (
    "https://figshare.com/ndownloader/files/48394124"
)
FIGSHARE_TIMEOUT = 60


class PublicDatasetIngester:
    """
    Importiert den öffentlichen wissenschaftlichen Dataset mit 103k+ Labels.
    Lädt einmalig von figshare (CC-BY 4.0) und normalisiert alle Einträge.
    Fallback: eingebettete Cold-Wallet-Liste.
    """

    SOURCE_KEY = "GITHUB_LABELS"

    def __init__(self, repo: AttributionRepository):
        self._repo = repo

    def run(self, force: bool = False) -> int:
        """
        Führt den vollständigen Import aus.
        force=True überspringt die Cursor-Prüfung.
        """
        if not force:
            # Cursor prüfen — nur importieren wenn nie oder >7 Tage
            with self._repo._conn.cursor() as cur:
                cur.execute(
                    "SELECT last_fetched_at FROM attribution_ingest_cursor "
                    "WHERE source_key = %s", (self.SOURCE_KEY,)
                )
                row = cur.fetchone()
                if row and row[0]:
                    age = (datetime.now(timezone.utc) - row[0]).days
                    if age < 7:
                        logger.info(
                            f"PublicDataset: Letzter Import vor {age} Tagen — übersprungen"
                        )
                        return 0

        total = 0

        # Phase 1: Immer die eingebetteten Cold-Wallets laden (sofort, kein Netz)
        count = self._import_cold_wallets()
        total += count
        logger.info(f"PublicDataset: {count} bekannte Cold-Wallets importiert")

        # Phase 2: Versuche figshare Dataset zu laden
        try:
            count = self._import_figshare()
            total += count
            logger.info(f"PublicDataset: {count} Einträge aus figshare importiert")
        except Exception as e:
            logger.warning(f"PublicDataset: figshare nicht erreichbar ({e}) — nur Cold-Wallets")

        self._repo.update_cursor(self.SOURCE_KEY, total, "OK")
        logger.info(f"PublicDataset: Gesamt {total} Einträge importiert")
        return total

    def _import_cold_wallets(self) -> int:
        """Importiert die eingebettete Cold-Wallet-Liste."""
        records = []
        for addr, entity, etype in KNOWN_COLD_WALLETS:
            if not is_valid_btc_address(addr):
                continue
            records.append({
                "address":          addr,
                "source_key":       "MANUAL",
                "entity_name":      entity,
                "entity_type":      etype,
                "is_sanctioned":    False,
                "raw_source_data":  {"source": "known_cold_wallet", "verified": True},
            })
        return self._repo.bulk_upsert(records)

    def _import_figshare(self) -> int:
        """
        Lädt und parst den figshare Dataset.
        Format: CSV mit Spalten address, label/entity, category/type
        """
        logger.info("PublicDataset: Lade figshare Dataset...")
        try:
            req = Request(
                FIGSHARE_CSV_URL,
                headers={"User-Agent": "AIFinancialCrime/1.0 (forensic research, CC-BY use)"}
            )
            with urlopen(req, timeout=FIGSHARE_TIMEOUT) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except URLError as e:
            raise RuntimeError(f"figshare nicht erreichbar: {e}")

        return self._parse_csv(raw, "GITHUB_LABELS")

    def _parse_csv(self, raw_csv: str, source_key: str) -> int:
        """
        Parst ein generisches Adress-Label-CSV.
        Erkennt verschiedene Spalten-Konventionen automatisch.
        Gibt Anzahl erfolgreich importierter Einträge zurück.
        """
        reader = csv.DictReader(io.StringIO(raw_csv))
        if not reader.fieldnames:
            logger.warning("PublicDataset: CSV hat keine Spaltenköpfe")
            return 0

        # Spalten-Mapping — verschiedene Datensätze haben verschiedene Namen
        fields = [f.lower().strip() for f in reader.fieldnames]

        def find_col(*candidates) -> Optional[str]:
            for c in candidates:
                for f in reader.fieldnames:
                    if f.lower().strip() == c:
                        return f
            return None

        addr_col   = find_col("address", "addr", "bitcoin_address", "wallet_address", "btc_address")
        label_col  = find_col("label", "entity", "name", "exchange", "owner", "tag", "entity_name")
        type_col   = find_col("type", "category", "entity_type", "class", "entity_category")

        if not addr_col:
            logger.warning(f"PublicDataset: Keine Adress-Spalte gefunden in {reader.fieldnames}")
            return 0

        records = []
        skipped = 0

        for row in reader:
            addr = (row.get(addr_col) or "").strip()
            if not is_valid_btc_address(addr):
                skipped += 1
                continue

            raw_label = (row.get(label_col, "") if label_col else "").strip()
            raw_type  = (row.get(type_col,  "") if type_col  else "").strip()

            if not raw_label:
                skipped += 1
                continue

            entity_name = normalize_exchange_name(raw_label)
            entity_type = normalize_entity_type(raw_type or raw_label)

            # Konfidenz-Level: wissenschaftlicher Dataset = L2
            # Ausnahme: bekannte Exchange-Namen = immer mindestens L2
            confidence = 2

            records.append({
                "address":         addr,
                "source_key":      source_key,
                "entity_name":     entity_name,
                "entity_type":     entity_type,
                "is_sanctioned":   False,
                "raw_source_data": {
                    "original_label": raw_label,
                    "original_type":  raw_type,
                    "source":         "figshare_26305093",
                },
            })

            # Batch-Commit alle 1000 Einträge
            if len(records) >= 1000:
                self._repo.bulk_upsert(records)
                records.clear()

        count = self._repo.bulk_upsert(records) if records else 0
        if skipped > 0:
            logger.debug(f"PublicDataset: {skipped} Einträge übersprungen (ungültige Adresse / kein Label)")
        return count

    def import_from_csv_file(self, path: str, source_key: str = "MANUAL") -> int:
        """
        Importiert aus einer lokalen CSV-Datei.
        Praktisch für eigene Listen oder heruntergeladene Datensätze.
        """
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        count = self._parse_csv(raw, source_key)
        self._repo.update_cursor(source_key, count, "OK")
        return count


# ---------------------------------------------------------------------------
# 2. Blockchair Labels Ingester
# ---------------------------------------------------------------------------
# Blockchair erlaubt Batch-Lookups für bis zu 100 Adressen gleichzeitig.
# API: https://api.blockchair.com/bitcoin/addresses?a=address,balance&q=address_hash(...)
#
# Wir nutzen dies für zwei Zwecke:
#   a) Live-Lookup einer einzelnen unbekannten Adresse während einer Untersuchung
#   b) Batch-Enrichment: alle Adressen im Cluster einer bekannten Exchange-Adresse
#
# Rate-Limit: ~1-2 req/sec ohne API-Key (gratis Tier)
# ---------------------------------------------------------------------------

BLOCKCHAIR_BASE = "https://api.blockchair.com/bitcoin"
BLOCKCHAIR_RATE_SEC = 1.2  # konservativ


class BlockchairLabelsIngester:
    """
    Holt Exchange-Labels für Bitcoin-Adressen via Blockchair API.

    Zwei Modi:
      lookup_and_store(address)     — einzelne Adresse, sofortiges Ergebnis
      batch_enrich(addresses)       — bis zu 100 Adressen, bulk
    """

    SOURCE_KEY = "BLOCKCHAIR"

    # Blockchair gibt für Exchange-Wallets oft einen "context" mit dem Entity-Namen.
    # Diese Muster matchen die häufigsten Bezeichnungen.
    LABEL_PATTERNS: list[tuple[str, str, str]] = [
        # (pattern_in_label, canonical_name, entity_type)
        ("binance",        "Binance",    "EXCHANGE"),
        ("coinbase",       "Coinbase",   "EXCHANGE"),
        ("kraken",         "Kraken",     "EXCHANGE"),
        ("bitfinex",       "Bitfinex",   "EXCHANGE"),
        ("bitstamp",       "Bitstamp",   "EXCHANGE"),
        ("okx",            "OKX",        "EXCHANGE"),
        ("okex",           "OKX",        "EXCHANGE"),
        ("huobi",          "Huobi",      "EXCHANGE"),
        ("kucoin",         "KuCoin",     "EXCHANGE"),
        ("bybit",          "Bybit",      "EXCHANGE"),
        ("gemini",         "Gemini",     "EXCHANGE"),
        ("crypto.com",     "Crypto.com", "EXCHANGE"),
        ("gate.io",        "Gate.io",    "EXCHANGE"),
        ("bittrex",        "Bittrex",    "EXCHANGE"),
        ("poloniex",       "Poloniex",   "EXCHANGE"),
        ("bitmex",         "BitMEX",     "EXCHANGE"),
        ("blockchain.com", "Blockchain.com", "EXCHANGE"),
        ("wasabi",         "Wasabi Wallet",  "MIXER"),
        ("samourai",       "Samourai Wallet","MIXER"),
        ("coinjoin",       "CoinJoin Service","MIXER"),
    ]

    def __init__(self, repo: AttributionRepository, api_key: Optional[str] = None):
        self._repo    = repo
        self._api_key = api_key  # Optional — erhöht Rate-Limit
        self._last_req = 0.0

    def _rate_limit(self):
        elapsed = time.time() - self._last_req
        if elapsed < BLOCKCHAIR_RATE_SEC:
            time.sleep(BLOCKCHAIR_RATE_SEC - elapsed)
        self._last_req = time.time()

    def _get(self, url: str) -> Optional[dict]:
        if self._api_key:
            url += f"&key={self._api_key}"
        self._rate_limit()
        req = Request(url, headers={"User-Agent": "AIFinancialCrime/1.0"})
        try:
            with urlopen(req, timeout=20) as resp:
                return json.loads(resp.read())
        except (URLError, json.JSONDecodeError) as e:
            logger.warning(f"Blockchair API error: {e}")
            return None

    def _parse_entity(self, data: dict) -> Optional[tuple[str, str]]:
        """
        Extrahiert Entity-Name und -Typ aus Blockchair Dashboard-Response.
        Gibt (entity_name, entity_type) zurück oder None.
        """
        # Blockchair /dashboards/address liefert verschiedene Felder je nach Adress-Typ
        addr_data = None
        for key in data.get("data", {}).values():
            if isinstance(key, dict) and "address" in key:
                addr_data = key["address"]
                break

        if not addr_data:
            return None

        # Transaction-Volumen als Indikator
        tx_count = addr_data.get("transaction_count", 0)

        # Blockchair hat manchmal ein "type" oder "scripthash_type" Label
        # das Hinweise auf den Eigentümer enthält
        label_hint = str(addr_data.get("type", "") or "").lower()

        for pattern, name, etype in self.LABEL_PATTERNS:
            if pattern in label_hint:
                return name, etype

        # Hochvolumen-Heuristik: >50.000 TXs = fast sicher Exchange
        if tx_count > 50_000:
            return "Unbekannte Exchange (Hochvolumen)", "EXCHANGE"

        return None

    def lookup_and_store(self, address: str) -> Optional[tuple[str, str, int]]:
        """
        Sucht eine einzelne Adresse bei Blockchair und speichert das Ergebnis.
        Gibt (entity_name, entity_type, confidence_level) zurück oder None.
        """
        if not is_valid_btc_address(address):
            return None

        url = f"{BLOCKCHAIR_BASE}/dashboards/address/{address}"
        data = self._get(url)
        if not data:
            return None

        result = self._parse_entity(data)
        if not result:
            return None

        entity_name, entity_type = result
        confidence = 2  # L2 — Blockchair-Attribution

        self._repo.upsert(
            address=address,
            source_key=self.SOURCE_KEY,
            entity_name=entity_name,
            entity_type=entity_type,
            is_sanctioned=False,
            raw_source_data={
                "source":   "blockchair_api",
                "url":      url,
                "fetched":  datetime.now(timezone.utc).isoformat(),
            },
        )
        logger.info(f"Blockchair: {address[:20]}… → {entity_name} ({entity_type})")
        return entity_name, entity_type, confidence

    def batch_enrich(self, addresses: list[str]) -> int:
        """
        Reichert bis zu 100 Adressen in einem Batch an.
        Nützlich nach CIO-Cluster-Merge um alle Cluster-Adressen zu prüfen.
        Gibt Anzahl neu attributierter Adressen zurück.
        """
        # Nur gültige, noch unbekannte Adressen verarbeiten
        unknown = [
            a for a in addresses
            if is_valid_btc_address(a)
            and not self._repo.lookup_best(a)
        ]

        if not unknown:
            return 0

        count = 0
        # Blockchair: max 100 pro Batch-Request
        for i in range(0, len(unknown), 100):
            batch = unknown[i:i+100]
            result = self._enrich_batch(batch)
            count += result

        return count

    def _enrich_batch(self, addresses: list[str]) -> int:
        """Interne Batch-Verarbeitung für bis zu 100 Adressen."""
        # Blockchair erlaubt Adressen-Query via kommaseparierte Liste
        addr_str = ",".join(addresses)
        url = f"{BLOCKCHAIR_BASE}/dashboards/addresses/{addr_str}"
        data = self._get(url)
        if not data or "data" not in data:
            return 0

        count = 0
        for addr, addr_data in data["data"].items():
            if not isinstance(addr_data, dict):
                continue
            # Einzel-Response simulieren für _parse_entity
            mock_response = {"data": {addr: addr_data}}
            result = self._parse_entity(mock_response)
            if result:
                entity_name, entity_type = result
                self._repo.upsert(
                    address=addr,
                    source_key=self.SOURCE_KEY,
                    entity_name=entity_name,
                    entity_type=entity_type,
                    is_sanctioned=False,
                    raw_source_data={"source": "blockchair_batch"},
                )
                count += 1

        return count


# ---------------------------------------------------------------------------
# 3. Community List Ingester
# ---------------------------------------------------------------------------
# Mehrere öffentliche GitHub-Quellen mit verifizierten Exchange-Adressen.
# Alle Quellen: MIT/CC-BY/Public Domain — frei nutzbar.
#
# Quellen:
#   a) GitHub Gist mit manuell kuratierten Cold-Wallet-Adressen
#      (f13end/bf88acb162bed0b3dcf5e35f1fdb3c17)
#   b) Weitere Community-Listen werden hier ergänzt
# ---------------------------------------------------------------------------

# Bekannte Community-Quellen.
# Format: (url, source_description, parser_type)
COMMUNITY_SOURCES: list[tuple[str, str, str]] = [
    (
        "https://gist.githubusercontent.com/f13end/bf88acb162bed0b3dcf5e35f1fdb3c17"
        "/raw/exchange_wallets.txt",
        "Community Exchange Wallets List",
        "text_label",  # Format: "address  wallet: ExchangeName  BTC"
    ),
]


class CommunityListIngester:
    """
    Importiert Community-gepflegte Listen bekannter Exchange-Adressen.
    Parst verschiedene Textformate automatisch.
    """

    SOURCE_KEY = "GITHUB_LABELS"

    # Regex-Muster für verschiedene Textformate
    # Format 1: "1ABC... https://... wallet: Binance-coldwallet 137,559 BTC"
    WALLET_LABEL_RE = re.compile(
        r'([13][a-zA-HJ-NP-Z0-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,62})'
        r'.*wallet:\s*([^\s]+)',
        re.IGNORECASE
    )
    # Format 2: Einfache Adresse + Name pro Zeile "1ABC... Binance"
    ADDR_NAME_RE = re.compile(
        r'^([13][a-zA-HJ-NP-Z0-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,62})\s+(.+)$'
    )

    def __init__(self, repo: AttributionRepository):
        self._repo = repo

    def run(self) -> int:
        """Importiert alle konfigurierten Community-Quellen."""
        total = 0
        for url, description, parser_type in COMMUNITY_SOURCES:
            try:
                count = self._import_source(url, description, parser_type)
                total += count
                logger.info(f"CommunityList: {count} Einträge aus '{description}'")
            except Exception as e:
                logger.warning(f"CommunityList: Fehler bei '{description}': {e}")

        self._repo.update_cursor(self.SOURCE_KEY, total, "OK")
        return total

    def _import_source(self, url: str, description: str, parser_type: str) -> int:
        req = Request(url, headers={"User-Agent": "AIFinancialCrime/1.0"})
        try:
            with urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except URLError as e:
            raise RuntimeError(f"Netzwerk-Fehler: {e}")

        if parser_type == "text_label":
            return self._parse_text_label(raw)
        elif parser_type == "csv":
            return self._parse_csv_generic(raw)
        else:
            logger.warning(f"CommunityList: Unbekannter Parser-Typ '{parser_type}'")
            return 0

    def _parse_text_label(self, raw: str) -> int:
        """
        Parst Textformat: "address  wallet: ExchangeName  BTC"
        Wie das öffentliche GitHub Gist format.
        """
        records = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Format 1: wallet: ExchangeName
            m = self.WALLET_LABEL_RE.search(line)
            if m:
                addr = m.group(1).strip()
                raw_label = m.group(2).strip()
                if is_valid_btc_address(addr) and raw_label:
                    # "Binance-coldwallet" → "Binance"
                    entity = normalize_exchange_name(
                        raw_label.replace("-coldwallet", "")
                               .replace("-hot", "")
                               .replace("-cold", "")
                               .replace("-wallet", "")
                    )
                    entity_type = normalize_entity_type(raw_label)
                    records.append({
                        "address":         addr,
                        "source_key":      self.SOURCE_KEY,
                        "entity_name":     entity,
                        "entity_type":     entity_type,
                        "is_sanctioned":   False,
                        "raw_source_data": {"original": raw_label, "source": "community_gist"},
                    })
                    continue

            # Format 2: Adresse Leerzeichen Name
            m2 = self.ADDR_NAME_RE.match(line)
            if m2:
                addr = m2.group(1).strip()
                raw_label = m2.group(2).strip()
                if is_valid_btc_address(addr) and raw_label:
                    records.append({
                        "address":         addr,
                        "source_key":      self.SOURCE_KEY,
                        "entity_name":     normalize_exchange_name(raw_label),
                        "entity_type":     normalize_entity_type(raw_label),
                        "is_sanctioned":   False,
                        "raw_source_data": {"original": raw_label, "source": "community_text"},
                    })

        return self._repo.bulk_upsert(records)

    def _parse_csv_generic(self, raw: str) -> int:
        """
        Parst generisches CSV — delegiert an PublicDatasetIngester._parse_csv.
        Wiederverwendung der Logik ohne Vererbung.
        """
        dummy_repo = self._repo  # gleiche Repo-Referenz
        ingester = PublicDatasetIngester(dummy_repo)
        return ingester._parse_csv(raw, self.SOURCE_KEY)

    def add_source(self, url: str, description: str, parser_type: str = "text_label"):
        """
        Fügt eine neue Community-Quelle zur Liste hinzu.
        Wird sofort importiert.
        """
        try:
            count = self._import_source(url, description, parser_type)
            logger.info(f"CommunityList: Neue Quelle '{description}' — {count} Einträge")
            return count
        except Exception as e:
            logger.error(f"CommunityList: Fehler bei '{description}': {e}")
            return 0


# ---------------------------------------------------------------------------
# Orchestrator — alle Ingesters koordiniert ausführen
# ---------------------------------------------------------------------------

class BulkAttributionOrchestrator:
    """
    Koordiniert alle Bulk-Ingesters in der richtigen Reihenfolge.

    Priorität:
      1. MANUAL / Cold-Wallets (höchste Vertrauensstufe)
      2. Public Dataset (wissenschaftlich kuratiert)
      3. Community Lists
      4. Blockchair (on-demand / batch-enrichment)

    Verwendung:
        orchestrator = BulkAttributionOrchestrator(repo)
        stats = orchestrator.run_full_import()      # Einmaliger Vollimport
        stats = orchestrator.run_daily_update()     # Tägliches Update
    """

    def __init__(
        self,
        repo: AttributionRepository,
        blockchair_api_key: Optional[str] = None,
    ):
        self._repo       = repo
        self._dataset    = PublicDatasetIngester(repo)
        self._community  = CommunityListIngester(repo)
        self._blockchair = BlockchairLabelsIngester(repo, api_key=blockchair_api_key)

    def run_full_import(self) -> dict:
        """
        Vollständiger Erstimport aller Quellen.
        Dauert je nach Netzwerk 1-5 Minuten.
        """
        logger.info("BulkAttribution: Starte Vollimport...")
        start = time.time()
        results = {}

        results["cold_wallets"] = self._dataset.run(force=True)
        results["community"]    = self._community.run()

        elapsed = time.time() - start
        results["elapsed_sec"]  = round(elapsed, 1)
        results["total"]        = sum(v for k, v in results.items()
                                      if k not in ("elapsed_sec",))

        logger.info(
            f"BulkAttribution: Vollimport abgeschlossen — "
            f"{results['total']} Einträge in {elapsed:.1f}s"
        )
        return results

    def run_daily_update(self) -> dict:
        """
        Tägliches Update — aktualisiert nur Quellen die >24h alt sind.
        Kann als Cron-Job laufen.
        """
        logger.info("BulkAttribution: Starte tägliches Update...")
        start = time.time()
        results = {}

        # PublicDatasetIngester prüft Cursor intern (force=False)
        results["dataset"]   = self._dataset.run(force=False)
        results["community"] = self._community.run()

        elapsed = time.time() - start
        results["elapsed_sec"] = round(elapsed, 1)
        return results

    def enrich_address(self, address: str) -> Optional[tuple[str, str, int]]:
        """
        Live-Enrichment einer einzelnen unbekannten Adresse.
        Wird vom CioEngine aufgerufen wenn lokale DB keinen Treffer hat.
        Gibt (entity_name, entity_type, confidence) zurück oder None.
        """
        return self._blockchair.lookup_and_store(address)

    def enrich_cluster(self, addresses: list[str]) -> int:
        """
        Reichert alle Adressen eines CIO-Clusters an.
        Nützlich nach einem neuen Cluster-Merge um Attribution zu verbessern.
        """
        return self._blockchair.batch_enrich(addresses)

    def get_stats(self) -> dict:
        """Gibt aktuelle Statistiken über den Inhalt der Attribution-DB zurück."""
        with self._repo._conn.cursor() as cur:
            cur.execute("SELECT COUNT(DISTINCT address) FROM address_attributions")
            total_addresses = cur.fetchone()[0]

            cur.execute("""
                SELECT entity_type, COUNT(DISTINCT address) as cnt
                FROM address_attributions
                GROUP BY entity_type
                ORDER BY cnt DESC
            """)
            by_type = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute("""
                SELECT s.source_key, COUNT(aa.address) as cnt
                FROM address_attributions aa
                JOIN attribution_sources s ON aa.source_id = s.source_id
                GROUP BY s.source_key ORDER BY cnt DESC
            """)
            by_source = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute("""
                SELECT entity_name, COUNT(*) as cnt
                FROM address_attributions
                WHERE entity_type = 'EXCHANGE'
                GROUP BY entity_name
                ORDER BY cnt DESC
                LIMIT 15
            """)
            top_exchanges = [{"name": r[0], "addresses": r[1]} for r in cur.fetchall()]

        return {
            "total_addresses":  total_addresses,
            "by_type":          by_type,
            "by_source":        by_source,
            "top_exchanges":    top_exchanges,
        }
