"""
AIFinancialCrime — OpenSanctions Bulk Data Ingester
====================================================
Lädt täglich die OpenSanctions Bulk-Daten herunter und indexiert
alle sanktionierten Entities + Crypto-Wallets lokal.

Kostenlos für non-commercial use (CC BY-NC 4.0).
Kein API-Key erforderlich.

Datenquellen (alle in einem Download):
  - OFAC SDN (USA) — inkl. Crypto Wallets
  - EU Consolidated Sanctions
  - UN Security Council
  - UK HM Treasury
  - FATF High-Risk
  - Interpol Red Notices
  - PEP-Datenbank (Politically Exposed Persons)
  - 50+ weitere nationale Listen

Download-URLs:
  Entities (JSON):  https://data.opensanctions.org/datasets/latest/default/entities.ftm.json
  Targets (CSV):    https://data.opensanctions.org/datasets/latest/default/targets.simple.csv
  Metadata:         https://data.opensanctions.org/datasets/latest/default/index.json

Scheduling (crontab):
  # Täglich 02:00 Uhr
  0 2 * * * cd /opt/aifinancialcrime && python3 scripts/ingest_opensanctions.py --update

Verwendung:
  python3 scripts/ingest_opensanctions.py --update     # Download + Import
  python3 scripts/ingest_opensanctions.py --check      # Metadata prüfen
  python3 scripts/ingest_opensanctions.py --stats      # Lokale DB-Statistiken
  python3 scripts/ingest_opensanctions.py --lookup <addr>  # Einzelne Adresse prüfen
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger("aifc.opensanctions_bulk")

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

BASE_URL      = "https://data.opensanctions.org/datasets/latest"
METADATA_URL  = f"{BASE_URL}/sanctions/index.json"
TARGETS_CSV   = f"{BASE_URL}/sanctions/targets.simple.csv"  # ~5MB vs 434MB
ENTITIES_JSON = f"{BASE_URL}/sanctions/entities.ftm.json"

# Lokaler Cache
CACHE_DIR     = Path(os.environ.get("OPENSANCTIONS_CACHE",
                     Path.home() / "AIFinancialCrime-Cases" / "cache" / "opensanctions"))
METADATA_FILE = CACHE_DIR / "metadata.json"
TARGETS_FILE  = CACHE_DIR / "targets.simple.csv"
WALLETS_FILE  = CACHE_DIR / "wallets.json"   # Extrahierte Wallet-Adressen

HEADERS = {
    "User-Agent": "AIFinancialCrime/1.0 (non-commercial research)",
    "Accept":     "*/*",
}


# ---------------------------------------------------------------------------
# Metadata Check
# ---------------------------------------------------------------------------

def get_remote_metadata() -> Optional[dict]:
    """Holt Metadaten vom OpenSanctions Server."""
    try:
        req = Request(METADATA_URL, headers=HEADERS)
        with urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        logger.warning(f"opensanctions_metadata_failed: {e}")
        return None


def get_local_metadata() -> Optional[dict]:
    """Liest lokale Metadaten."""
    if METADATA_FILE.exists():
        with open(METADATA_FILE) as f:
            return json.load(f)
    return None


def needs_update() -> bool:
    """
    Prüft ob ein Update nötig ist via Metadata-Checksum.
    Returns True wenn Remote neuer als Local.
    """
    remote = get_remote_metadata()
    if not remote:
        logger.warning("Konnte Remote-Metadaten nicht abrufen")
        return False

    local = get_local_metadata()
    if not local:
        logger.info("Keine lokalen Daten — Update erforderlich")
        return True

    remote_version = remote.get("version_id") or remote.get("last_export", "")
    local_version  = local.get("version_id") or local.get("last_export", "")

    if remote_version != local_version:
        logger.info(f"Neue Version verfügbar: {local_version} → {remote_version}")
        return True

    logger.info(f"Lokale Daten aktuell (Version: {local_version})")
    return False


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def download_targets_csv() -> Optional[Path]:
    """
    Lädt targets.simple.csv herunter.
    Das ist das kompakteste Format mit allen Entities.

    Spalten:
      id, schema, name, aliases, birth_date, nationalities,
      addresses, identifiers, sanctions, phones, emails,
      dataset, first_seen, last_seen, last_change
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Lade OpenSanctions targets.simple.csv herunter...")

    try:
        req = Request(TARGETS_CSV, headers=HEADERS)
        with urlopen(req, timeout=120) as r:
            total = int(r.headers.get("Content-Length", 0))
            chunk_size = 65536
            downloaded = 0
            with open(TARGETS_FILE, "wb") as f:
                while True:
                    chunk = r.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded / total * 100
                        print(f"\r  {pct:.0f}% ({downloaded//1024//1024}MB/{total//1024//1024}MB)",
                              end="", flush=True)
            print()

        logger.info(f"Download abgeschlossen: {TARGETS_FILE.stat().st_size//1024//1024}MB → {TARGETS_FILE}")
        return TARGETS_FILE

    except Exception as e:
        logger.error(f"Download fehlgeschlagen: {e}")
        return None


# ---------------------------------------------------------------------------
# Parsing & Extraction
# ---------------------------------------------------------------------------

def extract_wallets_from_csv(csv_path: Path) -> dict[str, list[dict]]:
    """
    Parst targets.simple.csv und extrahiert alle Crypto-Wallet-Adressen.

    Returns:
        {
            "bc1q...": [
                {
                    "entity_id": "NK-ABC123",
                    "entity_name": "Lazarus Group",
                    "schema": "Organization",
                    "sanctions": ["OFAC-SDN", "UN-1718"],
                    "datasets": ["us_ofac_sdn", "un_sc_sanctions"],
                    "first_seen": "2022-01-01",
                    "last_seen": "2024-03-15",
                }
            ]
        }
    """
    wallets: dict[str, list[dict]] = {}
    entity_count = 0
    wallet_count = 0

    with open(csv_path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            entity_count += 1

            # identifiers Spalte enthält u.a. Wallet-Adressen
            # Format: "CRYPTO-BTC: bc1q...; CRYPTO-ETH: 0x..."
            identifiers = row.get("identifiers", "")
            if not identifiers:
                continue

            # Bitcoin-Adressen aus identifiers extrahieren
            btc_addrs = []
            for part in identifiers.split(";"):
                part = part.strip()
                if "CRYPTO-BTC:" in part.upper() or "BTC:" in part.upper():
                    addr = part.split(":", 1)[-1].strip()
                    if addr and len(addr) >= 26:
                        btc_addrs.append(addr)
                # Auch direkte Adress-Patterns erkennen
                elif part.startswith(("1", "3", "bc1")):
                    # Validierung: Bitcoin-Adresse Länge
                    if 26 <= len(part) <= 62:
                        btc_addrs.append(part)

            if not btc_addrs:
                continue

            # Entity-Daten
            entity = {
                "entity_id":   row.get("id", ""),
                "entity_name": row.get("name", "Unknown"),
                "schema":      row.get("schema", ""),
                "sanctions":   [s.strip() for s in row.get("sanctions", "").split(";") if s.strip()],
                "datasets":    [row.get("dataset", "")],
                "first_seen":  row.get("first_seen", ""),
                "last_seen":   row.get("last_seen", ""),
                "url":         f"https://www.opensanctions.org/entities/{row.get('id', '')}",
            }

            for addr in btc_addrs:
                if addr not in wallets:
                    wallets[addr] = []
                wallets[addr].append(entity)
                wallet_count += 1

            if entity_count % 10000 == 0:
                print(f"\r  {entity_count:,} Entities verarbeitet, {wallet_count} Wallets gefunden",
                      end="", flush=True)

    print(f"\r  {entity_count:,} Entities verarbeitet, {wallet_count} Wallets gefunden")
    return wallets


def extract_wallets_from_json(json_path: Path) -> dict[str, list[dict]]:
    """
    Alternative: Parst entities.ftm.json für detailliertere Daten.
    Nutzt den walletAddress Property direkt.
    """
    wallets: dict[str, list[dict]] = {}

    with open(json_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entity = json.loads(line)
            except json.JSONDecodeError:
                continue

            props = entity.get("properties", {})
            btc_addrs = []

            # walletAddress Property
            for addr in props.get("walletAddress", []):
                if addr.startswith(("1", "3", "bc1")) and 26 <= len(addr) <= 62:
                    btc_addrs.append(addr)

            if not btc_addrs:
                continue

            entity_data = {
                "entity_id":   entity.get("id", ""),
                "entity_name": entity.get("caption", "Unknown"),
                "schema":      entity.get("schema", ""),
                "sanctions":   props.get("program", []),
                "datasets":    entity.get("datasets", []),
                "topics":      entity.get("topics", []),
                "url":         f"https://www.opensanctions.org/entities/{entity.get('id', '')}",
            }

            for addr in btc_addrs:
                if addr not in wallets:
                    wallets[addr] = []
                wallets[addr].append(entity_data)

    return wallets


# ---------------------------------------------------------------------------
# Import in Attribution DB
# ---------------------------------------------------------------------------

def import_to_attribution_db(wallets: dict, repo) -> int:
    """
    Schreibt alle gefundenen Wallet-Adressen in die Attribution-DB.

    Returns: Anzahl importierter Einträge
    """
    records = []

    for addr, entities in wallets.items():
        for entity in entities:
            records.append({
                "address":       addr,
                "source_key":    "opensanctions",
                "entity_name":   entity["entity_name"],
                "entity_type":   "sanctioned",
                "is_sanctioned": True,
                "abuse_category": "OPENSANCTIONS_SANCTIONED",
                "source_updated_at": datetime.now(timezone.utc),
                "raw_source_data": {
                    "entity_id":  entity["entity_id"],
                    "schema":     entity["schema"],
                    "sanctions":  entity.get("sanctions", []),
                    "datasets":   entity.get("datasets", []),
                    "url":        entity["url"],
                },
            })

    if not records:
        logger.warning("Keine Wallet-Einträge zum Importieren")
        return 0

    count = repo.bulk_upsert(records)
    logger.info(f"opensanctions_import_complete: {count} Einträge")
    return count


def save_wallets_cache(wallets: dict):
    """Speichert extrahierte Wallets als lokalen Cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(WALLETS_FILE, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "wallet_count": len(wallets),
            "wallets": wallets,
        }, f, indent=2)
    logger.info(f"Wallet-Cache gespeichert: {len(wallets)} Adressen → {WALLETS_FILE}")


def load_wallets_cache() -> dict[str, list[dict]]:
    """Lädt lokalen Wallet-Cache."""
    if not WALLETS_FILE.exists():
        return {}
    with open(WALLETS_FILE) as f:
        data = json.load(f)
    return data.get("wallets", {})


# ---------------------------------------------------------------------------
# Lookup (ohne Attribution-DB)
# ---------------------------------------------------------------------------

class OpenSanctionsLocalLookup:
    """
    Lokaler Lookup gegen den OpenSanctions Wallet-Cache.
    Keine API, keine DB — nur lokale JSON-Datei.

    Verwendung in der Forensik-Pipeline als erste Sanctions-Quelle.
    """

    def __init__(self):
        self._wallets = None
        self._loaded_at = None

    def _ensure_loaded(self):
        """Lazy-load des Wallet-Cache."""
        if self._wallets is None:
            self._wallets = load_wallets_cache()
            self._loaded_at = datetime.now(timezone.utc)
            logger.info(f"OpenSanctions lokaler Cache geladen: {len(self._wallets)} Adressen")

    def lookup(self, address: str) -> dict:
        """
        Prüft eine Adresse gegen den lokalen Cache.

        Returns:
            {
                "sanctioned": bool,
                "confidence": "L1" | None,
                "entities": [...],
                "source": "opensanctions_local",
            }
        """
        self._ensure_loaded()

        if address not in self._wallets:
            return {
                "sanctioned": False,
                "confidence": None,
                "entities":   [],
                "source":     "opensanctions_local",
            }

        entities = self._wallets[address]
        return {
            "sanctioned": True,
            "confidence": "L1",  # Direkte Übereinstimmung = L1
            "entities":   entities,
            "source":     "opensanctions_local",
            "entity_name": entities[0]["entity_name"] if entities else "Unknown",
            "sanctions":   entities[0].get("sanctions", []) if entities else [],
        }

    def batch_lookup(self, addresses: list[str]) -> dict[str, dict]:
        """Batch-Lookup für mehrere Adressen."""
        self._ensure_loaded()
        return {addr: self.lookup(addr) for addr in addresses}

    @property
    def wallet_count(self) -> int:
        self._ensure_loaded()
        return len(self._wallets)

    @property
    def cache_exists(self) -> bool:
        return WALLETS_FILE.exists()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="OpenSanctions Bulk Data Ingester"
    )
    parser.add_argument("--update",  action="store_true", help="Download + Import")
    parser.add_argument("--check",   action="store_true", help="Metadata prüfen")
    parser.add_argument("--stats",   action="store_true", help="Lokale Statistiken")
    parser.add_argument("--lookup",  metavar="ADDR",      help="Adresse prüfen")
    parser.add_argument("--force",   action="store_true", help="Update erzwingen")
    parser.add_argument("--dataset", default="sanctions", help="Dataset: sanctions|default|us_ofac_sdn (default: sanctions)")
    parser.add_argument("--no-db",   action="store_true", help="Nur Cache, keine DB")
    args = parser.parse_args()

    if args.check:
        print("Prüfe OpenSanctions Metadaten...")
        remote = get_remote_metadata()
        local  = get_local_metadata()
        print(f"Remote Version: {remote.get('version_id') if remote else 'N/A'}")
        print(f"Lokale Version: {local.get('version_id') if local else 'nicht vorhanden'}")
        print(f"Update nötig:   {needs_update()}")
        return

    if args.stats:
        lookup = OpenSanctionsLocalLookup()
        if lookup.cache_exists:
            print(f"Wallet-Cache:   {WALLETS_FILE}")
            print(f"Wallet-Anzahl:  {lookup.wallet_count:,}")
            meta = get_local_metadata()
            if meta:
                print(f"Version:        {meta.get('version_id', '?')}")
                print(f"Erstellt:       {meta.get('last_export', '?')}")
        else:
            print("Kein lokaler Cache. Bitte --update ausführen.")
        return

    if args.lookup:
        lookup = OpenSanctionsLocalLookup()
        if not lookup.cache_exists:
            print("❌ Kein lokaler Cache. Bitte zuerst --update ausführen.")
            sys.exit(1)
        result = lookup.lookup(args.lookup)
        print(f"\nAdresse: {args.lookup}")
        print(f"Sanctioned: {result['sanctioned']}")
        if result["sanctioned"]:
            print(f"Confidence: {result['confidence']}")
            for entity in result["entities"]:
                print(f"  Entity: {entity['entity_name']}")
                print(f"  Sanctions: {', '.join(entity.get('sanctions', []))}")
                print(f"  URL: {entity['url']}")
        return

    if args.update:
        # Prüfe ob Update nötig
        if not args.force and not needs_update():
            print("✅ Lokale Daten sind aktuell — kein Update nötig")
            print("   (--force zum Erzwingen)")
            return

        t0 = time.monotonic()
        print("=== OpenSanctions Bulk Update ===")
        print(f"Cache-Verzeichnis: {CACHE_DIR}")

        # 1. Download
        print("\n1. Lade targets.simple.csv...")
        csv_path = download_targets_csv()
        if not csv_path:
            print("❌ Download fehlgeschlagen")
            sys.exit(1)

        # 2. Parse
        print("\n2. Extrahiere Bitcoin-Wallet-Adressen...")
        wallets = extract_wallets_from_csv(csv_path)
        print(f"   {len(wallets):,} einzigartige BTC-Adressen gefunden")

        # 3. Cache speichern
        print("\n3. Speichere lokalen Cache...")
        save_wallets_cache(wallets)

        # 4. Metadaten aktualisieren
        remote_meta = get_remote_metadata()
        if remote_meta:
            with open(METADATA_FILE, "w") as f:
                json.dump(remote_meta, f, indent=2)

        # 5. Optional: Attribution-DB Import
        if not args.no_db:
            db_url = os.environ.get("DATABASE_URL",
                                    "postgresql://aifc:aifc@localhost:5432/aifinancialcrime")
            try:
                import psycopg2
                sys.path.insert(0, str(Path(__file__).parent.parent))
                from src.investigation.attribution_db import AttributionRepository
                conn = psycopg2.connect(db_url)
                repo = AttributionRepository(conn)
                print("\n4. Importiere in Attribution-DB...")
                count = import_to_attribution_db(wallets, repo)
                print(f"   {count:,} Einträge importiert")
            except ImportError:
                print("\n4. Attribution-DB Import übersprungen (psycopg2 nicht verfügbar)")
            except Exception as e:
                print(f"\n4. Attribution-DB Import fehlgeschlagen: {e}")
                print("   Wallet-Cache wurde trotzdem gespeichert")

        duration = time.monotonic() - t0
        print(f"\n✅ Update abgeschlossen in {duration:.0f}s")
        print(f"   {len(wallets):,} BTC-Adressen im lokalen Cache")
        print(f"   Cache: {WALLETS_FILE}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
