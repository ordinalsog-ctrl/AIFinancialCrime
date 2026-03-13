#!/usr/bin/env python3
"""
scripts/run_bulk_attribution_import.py

Einmaliger Vollimport + tägliches Update der Attribution-DB.

Verwendung:
    python scripts/run_bulk_attribution_import.py --full      # Erstimport
    python scripts/run_bulk_attribution_import.py --update    # Tägliches Update
    python scripts/run_bulk_attribution_import.py --stats     # Nur Statistiken
    python scripts/run_bulk_attribution_import.py --csv pfad.csv  # Lokale CSV

Als Cron-Job (täglich 3:00 Uhr):
    0 3 * * * cd /opt/aifinancialcrime && python scripts/run_bulk_attribution_import.py --update >> /var/log/attribution_import.log 2>&1
"""

import argparse
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("attribution_import")

try:
    import psycopg2
except ImportError:
    logger.error("psycopg2 nicht installiert: pip install psycopg2-binary")
    sys.exit(1)

from src.investigation.attribution_db import AttributionRepository
from src.investigation.attribution_ingesters_bulk import (
    BulkAttributionOrchestrator,
    PublicDatasetIngester,
)


def get_db_conn():
    """Verbindung aus Umgebungsvariablen."""
    db_url = os.environ.get("DATABASE_URL")
    if db_url:
        return psycopg2.connect(db_url)
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", 5432)),
        dbname=os.environ.get("DB_NAME", "aifinancialcrime"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASSWORD", ""),
    )


def main():
    parser = argparse.ArgumentParser(description="Attribution DB Bulk Import")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--full",   action="store_true", help="Vollständiger Erstimport")
    group.add_argument("--update", action="store_true", help="Tägliches Update (Cursor-gestützt)")
    group.add_argument("--stats",  action="store_true", help="Statistiken anzeigen")
    group.add_argument("--csv",    metavar="PATH",       help="Lokale CSV-Datei importieren")
    parser.add_argument("--api-key", metavar="KEY",      help="Blockchair API-Key (optional)")
    args = parser.parse_args()

    try:
        conn = get_db_conn()
    except Exception as e:
        logger.error(f"DB-Verbindung fehlgeschlagen: {e}")
        sys.exit(1)

    repo = AttributionRepository(conn)
    orch = BulkAttributionOrchestrator(repo, blockchair_api_key=args.api_key)

    if args.stats:
        stats = orch.get_stats()
        print("\n=== Attribution DB Statistiken ===")
        print(f"Gesamt attribuierte Adressen: {stats['total_addresses']:,}")
        print("\nNach Typ:")
        for etype, cnt in stats["by_type"].items():
            print(f"  {etype:<20} {cnt:>8,}")
        print("\nNach Quelle:")
        for src, cnt in stats["by_source"].items():
            print(f"  {src:<20} {cnt:>8,}")
        print("\nTop Exchanges:")
        for ex in stats["top_exchanges"]:
            print(f"  {ex['name']:<25} {ex['addresses']:>6,} Adressen")
        return

    if args.full:
        logger.info("Starte Vollimport...")
        results = orch.run_full_import()
        logger.info(f"Vollimport abgeschlossen: {json.dumps(results)}")

    elif args.update:
        logger.info("Starte tägliches Update...")
        results = orch.run_daily_update()
        logger.info(f"Update abgeschlossen: {json.dumps(results)}")

    elif args.csv:
        if not os.path.exists(args.csv):
            logger.error(f"Datei nicht gefunden: {args.csv}")
            sys.exit(1)
        ingester = PublicDatasetIngester(repo)
        count = ingester.import_from_csv_file(args.csv, source_key="MANUAL")
        logger.info(f"CSV-Import: {count} Einträge aus {args.csv}")

    conn.close()


if __name__ == "__main__":
    main()
