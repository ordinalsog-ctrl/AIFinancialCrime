#!/usr/bin/env bash
# scripts/run_attribution_ingest.sh
# Run all attribution source ingesters
#
# Usage:
#   ./scripts/run_attribution_ingest.sh
#   ./scripts/run_attribution_ingest.sh --manual-only
#   ./scripts/run_attribution_ingest.sh --ofac-only
#
# Env vars:
#   POSTGRES_DSN             (required)
#   BITCOINABUSE_API_TOKEN   (optional — skip BitcoinAbuse if not set)
#   MANUAL_ATTRIBUTIONS_PATH (optional — defaults to data/manual_attributions.json)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

MANUAL_PATH="${MANUAL_ATTRIBUTIONS_PATH:-data/manual_attributions.json}"
MODE="${1:-}"

python -c "
import sys, os
sys.path.insert(0, '.')
import psycopg2
from src.investigation.attribution_db import AttributionRepository
from src.investigation.attribution_ingesters import (
    AttributionIngestOrchestrator, ManualIngester, OFACIngester
)

dsn = os.environ['POSTGRES_DSN']
token = os.environ.get('BITCOINABUSE_API_TOKEN')
manual_path = os.environ.get('MANUAL_ATTRIBUTIONS_PATH', 'data/manual_attributions.json')
mode = sys.argv[1] if len(sys.argv) > 1 else 'all'

conn = psycopg2.connect(dsn)
repo = AttributionRepository(conn)

if mode == '--manual-only':
    count = ManualIngester(repo, manual_path).run()
    print(f'Manual: {count} records ingested.')
elif mode == '--ofac-only':
    count = OFACIngester(repo).run()
    print(f'OFAC: {count} records ingested.')
else:
    orch = AttributionIngestOrchestrator(repo, token, manual_path)
    results = orch.run_all()
    print('Ingestion complete:', results)

conn.close()
" "$MODE"
