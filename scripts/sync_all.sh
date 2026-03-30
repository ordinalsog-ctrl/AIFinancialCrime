#!/usr/bin/env bash
# sync_all.sh — Alle Session 1+2+3 Dateien ins Repo einpflegen
# Aufruf: bash sync_all.sh /pfad/zu/downloads
set -e

DOWNLOADS="${1:-$HOME/Downloads}"
REPO="$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")"

echo "🔍 Repo:      $REPO"
echo "📂 Downloads: $DOWNLOADS"
echo ""

cp_file() {
    local src="$DOWNLOADS/$1"
    local dst="$REPO/$2"
    mkdir -p "$(dirname "$dst")"
    if [ -f "$src" ]; then
        cp "$src" "$dst"
        echo "✅ $1 → $2"
    else
        echo "⚠  Nicht gefunden: $1"
    fi
}

echo "=== SQL Migrations ==="
cp_file "000_migration_log.sql"  "sql/000_migration_log.sql"
# 001_init.sql wird NICHT überschrieben
cp_file "002_attribution.sql"    "sql/002_attribution.sql"
cp_file "003_fraud_investigations.sql" "sql/003_fraud_investigations.sql"
cp_file "004_api_keys.sql"       "sql/004_api_keys.sql"
cp_file "005_cio_clusters.sql"   "sql/005_cio_clusters.sql"
cp_file "006_cases.sql"          "sql/006_cases.sql"
cp_file "007_serial_actors.sql"  "sql/007_serial_actors.sql"

echo ""
echo "=== Session 1 — Core Investigation Modules ==="
cp_file "confidence_engine.py"   "src/investigation/confidence_engine.py"
cp_file "attribution_db.py"      "src/investigation/attribution_db.py"
cp_file "peeling_chain.py"       "src/investigation/peeling_chain.py"
cp_file "peeling_chain_v2.py"    "src/investigation/peeling_chain_v2.py"
cp_file "freeze_request.py"      "src/investigation/freeze_request.py"
cp_file "freeze_request_v2.py"   "src/investigation/freeze_request_v2.py"
cp_file "visualizer.py"          "src/investigation/visualizer.py"
cp_file "cio_engine.py"          "src/investigation/cio_engine.py"
cp_file "serial_actor.py"        "src/investigation/serial_actor.py"
cp_file "exchange_contacts.py"   "src/investigation/exchange_contacts.py"
cp_file "adapters.py"            "src/investigation/adapters.py"
cp_file "adapters_v2.py"         "src/investigation/adapters_v2.py"

echo ""
echo "=== Session 2 — Auth ==="
cp_file "auth.py"                "src/api/auth.py"
cp_file "auth_integration.py"   "src/api/auth_integration.py"
cp_file "fraud_report.py"        "src/api/fraud_report.py"

echo ""
echo "=== Pipelines ==="
cp_file "pipeline.py"            "src/investigation/pipeline.py"
cp_file "pipeline_v2.py"         "src/investigation/pipeline_v2.py"
cp_file "pipeline_v3.py"         "src/investigation/pipeline_v3.py"

echo ""
echo "=== Report Generators ==="
cp_file "report_generator.py"    "src/investigation/report_generator.py"
cp_file "report_generator_v2.py" "src/investigation/report_generator_v2.py"
cp_file "report_generator_v3.py" "src/investigation/report_generator_v3.py"
cp_file "report_generator_v4.py" "src/investigation/report_generator_v4.py"

echo ""
echo "=== Tests ==="
cp_file "e2e_test.py"            "tests/e2e_test.py"
cp_file "test_cio_engine.py"     "tests/test_cio_engine.py"
cp_file "test_confidence_engine.py" "tests/test_confidence_engine.py"

echo ""
echo "=== Scripts ==="
cp_file "setup_pi.sh"            "scripts/setup_pi.sh"
cp_file "system_update.sh"       "scripts/system_update.sh"
cp_file "manual_attributions.example.json" "data/manual_attributions.example.json"

echo ""
echo "=== FastAPI Main (OVERWRITE) ==="
cp_file "main.py"                "main.py"

echo ""
echo "=== __init__.py sicherstellen ==="
for d in src/investigation src/api src/core tests; do
    mkdir -p "$REPO/$d"
    touch "$REPO/$d/__init__.py"
    echo "✅ $d/__init__.py"
done

echo ""
echo "=== Git ==="
cd "$REPO"
git add -A
git status --short

echo ""
read -p "Commit-Message [Enter für Default]: " MSG
MSG="${MSG:-feat: add all session 1+2 modules - core investigation, attribution, auth, pipelines, report generators, SQL migrations}"

git commit -m "$MSG"
git push origin main
echo ""
echo "✅ Fertig! Alle Dateien gepusht."
