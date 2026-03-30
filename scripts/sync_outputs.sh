#!/usr/bin/env bash
# =============================================================================
# AIFinancialCrime — Präzises Session-Sync-Script
# =============================================================================
# Legt alle Session-Dateien an den richtigen Stellen ab.
# Überschreibt NICHT die bestehende Ingestion-Codebasis (run_*.sh, 001_init.sql etc.)
#
# Ausführen im Repo-Root:
#   bash scripts/sync_outputs.sh ~/Downloads
#
# Mit FORCE=1 werden bestehende Dateien überschrieben:
#   FORCE=1 bash scripts/sync_outputs.sh ~/Downloads
# =============================================================================

set -euo pipefail

DOWNLOADS="${1:-$HOME/Downloads}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORCE="${FORCE:-0}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✅ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠  $1${NC}"; }

copy_file() {
    local src="$DOWNLOADS/$1" dst="$REPO_ROOT/$2"
    [[ ! -f "$src" ]] && { warn "Nicht gefunden: $1"; return; }
    [[ -f "$dst" && "$FORCE" != "1" ]] && { echo "⏭  SKIP: $2"; return; }
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst" && ok "$1 → $2"
}

overwrite_file() {
    local src="$DOWNLOADS/$1" dst="$REPO_ROOT/$2"
    [[ ! -f "$src" ]] && { warn "Nicht gefunden: $1"; return; }
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst" && ok "↺  $1 → $2"
}

echo "🔍 Repo:      $REPO_ROOT"
echo "📂 Downloads: $DOWNLOADS"
echo ""

echo "=== HANDOVER ==="
copy_file "HANDOVER.md" "HANDOVER.md"

echo ""
echo "=== Session 3 — Core: Logging + Metrics ==="
copy_file "logging_config.py"  "src/core/logging_config.py"

echo ""
echo "=== Session 3 — API: Health Endpoints ==="
copy_file "health.py"          "src/api/health.py"

echo ""
echo "=== Session 3 — Monitoring ==="
copy_file "prometheus.yml"     "monitoring/prometheus.yml"
copy_file "alerts.yml"         "monitoring/alerts.yml"

echo ""
echo "=== Session 3 — Forensik: Graph + Change + Temporal ==="

echo ""
echo "=== Session 2 — Report v3 ==="
copy_file "006_cases.sql"          "sql/006_cases.sql"
copy_file "setup_pi.sh"            "scripts/setup_pi.sh"
copy_file "system_update.sh"       "scripts/system_update.sh"

echo ""
echo "=== FastAPI Main — OVERWRITE (neue SPA-Version) ==="
overwrite_file "main.py" "main.py"

echo ""
echo "=== Session 1 — Core Investigation Modules ==="
copy_file "confidence_engine.py" "src/investigation/confidence_engine.py"
copy_file "attribution_db.py"    "src/investigation/attribution_db.py"

echo ""
echo "=== SQL Migrations (001_init.sql wird NICHT überschrieben) ==="
copy_file "000_migration_log.sql"        "sql/000_migration_log.sql"
copy_file "002_attribution.sql"          "sql/002_attribution.sql"
copy_file "003_fraud_investigations.sql" "sql/003_fraud_investigations.sql"
copy_file "004_api_keys.sql"             "sql/004_api_keys.sql"
copy_file "005_cio_clusters.sql"         "sql/005_cio_clusters.sql"

echo ""
echo "=== __init__.py anlegen ==="
for pkg in "src/core" "src/api" "src/investigation"; do
    init="$REPO_ROOT/$pkg/__init__.py"
    [[ ! -f "$init" ]] && touch "$init" && ok "Created: $pkg/__init__.py"
done

echo ""
echo "=== Git ==="
cd "$REPO_ROOT"
git status --short

echo ""
read -rp "Commit-Message [Enter für Default]: " MSG
MSG="${MSG:-"feat: forensic infrastructure Phase 1+2+3 - logging, metrics, health, graph, change heuristics, temporal engine"}"

git add -A
git commit -m "$MSG"
git push origin main

echo ""
echo -e "${GREEN}✅ Fertig — alle Dateien auf GitHub.${NC}"
echo "MacBook: git clone https://github.com/ordinalsog-ctrl/AIFinancialCrime"
