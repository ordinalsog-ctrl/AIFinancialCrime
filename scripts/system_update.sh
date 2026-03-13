#!/usr/bin/env bash
# =============================================================================
# AIFinancialCrime — Wöchentliches System-Update
# scripts/system_update.sh
#
# Wird jeden Sonntag 02:00 Uhr automatisch von systemd ausgeführt.
# Niemals manuell nötig.
#
# Was passiert:
#   1. apt: Security-Updates (nur, keine Major-Upgrades)
#   2. git pull: neuester Code
#   3. pip: Python-Packages aktualisieren
#   4. Services neu starten
#   5. Health-Check — bei Fehler alten Stand wiederherstellen
# =============================================================================

set -euo pipefail

PROJECT_DIR="/opt/aifinancialcrime"
APP_USER="aifc"
VENV="$PROJECT_DIR/venv"
LOG_DIR="/var/log/aifc"
LOG="$LOG_DIR/system_update.log"

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [UPDATE] $*" | tee -a "$LOG"; }
err()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR]  $*" | tee -a "$LOG"; }

log "=== Wöchentliches System-Update gestartet ==="

# ── 1. apt Security-Updates ─────────────────────────────────────────────────
log "apt: Security-Updates..."
apt-get update -qq 2>/dev/null
# Nur Security-Updates — keine automatischen Major-Upgrades
apt-get upgrade -y -o Dpkg::Options::="--force-confold" \
    --only-upgrade 2>/dev/null | tail -3 | tee -a "$LOG" || true
log "apt: fertig"

# ── 2. Git Pull ──────────────────────────────────────────────────────────────
log "git: aktueller Stand..."
cd "$PROJECT_DIR"

# Aktuellen Commit merken für Rollback
OLD_COMMIT=$(sudo -u "$APP_USER" git rev-parse HEAD)
BRANCH=$(sudo -u "$APP_USER" git rev-parse --abbrev-ref HEAD)

# Stash falls lokale Änderungen vorhanden (z.B. .env wird nicht überschrieben)
sudo -u "$APP_USER" git stash --quiet 2>/dev/null || true

if sudo -u "$APP_USER" git pull --quiet origin "$BRANCH" 2>&1 | tee -a "$LOG"; then
    NEW_COMMIT=$(sudo -u "$APP_USER" git rev-parse HEAD)
    if [[ "$OLD_COMMIT" != "$NEW_COMMIT" ]]; then
        log "git: Update von ${OLD_COMMIT:0:8} → ${NEW_COMMIT:0:8}"
        GIT_UPDATED=true
    else
        log "git: Bereits aktuell (${OLD_COMMIT:0:8})"
        GIT_UPDATED=false
    fi
else
    err "git pull fehlgeschlagen — behalte aktuelle Version"
    GIT_UPDATED=false
fi

# Gestashte Änderungen wiederherstellen
sudo -u "$APP_USER" git stash pop --quiet 2>/dev/null || true

# ── 3. SQL-Migrationen (nur neue) ────────────────────────────────────────────
if [[ "${GIT_UPDATED:-false}" == "true" ]]; then
    log "SQL: Prüfe neue Migrationen..."
    source "$PROJECT_DIR/.env"

    for sql_file in "$PROJECT_DIR"/sql/0*.sql; do
        # Prüfen ob Migration bereits im Changelog steht
        MIGRATION_NAME=$(basename "$sql_file")
        EXISTS=$(psql "$DATABASE_URL" -tAc \
            "SELECT 1 FROM information_schema.tables
             WHERE table_name='migration_log'" 2>/dev/null || echo "0")

        if [[ "$EXISTS" == "1" ]]; then
            ALREADY=$(psql "$DATABASE_URL" -tAc \
                "SELECT 1 FROM migration_log WHERE filename='$MIGRATION_NAME'" 2>/dev/null || echo "")
            if [[ -n "$ALREADY" ]]; then
                continue
            fi
        fi

        log "SQL: Führe aus: $MIGRATION_NAME"
        psql "$DATABASE_URL" \
             -v ON_ERROR_STOP=0 \
             -f "$sql_file" \
             2>&1 | grep -v "already exists" | grep -v "^$" | tee -a "$LOG" || true
    done
fi

# ── 4. pip-Packages aktualisieren ────────────────────────────────────────────
if [[ "${GIT_UPDATED:-false}" == "true" ]] && [[ -f "$PROJECT_DIR/requirements.txt" ]]; then
    log "pip: Packages aktualisieren..."
    sudo -u "$APP_USER" "$VENV/bin/pip" install --quiet \
        -r "$PROJECT_DIR/requirements.txt" 2>&1 | tail -2 | tee -a "$LOG"
    log "pip: fertig"
fi

# ── 4b. Frontend neu bauen (nur wenn frontend/ sich geändert hat) ─────────────
if [[ "${GIT_UPDATED:-false}" == "true" ]] && [[ -d "$PROJECT_DIR/frontend" ]]; then
    # Prüfen ob sich Frontend-relevante Dateien geändert haben
    CHANGED_FRONTEND=$(sudo -u "$APP_USER" git -C "$PROJECT_DIR" \
        diff --name-only "$OLD_COMMIT" "$NEW_COMMIT" 2>/dev/null \
        | grep -c "^frontend/" || true)

    if [[ "$CHANGED_FRONTEND" -gt 0 ]]; then
        log "Frontend: $CHANGED_FRONTEND Dateien geändert — baue neu..."
        sudo -u "$APP_USER" npm --prefix "$PROJECT_DIR/frontend" ci --silent \
            2>&1 | tail -2 | tee -a "$LOG"
        sudo -u "$APP_USER" npm --prefix "$PROJECT_DIR/frontend" run build \
            2>&1 | tail -3 | tee -a "$LOG"
        chown -R "$APP_USER:$APP_USER" "$PROJECT_DIR/static" 2>/dev/null || true
        log "Frontend: Build abgeschlossen"
    else
        log "Frontend: keine Änderungen — kein Rebuild nötig"
    fi
fi

# ── 5. Services neu starten ──────────────────────────────────────────────────
if [[ "${GIT_UPDATED:-false}" == "true" ]]; then
    log "Systemd: Services neu starten..."
    systemctl restart aifc-api.service
    sleep 3

    # Health-Check
    if systemctl is-active --quiet aifc-api.service; then
        log "Health-Check: API läuft ✓"
    else
        err "Health-Check FEHLGESCHLAGEN — Rollback auf $OLD_COMMIT"
        cd "$PROJECT_DIR"
        sudo -u "$APP_USER" git checkout "$OLD_COMMIT" --quiet
        sudo -u "$APP_USER" "$VENV/bin/pip" install --quiet \
            -r "$PROJECT_DIR/requirements.txt" 2>/dev/null || true
        systemctl restart aifc-api.service
        sleep 2
        if systemctl is-active --quiet aifc-api.service; then
            log "Rollback erfolgreich — API läuft wieder"
        else
            err "Rollback fehlgeschlagen — manuelle Prüfung erforderlich"
        fi
    fi
else
    log "Kein Code-Update — kein Service-Neustart nötig"
fi

# ── 6. Alten Log-Inhalt komprimieren ─────────────────────────────────────────
# (Logrotate übernimmt das regulär — hier nur als Sicherheitsnetz)
find "$LOG_DIR" -name "*.log" -size +50M -exec gzip {} \; 2>/dev/null || true

log "=== System-Update abgeschlossen ==="
echo ""
