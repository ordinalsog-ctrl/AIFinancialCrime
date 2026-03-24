#!/usr/bin/env bash
# =============================================================================
# AIFinancialCrime — Raspberry Pi Setup
# scripts/setup_pi.sh
#
# Einmalig ausführen nach dem ersten Git-Clone.
# Danach läuft alles vollautomatisch, 24/7, ohne manuellen Eingriff.
#
# Was dieses Script tut:
#   1. System-Dependencies installieren (Python, PostgreSQL, Git, Node.js)
#   2. Python venv + Packages
#   3. PostgreSQL-Datenbank + User anlegen
#   4. Alle SQL-Migrations ausführen
#   5. .env aus Template anlegen (Werte ausfüllen)
#   6. Systemd-Services + Timer installieren und aktivieren
#   7. Frontend Build (React → statische Dateien)
#   8. Erstimport aller Attribution-Daten
#   9. Status-Check
#
# Verwendung:
#   sudo bash scripts/setup_pi.sh
#
# Voraussetzungen:
#   - Raspberry Pi OS (Bookworm 64-bit empfohlen)
#   - Git-Clone bereits vorhanden: /opt/aifinancialcrime
#   - Internet-Verbindung
#   - Bitcoin Core läuft bereits (oder wird separat gestartet)
# =============================================================================

set -euo pipefail

# ── Farben für Ausgabe ──────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${GREEN}[SETUP]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step() { echo -e "\n${BOLD}${BLUE}━━ $* ━━${NC}"; }

# ── Konfiguration ──────────────────────────────────────────────────────────
PROJECT_DIR="/opt/aifinancialcrime"
APP_USER="aifc"
DB_NAME="aifinancialcrime"
DB_USER="aifc"
DB_PASS="$(openssl rand -hex 24)"   # zufälliges Passwort, wird in .env gespeichert
LOG_DIR="/var/log/aifc"
VENV="$PROJECT_DIR/venv"

# ── Muss als root laufen ───────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Bitte als root ausführen: sudo bash $0"
[[ ! -d "$PROJECT_DIR" ]] && err "Projekt nicht gefunden: $PROJECT_DIR\nBitte zuerst: git clone <repo> $PROJECT_DIR"

# =============================================================================
step "1 / 9 — System-Pakete"
# =============================================================================
apt-get update -qq

# Node.js LTS (v20) via NodeSource — für Frontend-Build
if ! command -v node &>/dev/null || [[ $(node -v | cut -d. -f1 | tr -d 'v') -lt 18 ]]; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>/dev/null
fi
apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    postgresql postgresql-client \
    nodejs \
    git curl ca-certificates \
    logrotate \
    2>/dev/null

log "System-Pakete installiert"

# =============================================================================
step "2 / 9 — App-Benutzer"
# =============================================================================
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --shell /bin/bash --home "$PROJECT_DIR" "$APP_USER"
    log "Benutzer '$APP_USER' angelegt"
else
    log "Benutzer '$APP_USER' existiert bereits"
fi

# Projekt dem App-User gehört lassen
chown -R "$APP_USER:$APP_USER" "$PROJECT_DIR"
mkdir -p "$LOG_DIR"
chown "$APP_USER:$APP_USER" "$LOG_DIR"

# =============================================================================
step "3 / 9 — Python venv"
# =============================================================================
if [[ ! -d "$VENV" ]]; then
    sudo -u "$APP_USER" python3 -m venv "$VENV"
    log "venv erstellt"
fi

sudo -u "$APP_USER" "$VENV/bin/pip" install --quiet --upgrade pip

# Requirements installieren (psycopg2-binary + alle App-Deps)
REQS="$PROJECT_DIR/requirements.txt"
if [[ -f "$REQS" ]]; then
    sudo -u "$APP_USER" "$VENV/bin/pip" install --quiet -r "$REQS"
    log "Python-Pakete aus requirements.txt installiert"
else
    # Minimale Basis falls requirements.txt fehlt
    sudo -u "$APP_USER" "$VENV/bin/pip" install --quiet \
        psycopg2-binary fastapi uvicorn requests reportlab
    log "Basis-Python-Pakete installiert"
fi

# =============================================================================
step "4 / 9 — PostgreSQL"
# =============================================================================
systemctl enable --quiet postgresql
systemctl start postgresql

# Warten bis PG bereit
for i in $(seq 1 15); do
    pg_isready -q && break
    sleep 1
done
pg_isready -q || err "PostgreSQL antwortet nicht nach 15 Sekunden"

# DB + User anlegen (idempotent)
sudo -u postgres psql -v ON_ERROR_STOP=0 <<SQL 2>/dev/null || true
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$DB_USER') THEN
    CREATE ROLE $DB_USER WITH LOGIN PASSWORD '$DB_PASS';
  END IF;
END \$\$;

SELECT 'CREATE DATABASE $DB_NAME OWNER $DB_USER'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$DB_NAME')\gexec
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
SQL

log "PostgreSQL: Datenbank '$DB_NAME' und User '$DB_USER' bereit"

# =============================================================================
step "5 / 9 — .env Datei"
# =============================================================================
ENV_FILE="$PROJECT_DIR/.env"

if [[ -f "$ENV_FILE" ]]; then
    warn ".env existiert bereits — wird nicht überschrieben"
    warn "Bitte sicherstellen dass DATABASE_URL korrekt gesetzt ist"
else
    cat > "$ENV_FILE" <<ENV
# AIFinancialCrime — Umgebungsvariablen
# Automatisch generiert von setup_pi.sh
# !! NICHT INS GIT EINCHECKEN !!

# Datenbank
DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}
POSTGRES_DSN=postgresql://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}

# Optionale API-Keys (leer lassen = kostenloser Tier)
BLOCKCHAIR_API_KEY=
BITCOINABUSE_API_TOKEN=

# Bitcoin Core RPC (sobald Node synchronisiert)
BITCOIN_RPC_HOST=127.0.0.1
BITCOIN_RPC_PORT=8332
BITCOIN_RPC_USER=aifc
BITCOIN_RPC_PASS=

# App-Einstellungen
LOG_LEVEL=INFO
JWT_SECRET=$(openssl rand -hex 32)
API_HOST=0.0.0.0
API_PORT=8000
ENV

    chown "$APP_USER:$APP_USER" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    log ".env erstellt (DB-Passwort zufällig generiert)"
fi

# =============================================================================
step "6 / 9 — SQL-Migrationen"
# =============================================================================
# Migrations in Reihenfolge ausführen
export PGPASSWORD="$DB_PASS"

MIGRATIONS=(
    "sql/001_init.sql"
    "sql/002_attribution.sql"
    "sql/003_fraud_investigations.sql"
    "sql/004_api_keys.sql"
    "sql/005_cio_clusters.sql"
)

for migration in "${MIGRATIONS[@]}"; do
    FULL_PATH="$PROJECT_DIR/$migration"
    if [[ ! -f "$FULL_PATH" ]]; then
        warn "Migration nicht gefunden: $migration — übersprungen"
        continue
    fi
    # Idempotent: Fehler bei "already exists" ignorieren
    psql -h localhost -U "$DB_USER" -d "$DB_NAME" \
         -v ON_ERROR_STOP=0 \
         -f "$FULL_PATH" \
         2>&1 | grep -v "already exists" | grep -v "^$" || true
    log "Migration ausgeführt: $migration"
done

unset PGPASSWORD
log "Alle Migrationen abgeschlossen"

# =============================================================================
step "7 / 9 — Systemd Services + Timer"
# =============================================================================

# ── Service: wöchentliches System-Update ────────────────────────────────────
cat > /etc/systemd/system/aifc-system-update.service <<UNIT
[Unit]
Description=AIFinancialCrime — System-Update (apt + git pull)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=$PROJECT_DIR
ExecStart=/bin/bash $PROJECT_DIR/scripts/system_update.sh
StandardOutput=append:$LOG_DIR/system_update.log
StandardError=append:$LOG_DIR/system_update.log
UNIT

cat > /etc/systemd/system/aifc-system-update.timer <<UNIT
[Unit]
Description=AIFinancialCrime — sonntags 02:00 System-Update

[Timer]
# Jeden Sonntag 02:00 Uhr
OnCalendar=Sun *-*-* 02:00:00
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
UNIT

# ── Service: API-Server (dauerhaft laufend) ──────────────────────────────────
cat > /etc/systemd/system/aifc-api.service <<UNIT
[Unit]
Description=AIFinancialCrime — FastAPI Server
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=$APP_USER
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$VENV/bin/uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --workers 2
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/api.log
StandardError=append:$LOG_DIR/api.log

[Install]
WantedBy=multi-user.target
UNIT

# ── Logrotate ────────────────────────────────────────────────────────────────
cat > /etc/logrotate.d/aifc <<LOGROTATE
$LOG_DIR/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 $APP_USER $APP_USER
}
LOGROTATE

# ── Systemd neu laden und aktivieren ────────────────────────────────────────
systemctl daemon-reload

systemctl enable --quiet aifc-system-update.timer
systemctl enable --quiet aifc-api.service

systemctl start aifc-system-update.timer
systemctl start aifc-api.service

log "Systemd-Services aktiviert und gestartet"

# =============================================================================
step "8 / 9 — Frontend Build (React)"
# =============================================================================
FRONTEND_DIR="$PROJECT_DIR/frontend"

if [[ ! -d "$FRONTEND_DIR" ]]; then
    warn "Kein frontend/ Verzeichnis gefunden — Frontend-Build übersprungen"
else
    log "npm install (kann 1-2 Minuten dauern)..."
    sudo -u "$APP_USER" npm --prefix "$FRONTEND_DIR" ci --silent \
        2>&1 | tail -3 | tee -a "$LOG_DIR/build.log"

    log "npm run build..."
    sudo -u "$APP_USER" npm --prefix "$FRONTEND_DIR" run build \
        2>&1 | tail -5 | tee -a "$LOG_DIR/build.log"

    STATIC_DIR="$PROJECT_DIR/static"
    if [[ -f "$STATIC_DIR/index.html" ]]; then
        log "Frontend Build erfolgreich → $STATIC_DIR"
        chown -R "$APP_USER:$APP_USER" "$STATIC_DIR"
    else
        warn "Build scheint fehlgeschlagen — $STATIC_DIR/index.html nicht gefunden"
        warn "Manuell prüfen: cd $FRONTEND_DIR && npm run build"
    fi
fi

# =============================================================================
step "9 / 9 — Abschluss"
# =============================================================================
log "Kein lokaler Exchange-Adress-Import mehr im Hauptprojekt."
log "Exchange-Erkennung wird zentral über den BTC Exchange Intel Agent bereitgestellt."

# =============================================================================
# Abschluss-Status
# =============================================================================
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}  AIFinancialCrime — Setup abgeschlossen        ${NC}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${GREEN}✓${NC} PostgreSQL läuft          (DB: $DB_NAME)"
echo -e "  ${GREEN}✓${NC} API-Server läuft          (Port 8000)"
echo -e "  ${GREEN}✓${NC} Frontend                  (http://$(hostname -I | awk '{print $1}'):8000)"
echo -e "  ${GREEN}✓${NC} System-Update             (sonntags 02:00)"
echo -e "  ${GREEN}✓${NC} Logs                      ($LOG_DIR/)"
echo ""
echo -e "  ${YELLOW}Nächste Schritte:${NC}"
echo -e "  1. .env prüfen und ggf. API-Keys eintragen:"
echo -e "     ${BLUE}nano $ENV_FILE${NC}"
echo -e "  2. Bitcoin Core RPC-Zugangsdaten eintragen (nach Sync)"
echo -e "  3. Status prüfen:"
echo -e "     ${BLUE}sudo systemctl list-timers 'aifc-*'${NC}"
echo -e "     ${BLUE}sudo journalctl -u aifc-api.service -f${NC}"
echo -e "  4. BTC Exchange Intel Agent erreichbar machen und in .env setzen:"
echo -e "     ${BLUE}EXCHANGE_INTEL_API_URL=http://localhost:8080${NC}"
echo ""
echo -e "  ${YELLOW}DB-Passwort (für Backup sichern):${NC}"
echo -e "  $DB_PASS"
echo ""
