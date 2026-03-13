-- =============================================================================
-- Case Management Schema
-- Migration: 006_cases.sql
--
-- Datenmodell für das Opfer-Portal:
--
--   users              — Benutzeraccounts (Email + Passwort)
--   user_cases         — Ein Fall pro Betrugsvorfall (1 User : N Cases)
--   case_actions       — Timeline: jede Aktion die der Nutzer unternommen hat
--   case_documents     — Generierte PDFs + hochgeladene Dokumente
--   case_notes         — Freie Notizen mit Zeitstempel
--   case_contacts      — Beteiligte Parteien (Polizei, Exchange, Anwalt, ...)
--
-- Design-Prinzipien:
--   - Jeder Case gehört einem User (row-level security möglich)
--   - case_actions ist die Kern-Timeline — alles hat ein Datum + Status
--   - Verknüpfung zu fraud_investigations über investigation_id (optional)
--     → Ein Case kann auch ohne forensische Analyse angelegt werden
--   - Alle Status-Felder als TEXT mit CHECK — erweiterbar ohne Migration
-- =============================================================================


-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,          -- bcrypt, niemals Plaintext
    full_name       TEXT,
    preferred_lang  TEXT NOT NULL DEFAULT 'de',  -- 'de' | 'en'
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    is_verified     BOOLEAN NOT NULL DEFAULT FALSE,
    email_verify_token TEXT,                -- für E-Mail-Bestätigung
    password_reset_token TEXT,
    password_reset_expires TIMESTAMPTZ,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_active   ON users(is_active) WHERE is_active = TRUE;


-- ---------------------------------------------------------------------------
-- Cases — ein Fall pro Betrugsvorfall
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_cases (
    case_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,

    -- Kerndaten des Vorfalls
    title           TEXT NOT NULL,              -- z.B. "Bitcoin-Betrug Okt 2024"
    fraud_txid      TEXT,                       -- die Haupt-TX des Betrugs
    fraud_address   TEXT,                       -- Empfänger-Adresse
    fraud_amount_btc NUMERIC(20, 8),
    fraud_amount_eur NUMERIC(15, 2),            -- zum Zeitpunkt des Betrugs
    fraud_date      DATE,                       -- wann ist es passiert
    fraud_description TEXT,                     -- freie Beschreibung des Vorfalls

    -- Verknüpfung zur forensischen Analyse
    investigation_id BIGINT REFERENCES fraud_investigations(investigation_id),
    forensic_case_id TEXT,                      -- z.B. CASE-20241015-A3F2

    -- Status des gesamten Falls
    status          TEXT NOT NULL DEFAULT 'OPEN'
                    CHECK (status IN (
                        'OPEN',         -- aktiv, Schritte laufen
                        'PENDING',      -- wartet auf externe Rückmeldung
                        'RESOLVED',     -- positiver Ausgang (Gelder zurück / Exchange kooperiert)
                        'CLOSED',       -- abgeschlossen ohne Erfolg
                        'ARCHIVED'      -- archiviert
                    )),

    -- Schnellzugriff-Flags (aus Actions aggregiert, für Dashboard)
    report_generated        BOOLEAN NOT NULL DEFAULT FALSE,
    freeze_request_sent     BOOLEAN NOT NULL DEFAULT FALSE,
    police_report_filed     BOOLEAN NOT NULL DEFAULT FALSE,
    lawyer_engaged          BOOLEAN NOT NULL DEFAULT FALSE,
    exchange_responded      BOOLEAN NOT NULL DEFAULT FALSE,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cases_user_id   ON user_cases(user_id);
CREATE INDEX IF NOT EXISTS idx_cases_status    ON user_cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_txid      ON user_cases(fraud_txid) WHERE fraud_txid IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cases_inv_id    ON user_cases(investigation_id) WHERE investigation_id IS NOT NULL;


-- ---------------------------------------------------------------------------
-- Case Actions — die Timeline
-- Jede Aktion die der Nutzer unternommen hat oder die das System ausgeführt hat
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS case_actions (
    action_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL REFERENCES user_cases(case_id) ON DELETE CASCADE,

    -- Aktions-Typ
    action_type     TEXT NOT NULL CHECK (action_type IN (
        -- System-generiert (automatisch)
        'SYSTEM_REPORT_GENERATED',      -- PDF-Report erstellt
        'SYSTEM_FREEZE_REQUEST_CREATED',-- Freeze-Request-PDF erstellt
        'SYSTEM_INVESTIGATION_RUN',     -- Forensische Analyse durchgeführt

        -- Nutzer-Aktionen (manuell eingetragen)
        'USER_POLICE_REPORT_FILED',     -- Anzeige erstattet
        'USER_FREEZE_REQUEST_SENT',     -- Freeze Request abgeschickt
        'USER_LAWYER_CONTACTED',        -- Anwalt eingeschaltet
        'USER_EXCHANGE_CONTACTED',      -- Exchange direkt kontaktiert
        'USER_BAFIN_CONTACTED',         -- BaFin kontaktiert
        'USER_COURT_FILING',            -- Gerichtliches Verfahren eingeleitet
        'USER_MEDIA_CONTACTED',         -- Medien / Verbraucherschutz kontaktiert

        -- Rückmeldungen (manuell eingetragen)
        'RESPONSE_POLICE',              -- Rückmeldung von Polizei
        'RESPONSE_EXCHANGE',            -- Rückmeldung von Exchange
        'RESPONSE_LAWYER',              -- Rückmeldung von Anwalt
        'RESPONSE_COURT',               -- Gerichtliche Rückmeldung
        'RESPONSE_BAFIN',               -- Rückmeldung BaFin

        -- Statusänderungen
        'STATUS_CHANGE',                -- Fall-Status geändert
        'NOTE'                          -- Freie Notiz / Gesprächsprotokoll
    )),

    -- Status dieser Aktion
    status          TEXT NOT NULL DEFAULT 'DONE'
                    CHECK (status IN (
                        'DONE',         -- erledigt
                        'PENDING',      -- ausstehend / wartet auf Antwort
                        'FAILED',       -- fehlgeschlagen / abgelehnt
                        'CANCELLED'     -- zurückgezogen
                    )),

    -- Wann
    action_date     DATE NOT NULL DEFAULT CURRENT_DATE,
    action_time     TIMESTAMPTZ,                -- optionale genaue Uhrzeit

    -- Wen / Was
    title           TEXT NOT NULL,              -- kurze Zusammenfassung
    description     TEXT,                       -- ausführliche Beschreibung
    reference_number TEXT,                      -- Aktenzeichen, Ticket-Nr, etc.
    contact_name    TEXT,                       -- Ansprechpartner (z.B. "Fr. Müller, LKA")
    contact_org     TEXT,                       -- Organisation (z.B. "LKA Berlin")

    -- Verknüpfung zu Dokumenten
    document_id     UUID,                       -- FK wird unten gesetzt

    -- Metadaten
    is_system       BOOLEAN NOT NULL DEFAULT FALSE,  -- TRUE = automatisch generiert
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_actions_case_id    ON case_actions(case_id);
CREATE INDEX IF NOT EXISTS idx_actions_type       ON case_actions(action_type);
CREATE INDEX IF NOT EXISTS idx_actions_status     ON case_actions(status);
CREATE INDEX IF NOT EXISTS idx_actions_date       ON case_actions(action_date DESC);


-- ---------------------------------------------------------------------------
-- Case Documents — PDFs und Uploads
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS case_documents (
    document_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL REFERENCES user_cases(case_id) ON DELETE CASCADE,

    doc_type        TEXT NOT NULL CHECK (doc_type IN (
        'FORENSIC_REPORT',          -- generierter Forensik-Report
        'FREEZE_REQUEST',           -- Freeze-Request-PDF
        'POLICE_RECEIPT',           -- Eingangsbestätigung Polizei
        'EXCHANGE_RESPONSE',        -- Antwort des Exchanges
        'LEGAL_DOCUMENT',           -- Gerichtsdokument / Anwaltsschreiben
        'EVIDENCE',                 -- Screenshot, Kontoauszug, etc.
        'OTHER'
    )),

    filename        TEXT NOT NULL,
    storage_path    TEXT NOT NULL,          -- Pfad auf Server / S3-Key
    file_size_bytes INTEGER,
    mime_type       TEXT,
    sha256_hash     TEXT,                   -- Integrität

    -- Metadaten
    title           TEXT,
    exchange_name   TEXT,                   -- bei FREEZE_REQUEST: welcher Exchange
    is_generated    BOOLEAN NOT NULL DEFAULT FALSE,  -- TRUE = von System erstellt
    generated_at    TIMESTAMPTZ,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_documents_case_id  ON case_documents(case_id);
CREATE INDEX IF NOT EXISTS idx_documents_type     ON case_documents(doc_type);

-- FK von case_actions → case_documents (nach Tabellen-Erstellung)
ALTER TABLE case_actions
    ADD CONSTRAINT fk_action_document
    FOREIGN KEY (document_id) REFERENCES case_documents(document_id)
    ON DELETE SET NULL
    DEFERRABLE INITIALLY DEFERRED;


-- ---------------------------------------------------------------------------
-- Case Contacts — Beteiligte Parteien
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS case_contacts (
    contact_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL REFERENCES user_cases(case_id) ON DELETE CASCADE,

    contact_type    TEXT NOT NULL CHECK (contact_type IN (
        'POLICE',       -- Polizei / LKA / BKA
        'EXCHANGE',     -- Krypto-Exchange
        'LAWYER',       -- Rechtsanwalt
        'BAFIN',        -- BaFin / Finanzaufsicht
        'COURT',        -- Gericht
        'MEDIATOR',     -- Vermittler / Verbraucherschutz
        'OTHER'
    )),

    org_name        TEXT NOT NULL,          -- z.B. "LKA Berlin", "Binance"
    contact_person  TEXT,                   -- Ansprechpartner
    email           TEXT,
    phone           TEXT,
    address         TEXT,
    reference_number TEXT,                  -- Aktenzeichen / Ticket-ID
    notes           TEXT,
    first_contact_date DATE,
    last_contact_date  DATE,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contacts_case_id   ON case_contacts(case_id);
CREATE INDEX IF NOT EXISTS idx_contacts_type      ON case_contacts(contact_type);


-- ---------------------------------------------------------------------------
-- View: Case Dashboard — alles auf einen Blick
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW case_dashboard AS
SELECT
    uc.case_id,
    uc.user_id,
    uc.title,
    uc.fraud_txid,
    uc.fraud_address,
    uc.fraud_amount_btc,
    uc.fraud_amount_eur,
    uc.fraud_date,
    uc.status,
    uc.report_generated,
    uc.freeze_request_sent,
    uc.police_report_filed,
    uc.exchange_responded,
    uc.forensic_case_id,
    uc.created_at,
    uc.updated_at,
    -- Letzte Aktion
    (SELECT a.title FROM case_actions a
     WHERE a.case_id = uc.case_id
     ORDER BY a.action_date DESC, a.created_at DESC LIMIT 1) AS last_action_title,
    (SELECT a.action_date FROM case_actions a
     WHERE a.case_id = uc.case_id
     ORDER BY a.action_date DESC, a.created_at DESC LIMIT 1) AS last_action_date,
    -- Offene Aktionen (ausstehende Antworten)
    (SELECT COUNT(*) FROM case_actions a
     WHERE a.case_id = uc.case_id AND a.status = 'PENDING') AS pending_actions,
    -- Dokumente
    (SELECT COUNT(*) FROM case_documents d
     WHERE d.case_id = uc.case_id) AS document_count,
    -- Tage seit letzter Aktivität
    EXTRACT(DAY FROM NOW() - uc.updated_at)::INTEGER AS days_since_update
FROM user_cases uc;


-- ---------------------------------------------------------------------------
-- Hilfsfunktion: Case-Status aggregieren
-- Aktualisiert die Schnellzugriff-Flags aus den Actions
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION refresh_case_flags(p_case_id UUID)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    UPDATE user_cases SET
        report_generated     = EXISTS(
            SELECT 1 FROM case_actions
            WHERE case_id = p_case_id
            AND action_type = 'SYSTEM_REPORT_GENERATED'),
        freeze_request_sent  = EXISTS(
            SELECT 1 FROM case_actions
            WHERE case_id = p_case_id
            AND action_type IN ('SYSTEM_FREEZE_REQUEST_CREATED','USER_FREEZE_REQUEST_SENT')
            AND status = 'DONE'),
        police_report_filed  = EXISTS(
            SELECT 1 FROM case_actions
            WHERE case_id = p_case_id
            AND action_type = 'USER_POLICE_REPORT_FILED'
            AND status = 'DONE'),
        lawyer_engaged       = EXISTS(
            SELECT 1 FROM case_actions
            WHERE case_id = p_case_id
            AND action_type = 'USER_LAWYER_CONTACTED'
            AND status = 'DONE'),
        exchange_responded   = EXISTS(
            SELECT 1 FROM case_actions
            WHERE case_id = p_case_id
            AND action_type = 'RESPONSE_EXCHANGE'
            AND status IN ('DONE','PENDING')),
        updated_at           = NOW()
    WHERE case_id = p_case_id;
END;
$$;
