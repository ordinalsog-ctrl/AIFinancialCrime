-- =============================================================================
-- Migration Log
-- Migration: 000_migration_log.sql
--
-- Wird von system_update.sh genutzt um zu erkennen welche Migrationen
-- bereits ausgeführt wurden. Muss als ERSTE Migration laufen.
-- =============================================================================

CREATE TABLE IF NOT EXISTS migration_log (
    id          SERIAL PRIMARY KEY,
    filename    TEXT NOT NULL UNIQUE,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    checksum    TEXT
);

-- Bestehende Migrationen als bereits angewendet eintragen
-- (da setup_pi.sh sie alle beim Erstsetup ausführt)
INSERT INTO migration_log (filename) VALUES
    ('000_migration_log.sql'),
    ('001_init.sql'),
    ('002_attribution.sql'),
    ('003_fraud_investigations.sql'),
    ('004_api_keys.sql'),
    ('005_cio_clusters.sql')
ON CONFLICT (filename) DO NOTHING;
