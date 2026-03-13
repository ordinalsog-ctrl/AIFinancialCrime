-- =============================================================================
-- Migration: 004_api_keys.sql
-- API key management + usage tracking
-- =============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    key_id          TEXT PRIMARY KEY,
    key_hash        TEXT NOT NULL UNIQUE,   -- SHA-256, never store raw key
    owner_name      TEXT NOT NULL,
    owner_email     TEXT NOT NULL,
    tier            TEXT NOT NULL DEFAULT 'FREE'
                    CHECK (tier IN ('FREE', 'PRO', 'ENTERPRISE')),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash      ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_email     ON api_keys(owner_email);
CREATE INDEX IF NOT EXISTS idx_api_keys_active    ON api_keys(is_active);

-- Usage log for billing and audit trail
CREATE TABLE IF NOT EXISTS api_usage_log (
    log_id          BIGSERIAL PRIMARY KEY,
    key_id          TEXT REFERENCES api_keys(key_id),
    endpoint        TEXT NOT NULL,
    method          TEXT NOT NULL,
    status_code     INTEGER,
    response_ms     INTEGER,
    ip_address      TEXT,
    is_heavy        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_usage_key_id   ON api_usage_log(key_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_created  ON api_usage_log(created_at DESC);
