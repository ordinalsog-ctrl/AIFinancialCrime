-- =============================================================================
-- Migration: 003_fraud_investigations.sql
-- Persistenz-Tabelle für abgeschlossene Fraud-Investigations
-- =============================================================================

CREATE TABLE IF NOT EXISTS fraud_investigations (
    investigation_id BIGSERIAL PRIMARY KEY,
    case_id          TEXT NOT NULL UNIQUE,
    fraud_txid       TEXT NOT NULL,
    fraud_address    TEXT NOT NULL,
    fraud_amount_btc NUMERIC(20, 8),
    fraud_timestamp  TIMESTAMPTZ,
    hop_count        INTEGER,
    official_hop_count INTEGER,
    exchange_hits    TEXT[],
    report_hash      TEXT,
    chain_data       JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fraud_inv_fraud_address
    ON fraud_investigations(fraud_address);
CREATE INDEX IF NOT EXISTS idx_fraud_inv_fraud_txid
    ON fraud_investigations(fraud_txid);
CREATE INDEX IF NOT EXISTS idx_fraud_inv_created_at
    ON fraud_investigations(created_at DESC);
