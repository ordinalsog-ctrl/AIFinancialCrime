-- =============================================================================
-- Attribution Database Schema
-- Migration: 002_attribution.sql
-- =============================================================================
-- Design principles:
--   - Every attribution has a source, confidence, and audit trail
--   - Multiple sources can attribute the same address (source_priority wins)
--   - All ingestion is idempotent (ON CONFLICT DO UPDATE)
--   - OFAC/manual entries are never overwritten by automated scrapers
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Source registry — every data provider is registered here
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attribution_sources (
    source_id       SERIAL PRIMARY KEY,
    source_key      TEXT NOT NULL UNIQUE,   -- e.g. 'OFAC', 'WALLETEXPLORER', 'BITCOINABUSE', 'MANUAL'
    display_name    TEXT NOT NULL,
    source_url      TEXT,
    confidence_level INTEGER NOT NULL,      -- 1=L1, 2=L2, 3=L3, 4=L4
    priority        INTEGER NOT NULL,       -- lower = higher priority (1 wins over 10)
    is_authoritative BOOLEAN NOT NULL DEFAULT FALSE,  -- true = never overwrite
    last_fetched_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed sources
INSERT INTO attribution_sources (source_key, display_name, source_url, confidence_level, priority, is_authoritative) VALUES
    ('MANUAL',       'Manuell verifiziert',         NULL,                                          1, 1,  TRUE),
    ('OFAC',         'OFAC SDN List',               'https://ofac.treasury.gov/sdn-list',          1, 2,  TRUE),
    ('BITCOINABUSE', 'Bitcoin Abuse Database',       'https://www.bitcoinabuse.com',                2, 3,  FALSE),
    ('WALLETEXPLORER','WalletExplorer.com',          'https://www.walletexplorer.com',              2, 4,  FALSE)
ON CONFLICT (source_key) DO NOTHING;


-- ---------------------------------------------------------------------------
-- Entity registry — named entities (exchanges, sanctioned actors, etc.)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attribution_entities (
    entity_id       SERIAL PRIMARY KEY,
    entity_name     TEXT NOT NULL,          -- e.g. 'Binance', 'Hydra Market'
    entity_type     TEXT NOT NULL,          -- 'EXCHANGE', 'DARKNET', 'MIXER', 'SANCTIONED', 'FRAUD', 'OTHER'
    jurisdiction    TEXT,                   -- ISO country code, e.g. 'US', 'DE'
    is_sanctioned   BOOLEAN NOT NULL DEFAULT FALSE,
    ofac_id         TEXT,                   -- OFAC SDN entry ID if applicable
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attribution_entities_name ON attribution_entities(entity_name);
CREATE INDEX IF NOT EXISTS idx_attribution_entities_type ON attribution_entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_attribution_entities_sanctioned ON attribution_entities(is_sanctioned);


-- ---------------------------------------------------------------------------
-- Address attributions — core lookup table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS address_attributions (
    attribution_id  BIGSERIAL PRIMARY KEY,
    address         TEXT NOT NULL,
    source_id       INTEGER NOT NULL REFERENCES attribution_sources(source_id),
    entity_id       INTEGER REFERENCES attribution_entities(entity_id),
    entity_name     TEXT,                   -- denormalized for fast lookup without JOIN
    entity_type     TEXT,                   -- denormalized
    confidence_level INTEGER NOT NULL,      -- inherited from source, can be overridden
    is_sanctioned   BOOLEAN NOT NULL DEFAULT FALSE,
    abuse_category  TEXT,                   -- for BitcoinAbuse: 'ransomware','scam','darknet', etc.
    report_count    INTEGER DEFAULT 1,      -- number of abuse reports (BitcoinAbuse)
    raw_source_data JSONB,                  -- original data from source for audit
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_updated_at TIMESTAMPTZ,          -- when the source last updated this entry

    CONSTRAINT uq_address_source UNIQUE (address, source_id)
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_address_attributions_address
    ON address_attributions(address);
CREATE INDEX IF NOT EXISTS idx_address_attributions_entity_type
    ON address_attributions(entity_type);
CREATE INDEX IF NOT EXISTS idx_address_attributions_sanctioned
    ON address_attributions(is_sanctioned);
CREATE INDEX IF NOT EXISTS idx_address_attributions_confidence
    ON address_attributions(confidence_level);


-- ---------------------------------------------------------------------------
-- Attribution lookup view — best attribution per address
-- (highest priority source wins, OFAC/MANUAL always on top)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW address_attribution_best AS
SELECT DISTINCT ON (aa.address)
    aa.address,
    aa.entity_name,
    aa.entity_type,
    aa.confidence_level,
    aa.is_sanctioned,
    aa.abuse_category,
    aa.report_count,
    s.source_key,
    s.display_name      AS source_display_name,
    s.source_url,
    s.is_authoritative,
    aa.last_updated_at,
    aa.raw_source_data
FROM address_attributions aa
JOIN attribution_sources s ON aa.source_id = s.source_id
ORDER BY aa.address, s.priority ASC, aa.confidence_level ASC;


-- ---------------------------------------------------------------------------
-- Ingestion cursor — track last fetch per source
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attribution_ingest_cursor (
    source_key      TEXT PRIMARY KEY REFERENCES attribution_sources(source_key),
    last_fetched_at TIMESTAMPTZ,
    last_count      INTEGER,
    last_status     TEXT,           -- 'OK', 'ERROR', 'PARTIAL'
    last_error      TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO attribution_ingest_cursor (source_key, last_status)
    SELECT source_key, 'NEVER' FROM attribution_sources
ON CONFLICT (source_key) DO NOTHING;
