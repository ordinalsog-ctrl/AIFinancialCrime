-- =============================================================================
-- CIO Cluster Schema
-- Migration: 005_cio_clusters.sql
--
-- Common Input Ownership (CIO) Heuristik:
--   Wenn mehrere Adressen als Inputs in derselben TX erscheinen,
--   kontrolliert mit hoher Wahrscheinlichkeit eine einzige Entität alle.
--
-- Design:
--   - address_clusters: jede Adresse → cluster_id (Union-Find flachgehalten)
--   - cluster_labels:   cluster_id → Attribution (Exchange, Mixer, etc.)
--   - cio_evidence:     Audit-Trail welche TXIDs den Cluster begründen
--   - Alle Writes idempotent (ON CONFLICT DO NOTHING / DO UPDATE)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Cluster registry — eine Zeile pro Cluster
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cio_clusters (
    cluster_id      BIGSERIAL PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    address_count   INTEGER NOT NULL DEFAULT 1,
    -- Attribution (sobald eine Adresse im Cluster bekannt ist)
    entity_name     TEXT,
    entity_type     TEXT,       -- 'EXCHANGE', 'MIXER', 'DARKNET', 'OTHER', NULL=unbekannt
    attribution_source TEXT,    -- woher die Attribution kommt
    attributed_at   TIMESTAMPTZ,
    confidence_level INTEGER    -- 1=L1, 2=L2, 3=L3
);

CREATE INDEX IF NOT EXISTS idx_cio_clusters_entity ON cio_clusters(entity_name)
    WHERE entity_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cio_clusters_type ON cio_clusters(entity_type)
    WHERE entity_type IS NOT NULL;


-- ---------------------------------------------------------------------------
-- Adress → Cluster Mapping
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cio_address_cluster (
    address         TEXT PRIMARY KEY,
    cluster_id      BIGINT NOT NULL REFERENCES cio_clusters(cluster_id),
    first_seen_txid TEXT,           -- TXID der ersten CIO-Beobachtung
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cio_address_cluster_cid
    ON cio_address_cluster(cluster_id);


-- ---------------------------------------------------------------------------
-- Evidence Trail — welche TXIDs haben welche Adressen zusammengeführt
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cio_evidence (
    evidence_id     BIGSERIAL PRIMARY KEY,
    txid            TEXT NOT NULL,
    cluster_id      BIGINT NOT NULL REFERENCES cio_clusters(cluster_id),
    addresses_merged TEXT[] NOT NULL,   -- die Adressen die in dieser TX zusammen als Input waren
    input_count     INTEGER NOT NULL,
    observed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_cio_evidence_tx_cluster UNIQUE (txid, cluster_id)
);

CREATE INDEX IF NOT EXISTS idx_cio_evidence_txid ON cio_evidence(txid);
CREATE INDEX IF NOT EXISTS idx_cio_evidence_cluster ON cio_evidence(cluster_id);


-- ---------------------------------------------------------------------------
-- Source registry Erweiterung — neue Sources eintragen
-- ---------------------------------------------------------------------------
INSERT INTO attribution_sources
    (source_key, display_name, source_url, confidence_level, priority, is_authoritative)
VALUES
    ('CIO_HEURISTIC', 'Common Input Ownership Heuristik', NULL, 2, 5, FALSE),
    ('BLOCKCHAIR',    'Blockchair Public Labels',
     'https://blockchair.com', 2, 6, FALSE),
    ('GITHUB_LABELS', 'Community Exchange Address Lists',
     'https://github.com', 3, 7, FALSE),
    ('INVESTIGATION', 'Bestätigter Fund (eigene Untersuchung)',
     NULL, 1, 3, TRUE)
ON CONFLICT (source_key) DO NOTHING;

INSERT INTO attribution_ingest_cursor (source_key, last_status)
    SELECT source_key, 'NEVER' FROM attribution_sources
    WHERE source_key IN ('CIO_HEURISTIC','BLOCKCHAIR','GITHUB_LABELS','INVESTIGATION')
ON CONFLICT (source_key) DO NOTHING;


-- ---------------------------------------------------------------------------
-- Hilfsfunktion: cluster_id für eine Adresse — gibt NULL zurück wenn unbekannt
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION get_cluster_id(p_address TEXT)
RETURNS BIGINT LANGUAGE SQL STABLE AS $$
    SELECT cluster_id FROM cio_address_cluster WHERE address = p_address;
$$;

-- ---------------------------------------------------------------------------
-- View: Beste Attribution pro Adresse inkl. CIO-Cluster-Ableitung
-- Ersetzt address_attribution_best mit erweiterter Logik
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW address_attribution_full AS
-- Direkte Attribution (aus address_attributions)
SELECT
    aa.address,
    aa.entity_name,
    aa.entity_type,
    aa.confidence_level,
    aa.is_sanctioned,
    s.source_key,
    s.display_name      AS source_display_name,
    s.priority          AS source_priority,
    'DIRECT'            AS attribution_method,
    aa.last_updated_at
FROM address_attributions aa
JOIN attribution_sources s ON aa.source_id = s.source_id

UNION ALL

-- Cluster-basierte Attribution (CIO-Ableitung)
SELECT
    ac.address,
    c.entity_name,
    c.entity_type,
    LEAST(c.confidence_level + 1, 4)  AS confidence_level,  -- CIO = 1 Stufe schlechter als Quelle
    FALSE                              AS is_sanctioned,
    'CIO_HEURISTIC'                    AS source_key,
    'CIO-Cluster Ableitung'            AS source_display_name,
    5                                  AS source_priority,
    'CIO_CLUSTER'                      AS attribution_method,
    c.attributed_at                    AS last_updated_at
FROM cio_address_cluster ac
JOIN cio_clusters c ON ac.cluster_id = c.cluster_id
WHERE c.entity_name IS NOT NULL;
