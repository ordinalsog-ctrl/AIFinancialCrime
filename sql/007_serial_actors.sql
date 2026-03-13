-- =============================================================================
-- Migration: 007_serial_actors.sql
-- Serientäter-Erkennung: gleiche Cluster / Adressen in mehreren Fällen
--
-- Tabellen:
--   investigation_addresses  — alle Adressen pro Investigation (denormalisiert)
--   serial_actor_matches     — Treffer: gleicher Cluster in ≥2 Fällen
--   serial_actor_profiles    — aggregiertes Täter-Profil
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Alle relevanten Adressen einer Investigation (für schnelle Quersuche)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS investigation_addresses (
    id                  BIGSERIAL PRIMARY KEY,
    investigation_id    BIGINT NOT NULL
                        REFERENCES fraud_investigations(investigation_id) ON DELETE CASCADE,
    case_id             TEXT NOT NULL,
    address             TEXT NOT NULL,
    address_role        TEXT NOT NULL,   -- 'FRAUD_ORIGIN' | 'HOP' | 'EXCHANGE_DEPOSIT'
    hop_index           INTEGER,
    confidence_level    TEXT,            -- L1 / L2 / L3 / L4
    amount_btc          NUMERIC(20, 8),
    block_height        INTEGER,
    seen_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inv_addr_address
    ON investigation_addresses(address);
CREATE INDEX IF NOT EXISTS idx_inv_addr_case_id
    ON investigation_addresses(case_id);
CREATE INDEX IF NOT EXISTS idx_inv_addr_inv_id
    ON investigation_addresses(investigation_id);

-- ---------------------------------------------------------------------------
-- Serientäter-Treffer: gleiche Adresse oder gleicher CIO-Cluster in ≥2 Fällen
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS serial_actor_matches (
    match_id            BIGSERIAL PRIMARY KEY,
    match_type          TEXT NOT NULL,      -- 'SAME_ADDRESS' | 'SAME_CIO_CLUSTER' | 'SAME_EXCHANGE_DEPOSIT'
    shared_value        TEXT NOT NULL,      -- Adresse oder Cluster-ID
    case_ids            TEXT[] NOT NULL,    -- Alle betroffenen Cases
    investigation_ids   BIGINT[] NOT NULL,  -- Alle betroffenen Investigation-IDs
    case_count          INTEGER NOT NULL GENERATED ALWAYS AS (array_length(case_ids, 1)) STORED,
    confidence_level    TEXT NOT NULL,      -- L1 / L2 / L3
    total_btc_involved  NUMERIC(20, 8),
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    profile_id          BIGINT,             -- FK → serial_actor_profiles (nullable bis Profil erstellt)
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_serial_match_shared_value
    ON serial_actor_matches(shared_value);
CREATE INDEX IF NOT EXISTS idx_serial_match_case_count
    ON serial_actor_matches(case_count DESC);
CREATE INDEX IF NOT EXISTS idx_serial_match_type
    ON serial_actor_matches(match_type);

-- ---------------------------------------------------------------------------
-- Aggregiertes Täter-Profil (aus mehreren Matches zusammengesetzt)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS serial_actor_profiles (
    profile_id          BIGSERIAL PRIMARY KEY,
    profile_label       TEXT,               -- z.B. "Pig-Butchering-Gruppe A"
    known_addresses     TEXT[] NOT NULL DEFAULT '{}',
    known_cio_clusters  TEXT[] NOT NULL DEFAULT '{}',
    known_exchanges     TEXT[] NOT NULL DEFAULT '{}',
    total_cases         INTEGER NOT NULL DEFAULT 0,
    total_btc_stolen    NUMERIC(20, 8) DEFAULT 0,
    first_case_date     TIMESTAMPTZ,
    last_case_date      TIMESTAMPTZ,
    modus_operandi      TEXT,               -- Beschreibung des Musters
    risk_score          INTEGER DEFAULT 0   -- 0–100, je mehr Fälle desto höher
                        CHECK (risk_score BETWEEN 0 AND 100),
    status              TEXT NOT NULL DEFAULT 'ACTIVE'
                        CHECK (status IN ('ACTIVE', 'ARRESTED', 'RESOLVED', 'SUSPECTED')),
    notes               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Rück-FK von serial_actor_matches → serial_actor_profiles
ALTER TABLE serial_actor_matches
    ADD CONSTRAINT fk_match_profile
    FOREIGN KEY (profile_id)
    REFERENCES serial_actor_profiles(profile_id)
    ON DELETE SET NULL;

-- ---------------------------------------------------------------------------
-- View: Aktive Serientäter mit aggregierten Metriken
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW serial_actor_overview AS
SELECT
    p.profile_id,
    p.profile_label,
    p.total_cases,
    p.total_btc_stolen,
    p.risk_score,
    p.status,
    p.first_case_date,
    p.last_case_date,
    p.modus_operandi,
    array_length(p.known_addresses,    1) AS address_count,
    array_length(p.known_cio_clusters, 1) AS cluster_count,
    array_length(p.known_exchanges,    1) AS exchange_count,
    -- Tage seit letztem bekanntem Fall
    EXTRACT(DAY FROM (NOW() - p.last_case_date))::INTEGER AS days_since_last_case,
    COUNT(m.match_id) AS match_count
FROM serial_actor_profiles p
LEFT JOIN serial_actor_matches m ON m.profile_id = p.profile_id
GROUP BY p.profile_id
ORDER BY p.risk_score DESC, p.total_cases DESC;

-- ---------------------------------------------------------------------------
-- Funktion: Serientäter-Analyse für eine neue Investigation starten
-- Prüft ob Adressen aus dieser Investigation in früheren Fällen vorkommen
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION find_serial_matches(p_investigation_id BIGINT)
RETURNS TABLE (
    match_type       TEXT,
    shared_value     TEXT,
    matching_cases   TEXT[],
    confidence_level TEXT
) LANGUAGE plpgsql AS $$
DECLARE
    v_case_id TEXT;
BEGIN
    SELECT case_id INTO v_case_id
    FROM fraud_investigations
    WHERE investigation_id = p_investigation_id;

    -- Gleiche Adresse in anderen Fällen
    RETURN QUERY
    SELECT
        'SAME_ADDRESS'::TEXT,
        ia_new.address,
        array_agg(DISTINCT ia_old.case_id ORDER BY ia_old.case_id),
        COALESCE(ia_new.confidence_level, 'L3')
    FROM investigation_addresses ia_new
    JOIN investigation_addresses ia_old
        ON ia_old.address = ia_new.address
        AND ia_old.case_id <> ia_new.case_id
    WHERE ia_new.investigation_id = p_investigation_id
    GROUP BY ia_new.address, ia_new.confidence_level
    HAVING count(DISTINCT ia_old.case_id) >= 1;

END;
$$;

-- ---------------------------------------------------------------------------
-- Funktion: Profil aktualisieren nach neuem Match
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION refresh_serial_profile(p_profile_id BIGINT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    UPDATE serial_actor_profiles p
    SET
        total_cases      = sub.case_count,
        total_btc_stolen = sub.total_btc,
        first_case_date  = sub.first_seen,
        last_case_date   = sub.last_seen,
        known_addresses  = sub.addresses,
        known_exchanges  = sub.exchanges,
        risk_score       = LEAST(100, sub.case_count * 10 +
                           CASE WHEN sub.total_btc > 100 THEN 20
                                WHEN sub.total_btc > 10  THEN 10
                                ELSE 0 END),
        updated_at       = NOW()
    FROM (
        SELECT
            COUNT(DISTINCT unnested_case) AS case_count,
            SUM(DISTINCT sam.total_btc_involved) AS total_btc,
            MIN(sam.first_seen) AS first_seen,
            MAX(sam.last_seen)  AS last_seen,
            array_agg(DISTINCT sam.shared_value) FILTER (
                WHERE sam.match_type = 'SAME_ADDRESS') AS addresses,
            array_agg(DISTINCT sam.shared_value) FILTER (
                WHERE sam.match_type = 'SAME_EXCHANGE_DEPOSIT') AS exchanges
        FROM serial_actor_matches sam,
             unnest(sam.case_ids) AS unnested_case
        WHERE sam.profile_id = p_profile_id
    ) sub
    WHERE p.profile_id = p_profile_id;
END;
$$;

-- Migration-Log eintrag
INSERT INTO migration_log(filename, applied_at)
VALUES ('007_serial_actors.sql', NOW())
ON CONFLICT (filename) DO NOTHING;
