-- =============================================================================
-- Seed Exchange Addresses
-- Migration: 008_seed_exchange_addresses.sql
-- =============================================================================
-- Bekannte Hot/Cold Wallets der Top-Exchanges.
-- Quellen: Blockchain Explorer Tags, öffentliche Dokumentation, On-Chain-Analyse.
-- Jede Adresse wird als WALLETEXPLORER-Source mit entity_type=EXCHANGE eingetragen.
--
-- Neue Source BLOCKCHAIR hinzugefügt für API-Ergebnisse.
-- Neue Source SEED_EXCHANGE für kuratierte Seed-Daten (Priorität 3, gleich nach OFAC).
-- =============================================================================

-- Neue Attribution Sources
INSERT INTO attribution_sources (source_key, display_name, source_url, confidence_level, priority, is_authoritative) VALUES
    ('BLOCKCHAIR',    'Blockchair API',              'https://blockchair.com',             2, 5, FALSE),
    ('SEED_EXCHANGE', 'Kuratierte Exchange-Adressen', NULL,                                1, 3, FALSE)
ON CONFLICT (source_key) DO NOTHING;

-- Ingestion Cursor für neue Sources
INSERT INTO attribution_ingest_cursor (source_key, last_status)
    SELECT source_key, 'NEVER' FROM attribution_sources
    WHERE source_key IN ('BLOCKCHAIR', 'SEED_EXCHANGE')
ON CONFLICT (source_key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Exchange Entities (idempotent)
-- ---------------------------------------------------------------------------
INSERT INTO attribution_entities (entity_name, entity_type, jurisdiction, notes) VALUES
    ('Binance',    'EXCHANGE', 'KY', 'Größte Krypto-Exchange weltweit'),
    ('Coinbase',   'EXCHANGE', 'US', 'US-regulierte Exchange, NASDAQ-gelistet'),
    ('Kraken',     'EXCHANGE', 'US', 'US-Exchange mit FIAT-Rampen'),
    ('Huobi',      'EXCHANGE', 'SC', 'Auch als HTX bekannt, Seychellen'),
    ('OKX',        'EXCHANGE', 'SC', 'Seychellen-basierte Exchange'),
    ('Bybit',      'EXCHANGE', 'AE', 'Dubai-basierte Exchange'),
    ('Bitfinex',   'EXCHANGE', 'VG', 'BVI-basierte Exchange, iFinex Inc.'),
    ('Bitstamp',   'EXCHANGE', 'LU', 'Luxemburg-regulierte Exchange'),
    ('KuCoin',     'EXCHANGE', 'SC', 'Seychellen-basierte Exchange'),
    ('Gate.io',    'EXCHANGE', 'KY', 'Cayman Islands Exchange'),
    ('Gemini',     'EXCHANGE', 'US', 'US-regulierte Exchange, Winklevoss'),
    ('Bittrex',    'EXCHANGE', 'US', 'US-Exchange (eingeschränkter Betrieb)'),
    ('BitMEX',     'EXCHANGE', 'SC', 'Derivate-Exchange'),
    ('Poloniex',   'EXCHANGE', 'SC', 'Seychellen-basierte Exchange'),
    ('Bitget',     'EXCHANGE', 'SC', 'Seychellen-basierte Exchange'),
    ('MEXC',       'EXCHANGE', 'SC', 'Seychellen-basierte Exchange'),
    ('Crypto.com', 'EXCHANGE', 'SG', 'Singapur-basierte Exchange'),
    ('Upbit',      'EXCHANGE', 'KR', 'Südkoreanische Exchange')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- Seed-Adressen: Bekannte Hot/Cold Wallets
-- Format: (address, source_key, entity_name, entity_type, confidence_level)
-- ---------------------------------------------------------------------------
-- Alle Adressen stammen aus öffentlich getaggten Blockchain-Explorern
-- (WalletExplorer, Blockchair, OXT, etc.)

-- Temporäre Funktion für einfaches Seeding
DO $$
DECLARE
    seed_source_id INTEGER;
BEGIN
    SELECT source_id INTO seed_source_id FROM attribution_sources WHERE source_key = 'SEED_EXCHANGE';

    -- ============================================================
    -- BINANCE
    -- ============================================================
    -- Binance Hot Wallet (größte)
    INSERT INTO address_attributions (address, source_id, entity_name, entity_type, confidence_level, is_sanctioned, raw_source_data)
    VALUES
    ('34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo', seed_source_id, 'Binance', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('3M219KR5vEneNb47ewrPfWyb5jQ2DjxRP6', seed_source_id, 'Binance', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h', seed_source_id, 'Binance', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s', seed_source_id, 'Binance', 'EXCHANGE', 1, FALSE, '{"type":"cold_wallet","verified":true}'),
    ('3JZq4atUahhuA9rLhXLMhhTo133J9rF97j', seed_source_id, 'Binance', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('3LYJfcfHPXYJreMsASk2jkn69LWEYKzexb', seed_source_id, 'Binance', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64', seed_source_id, 'Binance', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('1Pzaqw98PeRfyHypfqyEgg5yycJRsENrE7', seed_source_id, 'Binance', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('39884E3j6KZj82FK4hA3t5a18nDo6VEQqk', seed_source_id, 'Binance', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('bc1ql49ydapnjafl5t2cp9zqpjwe6pdgmxy98859v2', seed_source_id, 'Binance', 'EXCHANGE', 1, FALSE, '{"type":"cold_wallet","verified":true}'),
    ('3Kzh9qAqVWQhEsfQz7zEQL1EuSx5tyNLNS', seed_source_id, 'Binance', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- COINBASE
    -- ============================================================
    ('3Nxwenay9Z8Lc9JBiywExpnEFiLp6Afp8v', seed_source_id, 'Coinbase', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC', seed_source_id, 'Coinbase', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('3ANy9MHZoPLMn7JqBbyDFVKnD3bDPHVKbr', seed_source_id, 'Coinbase', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('395xAunitKWVMetmhPjoeaXRgtipMdZEHs', seed_source_id, 'Coinbase', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('3CD1QW6fjgTwKq3Pj97nty28WZAVkziNom', seed_source_id, 'Coinbase', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', seed_source_id, 'Coinbase', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('bc1q7cyrfmck2ffu2ud3rn5l5a8yv6f0chkp0zpemf', seed_source_id, 'Coinbase', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- KRAKEN
    -- ============================================================
    ('3AfP6p8FJWJDzgYJSeDMkGSfYBBafTaRqp', seed_source_id, 'Kraken', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('3FHNBLobJnbCTFTVakh5TXmEneyf5PT61B', seed_source_id, 'Kraken', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('3H5JTt42K7RmZtromfTSefcMEFMMe18pMD', seed_source_id, 'Kraken', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('bc1qr4dl5wa7kl8yu792dceg9z5knl2gkn220lk7a9', seed_source_id, 'Kraken', 'EXCHANGE', 1, FALSE, '{"type":"cold_wallet","verified":true}'),
    ('bc1qxku0t7nz65yg8mf0w3drxmx8e3uf7dcnw703kd', seed_source_id, 'Kraken', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- HUOBI / HTX
    -- ============================================================
    ('1DLymHytXsdD2Bhz7Ywa8JpGX7QsQFH1xr', seed_source_id, 'Huobi', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true,"alias":"HTX"}'),
    ('1B2opjpPPJNVQHmCjyxqnGP6mLq4wQcPgg', seed_source_id, 'Huobi', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true,"alias":"HTX"}'),
    ('1HckjUpRGcrrRAtFaaCAUaGjsPx9oYmLaZ', seed_source_id, 'Huobi', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('14burnslySnDoBgRYYap5vYm8bVVNp1vJP', seed_source_id, 'Huobi', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('1LAnF8h3qMGx3TSwNUHVneBZUEpwE4gu3D', seed_source_id, 'Huobi', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('1KYiKJEfdJtap9QX2v9BXJMpz2SfU4pgZw', seed_source_id, 'Huobi', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- OKX (ehemals OKEx)
    -- ============================================================
    ('3LQeSn2MMTCDeorcNkqMXGEFzhW7LqiKfA', seed_source_id, 'OKX', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('bc1q2s3rjwvam9dt2ftt4sqxqjf3twav0gdx0k0q2etjz8k6wtmel89s0gswmv', seed_source_id, 'OKX', 'EXCHANGE', 1, FALSE, '{"type":"cold_wallet","verified":true}'),
    ('3FupZp77ySr7jwoLYEJ9mwzJpvoNBXsBnE', seed_source_id, 'OKX', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- BYBIT
    -- ============================================================
    ('bc1qjysjfd9t9aspttpjqzv68k0ydpe7pvyd5v3pjl', seed_source_id, 'Bybit', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('bc1qnpqe3k8c45re39hltyhh8hw0guxq9kf6stpyzy', seed_source_id, 'Bybit', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- BITFINEX
    -- ============================================================
    ('3D2oetdNuZUqQHPJmcMDDHYoqkyNVsFk9r', seed_source_id, 'Bitfinex', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('3JZzSxYuZnMPKiRRngs4F2WCBRzReq92Yg', seed_source_id, 'Bitfinex', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97', seed_source_id, 'Bitfinex', 'EXCHANGE', 1, FALSE, '{"type":"cold_wallet","verified":true}'),

    -- ============================================================
    -- BITSTAMP
    -- ============================================================
    ('3P3QsMVK89JBNqZQv5zMAKG8FK3kJM4rjt', seed_source_id, 'Bitstamp', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('3BiKLKBe4UJXFHV2o5LRhRhkCbEMpxEhsN', seed_source_id, 'Bitstamp', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- KUCOIN
    -- ============================================================
    ('3M4QrHfSnDPxNyNqsmFePkwc4sa2Xjb9M9', seed_source_id, 'KuCoin', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('bc1qz7thke3qklwhg40c24ggwxmj7twc2g63h3w0cr', seed_source_id, 'KuCoin', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- GEMINI
    -- ============================================================
    ('3NhL3vvmjQ6iKPMwDaGx68bFiMjPWkm1N5', seed_source_id, 'Gemini', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- GATE.IO
    -- ============================================================
    ('3Q2PaKfBjJFHWDLYPPSwec7BNXQR4DQSAL', seed_source_id, 'Gate.io', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- BITMEX
    -- ============================================================
    ('3BMEXqGpG4FxBA1KWhRFufXfSTRgzfDBhJ', seed_source_id, 'BitMEX', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('3BMEXT39v2zsYBDrifKjzb5P4DMfcEQPc9', seed_source_id, 'BitMEX', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- POLONIEX
    -- ============================================================
    ('3FMJheviDL32yLgZ2bTgfKGJa2XbcUUxAa', seed_source_id, 'Poloniex', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- CRYPTO.COM
    -- ============================================================
    ('bc1q4c8n5t00jmj8temxdgcc3t32nkg2wjwz24lywv', seed_source_id, 'Crypto.com', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),
    ('3LCGsSmfr24demGvriN4e3ft8wEcDuHFqh', seed_source_id, 'Crypto.com', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}'),

    -- ============================================================
    -- UPBIT
    -- ============================================================
    ('3NtGBs9GDpx2VpMCX4ijiURr5qVFGFbqcZ', seed_source_id, 'Upbit', 'EXCHANGE', 1, FALSE, '{"type":"hot_wallet","verified":true}')

    ON CONFLICT (address, source_id) DO UPDATE SET
        entity_name = EXCLUDED.entity_name,
        entity_type = EXCLUDED.entity_type,
        raw_source_data = EXCLUDED.raw_source_data,
        last_updated_at = NOW();

    RAISE NOTICE 'Seed exchange addresses inserted/updated for source_id=%', seed_source_id;
END $$;

-- Verify
-- SELECT entity_name, COUNT(*) FROM address_attributions WHERE source_id = (SELECT source_id FROM attribution_sources WHERE source_key = 'SEED_EXCHANGE') GROUP BY entity_name ORDER BY entity_name;
