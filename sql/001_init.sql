-- Core facts
CREATE TABLE IF NOT EXISTS blocks (
  height BIGINT PRIMARY KEY,
  hash TEXT UNIQUE NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
  txid TEXT PRIMARY KEY,
  block_height BIGINT REFERENCES blocks(height),
  fee_sats BIGINT,
  vsize INT,
  first_seen TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS addresses (
  address TEXT PRIMARY KEY,
  script_type TEXT,
  first_seen TIMESTAMPTZ DEFAULT NOW(),
  last_seen TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS tx_inputs (
  txid TEXT REFERENCES transactions(txid),
  vin_index INT,
  prev_txid TEXT,
  prev_vout INT,
  address TEXT REFERENCES addresses(address),
  amount_sats BIGINT,
  PRIMARY KEY (txid, vin_index)
);

CREATE TABLE IF NOT EXISTS tx_outputs (
  txid TEXT REFERENCES transactions(txid),
  vout_index INT,
  address TEXT REFERENCES addresses(address),
  amount_sats BIGINT,
  spent_by_txid TEXT,
  PRIMARY KEY (txid, vout_index)
);

CREATE TABLE IF NOT EXISTS ingest_cursors (
  cursor_key TEXT PRIMARY KEY,
  last_height BIGINT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_transactions_block_height ON transactions (block_height);
CREATE INDEX IF NOT EXISTS idx_tx_inputs_prev ON tx_inputs (prev_txid, prev_vout);
CREATE INDEX IF NOT EXISTS idx_tx_outputs_address ON tx_outputs (address);
CREATE INDEX IF NOT EXISTS idx_tx_inputs_address ON tx_inputs (address);

-- Intelligence entities
CREATE TABLE IF NOT EXISTS entities (
  entity_id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  confidence NUMERIC(4,3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  source TEXT NOT NULL,
  first_seen TIMESTAMPTZ DEFAULT NOW(),
  last_seen TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS address_entity_links (
  address TEXT REFERENCES addresses(address),
  entity_id BIGINT REFERENCES entities(entity_id),
  confidence NUMERIC(4,3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  reason_code TEXT NOT NULL,
  source TEXT NOT NULL,
  PRIMARY KEY (address, entity_id)
);

-- Investigation workflow
CREATE TABLE IF NOT EXISTS cases (
  case_id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS case_evidence (
  evidence_id BIGSERIAL PRIMARY KEY,
  case_id BIGINT REFERENCES cases(case_id),
  evidence_type TEXT NOT NULL,
  ref_id TEXT NOT NULL,
  notes TEXT,
  confidence NUMERIC(4,3) CHECK (confidence >= 0 AND confidence <= 1),
  reason_code TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Assessment audit trail
CREATE TABLE IF NOT EXISTS risk_assessments (
  assessment_id BIGSERIAL PRIMARY KEY,
  assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  address TEXT NOT NULL,
  max_hops INT NOT NULL,
  result_limit INT NOT NULL,
  score NUMERIC(6,3) NOT NULL,
  risk_band TEXT NOT NULL,
  model_name TEXT NOT NULL,
  model_version TEXT NOT NULL,
  ruleset_id TEXT,
  ruleset_version TEXT,
  payload_json JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_assessment_findings (
  finding_id BIGSERIAL PRIMARY KEY,
  assessment_id BIGINT NOT NULL REFERENCES risk_assessments(assessment_id) ON DELETE CASCADE,
  finding_type TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  base_contribution NUMERIC(10,4) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  effective_contribution NUMERIC(10,4) NOT NULL,
  metadata_json JSONB
);

CREATE INDEX IF NOT EXISTS idx_risk_assessments_address_time ON risk_assessments (address, assessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_findings_assessment ON risk_assessment_findings (assessment_id);
