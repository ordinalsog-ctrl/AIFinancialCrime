# Pattern Detection Engine (Transparent Rules)

## Design goals
- Deterministic: same input data -> same matches.
- Explainable: every match has `rule_id`, `reason_code`, thresholds, feature values.
- Versioned: ruleset has fixed `ruleset_id` and `ruleset_version`.

## Ruleset
- `ruleset_id`: `btc_behavioral_patterns`
- `ruleset_version`: `1.0.0`

## Active rules
- `PAT-001` `CONSOLIDATION_PATTERN`
  - Logic: many input addresses to very few output addresses.
  - Thresholds: `min_input_addr_count=5`, `max_output_addr_count=2`
- `PAT-002` `RAPID_SPLIT_PATTERN`
  - Logic: very few input addresses to many outputs.
  - Thresholds: `max_input_addr_count=2`, `min_output_addr_count=8`
- `PAT-003` `PEELING_CANDIDATE_PATTERN`
  - Logic: single-input two-output transaction with dominant output.
  - Thresholds: `min_input_addr_count=1`, `max_input_addr_count=1`, `min_output_addr_count=2`, `max_output_addr_count=2`, `min_output_ratio=0.70`

## Feature model
Pattern matching runs on per-transaction features:
- `input_addr_count`
- `output_addr_count`
- `vin_count`
- `vout_count`
- `total_output_sats`
- `top_output_ratio`
- `min_hop` (distance to investigated seed address)

## Output interfaces
- Aggregated: `pattern-signals`
  - grouped by `pattern_name` with `tx_count`, `closest_hop`, `avg_confidence`, `density`, `rule_ids`.
- Detailed: `pattern-matches`
  - one row per matched transaction with full threshold + feature evidence.

## Risk integration
Pattern signals contribute to risk score with:
- `severity_weight` (rule-defined)
- density and activity factor
- proximity factor (`min_hop`)
- average confidence
