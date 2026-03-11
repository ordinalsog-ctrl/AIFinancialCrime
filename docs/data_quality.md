# Data Quality Gate

## Purpose
Validate ingestion integrity and coverage before running model evaluation and regression checks.

## What is checked
- Spent-link integrity
  - `dangling_spent_links`: outputs referencing unknown spending tx
  - `invalid_spent_links`: outputs where `spent_by_txid` does not match any corresponding input reference
- Coverage and fill-rates on non-coinbase inputs
  - `input_address_fill_rate`
  - `input_amount_fill_rate`
- Link coverage on resolvable references
  - `spent_link_coverage`

## Policy and exit behavior
- Policy can be loaded from JSON.
- CLI args can override policy values.
- Exit code `4` means quality gate failed.

## Example
```bash
./scripts/run_data_quality.sh \
  --policy eval/data_quality_policy.default.json \
  --output eval/data_quality_report.json
```
