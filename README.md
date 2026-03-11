# AIFinancialCrime

Financial Crime Intelligence Platform (Bitcoin-first) with a deterministic ingestion and investigation core.

## Current Scope
- Bitcoin L1 ingestion into PostgreSQL
- Idempotent upserts for blocks, transactions, inputs, outputs, addresses
- Ingestion cursor tracking for resumable imports
- Initial API skeleton (`/health`)

## Quickstart
1. Install dependencies:
   - `pip install -e .`
2. Set env vars:
   - `BITCOIN_RPC_URL`
   - `BITCOIN_RPC_USER`
   - `BITCOIN_RPC_PASSWORD`
   - `POSTGRES_DSN`
3. Run ingest:
   - `./scripts/run_ingest.sh --max-blocks 5`
4. Run API:
   - `./scripts/run_api.sh`
5. Run investigation queries:
   - `./scripts/run_queries.sh k-hop --address <btc_address> --max-hops 2 --limit 25`
   - `./scripts/run_queries.sh entity-exposure --address <btc_address> --max-hops 3 --limit 25`
   - `./scripts/run_queries.sh pattern-signals --address <btc_address> --max-hops 3 --limit 25`
   - `./scripts/run_queries.sh pattern-matches --address <btc_address> --max-hops 3 --limit 50`
   - `./scripts/run_queries.sh risk-score --address <btc_address> --max-hops 3 --limit 50 --top-findings 10`
   - `./scripts/run_queries.sh risk-score --address <btc_address> --max-hops 3 --limit 50 --top-findings 10 --persist`
6. Run quality evaluation (gold labels):
   - `./scripts/run_eval.sh --dataset eval/gold_labels.example.jsonl --high-risk-threshold 50 --min-precision 0.85 --min-recall 0.75 --max-fpr 0.10 --output eval/latest_report.json`
7. Run no-regression gate (candidate vs baseline):
   - `./scripts/run_regression.sh --baseline eval/baseline_report.json --candidate eval/latest_report.json --policy eval/regression_policy.default.json --output eval/regression_check.json`
8. Run data-quality gate (ingestion integrity):
   - `./scripts/run_data_quality.sh --policy eval/data_quality_policy.default.json --output eval/data_quality_report.json`

## Notes
- Ingest command applies `sql/001_init.sql` automatically before import.
- Re-running the same block range is safe (idempotent upserts).
- Ingest now links spent outputs (`tx_outputs.spent_by_txid`) from tx inputs automatically.
- REST endpoints are available via FastAPI: `/intel/k-hop`, `/intel/entity-exposure`, `/intel/pattern-signals`, `/intel/pattern-matches`, `/intel/risk-score`.
- Pattern detection spec: `docs/pattern_detection.md`.
- Risk methodology spec: `docs/risk_methodology.md`.
- Risk assessments can be persisted via CLI `--persist` or API `persist=true`.
- Evaluation framework spec: `docs/eval_framework.md`.
- Optimization loop spec: `docs/optimization_loop.md`.
- Data quality gate spec: `docs/data_quality.md`.
