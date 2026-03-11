# Continuous Optimization Loop (No Regression)

## Goal
Improve detection depth continuously without losing existing quality.

## Loop
1. Run eval on candidate model/rules.
2. Compare candidate vs baseline report.
3. Block release on any prohibited regression.
4. Only then promote candidate to new baseline.

## Commands
```bash
./scripts/run_eval.sh \
  --dataset eval/gold_labels.example.jsonl \
  --high-risk-threshold 50 \
  --output eval/candidate_report.json

./scripts/run_regression.sh \
  --baseline eval/baseline_report.json \
  --candidate eval/candidate_report.json \
  --policy eval/regression_policy.default.json \
  --output eval/regression_check.json
```

## Default policy
Current default policy is strict no-regression:
- precision must not decrease
- recall must not decrease
- f1 must not decrease
- fpr/fnr must not increase

## Release rule
If `run_regression.sh` exits with code `3`, promotion is blocked.
