# Gold-Label Evaluation Framework

## Purpose
This framework measures whether risk scoring and heuristics meet quality targets before release.

## Dataset format (JSONL)
Each line is one case:
- `case_id`: unique case identifier
- `address`: Bitcoin address under test
- `expected_label`: e.g. `clean`, `exchange`, `scam`, `sanctioned`
- `notes`: optional analyst context

## Binary quality target
For v1, labels are reduced to:
- Positive (`high risk`): `high_risk`, `sanctioned`, `scam`, `ransomware`, `darknet`
- Negative: everything else

## Metrics
- Precision
- Recall
- F1
- False Positive Rate (FPR)
- False Negative Rate (FNR)
- Accuracy

## Quality gates
Run with hard thresholds and fail CI if not met:
- `--min-precision`
- `--min-recall`
- `--max-fpr`

The command exits with code `2` when gates fail.

## Example
```bash
./scripts/run_eval.sh \
  --dataset eval/gold_labels.example.jsonl \
  --high-risk-threshold 50 \
  --min-precision 0.85 \
  --min-recall 0.75 \
  --max-fpr 0.10 \
  --output eval/latest_report.json
```
