from __future__ import annotations

import argparse
import json
from pathlib import Path

from afci.config import Settings
from afci.db.postgres import connect
from afci.eval.dataset import load_eval_cases
from afci.eval.metrics import Confusion, compute_binary_metrics
from afci.intel.risk_score import build_risk_report


RISK_BANDS = ["low", "medium", "high", "critical"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run labeled quality evaluation for risk scoring")
    parser.add_argument("--dataset", required=True, help="Path to JSONL eval dataset")
    parser.add_argument("--max-hops", type=int, default=3)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--high-risk-threshold", type=float, default=50.0)
    parser.add_argument("--output", default=None, help="Optional path to write JSON report")
    parser.add_argument("--min-precision", type=float, default=None)
    parser.add_argument("--min-recall", type=float, default=None)
    parser.add_argument("--max-fpr", type=float, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dataset_path = Path(args.dataset)
    cases = load_eval_cases(dataset_path)

    settings = Settings()
    conn = connect(settings)
    confusion = Confusion()
    case_results: list[dict] = []
    risk_band_counts: dict[str, int] = {b: 0 for b in RISK_BANDS}
    label_stats: dict[str, dict[str, float]] = {}

    try:
        for case in cases:
            report = build_risk_report(
                conn,
                seed_address=case.address,
                max_hops=args.max_hops,
                limit=args.limit,
                top_findings=10,
            )
            score = float(report["score"])
            predicted_high = score >= args.high_risk_threshold
            expected_high = case.expected_high_risk
            risk_band = str(report.get("risk_band") or "low")
            risk_band_counts[risk_band] = risk_band_counts.get(risk_band, 0) + 1
            ls = label_stats.setdefault(case.expected_label, {"count": 0.0, "score_sum": 0.0, "pred_high_count": 0.0})
            ls["count"] += 1.0
            ls["score_sum"] += score
            if predicted_high:
                ls["pred_high_count"] += 1.0

            if expected_high and predicted_high:
                confusion.tp += 1
            elif not expected_high and predicted_high:
                confusion.fp += 1
            elif not expected_high and not predicted_high:
                confusion.tn += 1
            else:
                confusion.fn += 1

            case_results.append(
                {
                    "case_id": case.case_id,
                    "address": case.address,
                    "expected_label": case.expected_label,
                    "expected_high_risk": expected_high,
                    "predicted_high_risk": predicted_high,
                    "score": score,
                    "risk_band": risk_band,
                    "model_name": report.get("model_name"),
                    "model_version": report.get("model_version"),
                    "top_reasons": [f.get("reason_code") for f in report.get("findings", [])[:5]],
                    "notes": case.notes,
                }
            )
    finally:
        conn.close()

    metrics = compute_binary_metrics(confusion)
    per_label_summary: dict[str, dict[str, float]] = {}
    for label, stats in label_stats.items():
        count = max(1.0, stats["count"])
        per_label_summary[label] = {
            "count": int(stats["count"]),
            "avg_score": round(stats["score_sum"] / count, 3),
            "predicted_high_rate": round(stats["pred_high_count"] / count, 4),
        }

    gates = {
        "min_precision": args.min_precision,
        "min_recall": args.min_recall,
        "max_fpr": args.max_fpr,
    }
    gate_results = {
        "precision_ok": True if args.min_precision is None else metrics["precision"] >= args.min_precision,
        "recall_ok": True if args.min_recall is None else metrics["recall"] >= args.min_recall,
        "fpr_ok": True if args.max_fpr is None else metrics["fpr"] <= args.max_fpr,
    }
    all_gates_ok = all(gate_results.values())

    report = {
        "dataset": str(dataset_path),
        "cases_count": len(cases),
        "high_risk_threshold": args.high_risk_threshold,
        "model": {
            "name": case_results[0]["model_name"] if case_results else None,
            "version": case_results[0]["model_version"] if case_results else None,
        },
        "confusion": {
            "tp": confusion.tp,
            "fp": confusion.fp,
            "tn": confusion.tn,
            "fn": confusion.fn,
        },
        "metrics": metrics,
        "per_label_summary": per_label_summary,
        "risk_band_counts": risk_band_counts,
        "gates": gates,
        "gate_results": gate_results,
        "all_gates_ok": all_gates_ok,
        "case_results": case_results,
    }

    rendered = json.dumps(report, indent=2, default=str)
    print(rendered)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(rendered + "\n", encoding="utf-8")

    if not all_gates_ok:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
