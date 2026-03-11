from __future__ import annotations

import argparse
import json
from pathlib import Path


DEFAULT_POLICY = {
    "max_precision_drop": 0.0,
    "max_recall_drop": 0.0,
    "max_f1_drop": 0.0,
    "max_fpr_increase": 0.0,
    "max_fnr_increase": 0.0,
}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _metric(report: dict, key: str) -> float:
    return float((report.get("metrics") or {}).get(key, 0.0))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check no-regression against a baseline eval report")
    parser.add_argument("--baseline", required=True, help="Baseline eval JSON report")
    parser.add_argument("--candidate", required=True, help="Candidate eval JSON report")
    parser.add_argument("--policy", default=None, help="Optional JSON policy file with delta limits")
    parser.add_argument("--output", default=None, help="Optional output path for comparison JSON")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    baseline = _load_json(Path(args.baseline))
    candidate = _load_json(Path(args.candidate))

    policy = dict(DEFAULT_POLICY)
    if args.policy:
        policy.update(_load_json(Path(args.policy)))

    deltas = {
        "precision_delta": round(_metric(candidate, "precision") - _metric(baseline, "precision"), 6),
        "recall_delta": round(_metric(candidate, "recall") - _metric(baseline, "recall"), 6),
        "f1_delta": round(_metric(candidate, "f1") - _metric(baseline, "f1"), 6),
        "fpr_delta": round(_metric(candidate, "fpr") - _metric(baseline, "fpr"), 6),
        "fnr_delta": round(_metric(candidate, "fnr") - _metric(baseline, "fnr"), 6),
    }

    checks = {
        "precision_ok": deltas["precision_delta"] >= -float(policy["max_precision_drop"]),
        "recall_ok": deltas["recall_delta"] >= -float(policy["max_recall_drop"]),
        "f1_ok": deltas["f1_delta"] >= -float(policy["max_f1_drop"]),
        "fpr_ok": deltas["fpr_delta"] <= float(policy["max_fpr_increase"]),
        "fnr_ok": deltas["fnr_delta"] <= float(policy["max_fnr_increase"]),
    }

    all_ok = all(checks.values())

    output = {
        "baseline": str(args.baseline),
        "candidate": str(args.candidate),
        "policy": policy,
        "deltas": deltas,
        "checks": checks,
        "all_ok": all_ok,
        "baseline_model": baseline.get("model"),
        "candidate_model": candidate.get("model"),
    }

    rendered = json.dumps(output, indent=2)
    print(rendered)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")

    if not all_ok:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
