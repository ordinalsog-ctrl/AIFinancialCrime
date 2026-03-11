from __future__ import annotations

import argparse
import json
from pathlib import Path

from afci.config import Settings
from afci.db.postgres import connect


DEFAULT_POLICY = {
    "max_dangling_spent_links": 0,
    "max_invalid_spent_links": 0,
    "min_input_address_fill_rate": 0.95,
    "min_input_amount_fill_rate": 0.95,
    "min_spent_link_coverage": 0.98,
}


def _safe_div(a: float, b: float) -> float:
    if b == 0:
        return 0.0
    return a / b


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run data-quality checks for ingested blockchain data")
    parser.add_argument("--policy", default=None, help="Optional JSON policy file")
    parser.add_argument("--output", default=None, help="Optional output JSON path")
    parser.add_argument("--max-dangling-spent-links", type=int, default=None)
    parser.add_argument("--max-invalid-spent-links", type=int, default=None)
    parser.add_argument("--min-input-address-fill-rate", type=float, default=None)
    parser.add_argument("--min-input-amount-fill-rate", type=float, default=None)
    parser.add_argument("--min-spent-link-coverage", type=float, default=None)
    return parser.parse_args()


def _effective_policy(args: argparse.Namespace) -> dict:
    policy = dict(DEFAULT_POLICY)
    if args.policy:
        policy.update(json.loads(Path(args.policy).read_text(encoding="utf-8")))

    overrides = {
        "max_dangling_spent_links": args.max_dangling_spent_links,
        "max_invalid_spent_links": args.max_invalid_spent_links,
        "min_input_address_fill_rate": args.min_input_address_fill_rate,
        "min_input_amount_fill_rate": args.min_input_amount_fill_rate,
        "min_spent_link_coverage": args.min_spent_link_coverage,
    }
    for key, value in overrides.items():
        if value is not None:
            policy[key] = value
    return policy


def _fetch_scalar(cur, query: str) -> int:
    cur.execute(query)
    row = cur.fetchone()
    return int(row[0] or 0)


def main() -> None:
    args = parse_args()
    policy = _effective_policy(args)

    settings = Settings()
    conn = connect(settings)

    try:
        with conn.cursor() as cur:
            blocks_count = _fetch_scalar(cur, "SELECT COUNT(*) FROM blocks")
            tx_count = _fetch_scalar(cur, "SELECT COUNT(*) FROM transactions")
            input_count = _fetch_scalar(cur, "SELECT COUNT(*) FROM tx_inputs")
            output_count = _fetch_scalar(cur, "SELECT COUNT(*) FROM tx_outputs")

            non_coinbase_inputs = _fetch_scalar(cur, "SELECT COUNT(*) FROM tx_inputs WHERE prev_txid IS NOT NULL")
            non_coinbase_inputs_with_address = _fetch_scalar(
                cur,
                "SELECT COUNT(*) FROM tx_inputs WHERE prev_txid IS NOT NULL AND address IS NOT NULL",
            )
            non_coinbase_inputs_with_amount = _fetch_scalar(
                cur,
                "SELECT COUNT(*) FROM tx_inputs WHERE prev_txid IS NOT NULL AND amount_sats IS NOT NULL",
            )

            # Spent link integrity checks
            dangling_spent_links = _fetch_scalar(
                cur,
                """
                SELECT COUNT(*)
                FROM tx_outputs o
                LEFT JOIN transactions t ON t.txid = o.spent_by_txid
                WHERE o.spent_by_txid IS NOT NULL
                  AND t.txid IS NULL
                """,
            )

            invalid_spent_links = _fetch_scalar(
                cur,
                """
                SELECT COUNT(*)
                FROM tx_outputs o
                LEFT JOIN tx_inputs i
                  ON i.txid = o.spent_by_txid
                 AND i.prev_txid = o.txid
                 AND i.prev_vout = o.vout_index
                WHERE o.spent_by_txid IS NOT NULL
                  AND i.txid IS NULL
                """,
            )

            ref_resolvable_inputs = _fetch_scalar(
                cur,
                """
                SELECT COUNT(*)
                FROM tx_inputs i
                JOIN tx_outputs o
                  ON o.txid = i.prev_txid
                 AND o.vout_index = i.prev_vout
                WHERE i.prev_txid IS NOT NULL
                """,
            )

            ref_resolvable_inputs_with_spent = _fetch_scalar(
                cur,
                """
                SELECT COUNT(*)
                FROM tx_inputs i
                JOIN tx_outputs o
                  ON o.txid = i.prev_txid
                 AND o.vout_index = i.prev_vout
                WHERE i.prev_txid IS NOT NULL
                  AND o.spent_by_txid = i.txid
                """,
            )

        metrics = {
            "input_address_fill_rate": round(_safe_div(non_coinbase_inputs_with_address, non_coinbase_inputs), 6),
            "input_amount_fill_rate": round(_safe_div(non_coinbase_inputs_with_amount, non_coinbase_inputs), 6),
            "spent_link_coverage": round(_safe_div(ref_resolvable_inputs_with_spent, ref_resolvable_inputs), 6),
        }

        checks = {
            "dangling_spent_links_ok": dangling_spent_links <= int(policy["max_dangling_spent_links"]),
            "invalid_spent_links_ok": invalid_spent_links <= int(policy["max_invalid_spent_links"]),
            "input_address_fill_ok": metrics["input_address_fill_rate"] >= float(policy["min_input_address_fill_rate"]),
            "input_amount_fill_ok": metrics["input_amount_fill_rate"] >= float(policy["min_input_amount_fill_rate"]),
            "spent_link_coverage_ok": metrics["spent_link_coverage"] >= float(policy["min_spent_link_coverage"]),
        }

        all_ok = all(checks.values())

        report = {
            "counts": {
                "blocks": blocks_count,
                "transactions": tx_count,
                "tx_inputs": input_count,
                "tx_outputs": output_count,
                "non_coinbase_inputs": non_coinbase_inputs,
                "resolvable_inputs": ref_resolvable_inputs,
            },
            "integrity": {
                "dangling_spent_links": dangling_spent_links,
                "invalid_spent_links": invalid_spent_links,
            },
            "metrics": metrics,
            "policy": policy,
            "checks": checks,
            "all_ok": all_ok,
        }

        rendered = json.dumps(report, indent=2)
        print(rendered)

        if args.output:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")

        if not all_ok:
            raise SystemExit(4)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
