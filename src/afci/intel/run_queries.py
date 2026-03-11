from __future__ import annotations

import argparse
import json

from afci.config import Settings
from afci.db.postgres import connect, insert_risk_assessment, insert_risk_assessment_finding, tx
from afci.intel.queries import (
    query_entity_exposure,
    query_k_hop_exposure,
    query_pattern_matches,
    query_pattern_signals,
)
from afci.intel.risk_score import build_risk_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run investigation queries")
    sub = parser.add_subparsers(dest="command", required=True)

    k_hop = sub.add_parser("k-hop", help="k-hop address exposure from a seed address")
    k_hop.add_argument("--address", required=True)
    k_hop.add_argument("--max-hops", type=int, default=3)
    k_hop.add_argument("--limit", type=int, default=100)

    entity = sub.add_parser("entity-exposure", help="entity exposure from a seed address")
    entity.add_argument("--address", required=True)
    entity.add_argument("--max-hops", type=int, default=3)
    entity.add_argument("--limit", type=int, default=50)

    patterns = sub.add_parser("pattern-signals", help="detect suspicious transaction behavior patterns")
    patterns.add_argument("--address", required=True)
    patterns.add_argument("--max-hops", type=int, default=3)
    patterns.add_argument("--limit", type=int, default=50)

    pattern_matches = sub.add_parser("pattern-matches", help="list transparent pattern matches per transaction")
    pattern_matches.add_argument("--address", required=True)
    pattern_matches.add_argument("--max-hops", type=int, default=3)
    pattern_matches.add_argument("--limit", type=int, default=100)

    risk = sub.add_parser("risk-score", help="explainable risk score from entity exposure")
    risk.add_argument("--address", required=True)
    risk.add_argument("--max-hops", type=int, default=3)
    risk.add_argument("--limit", type=int, default=50)
    risk.add_argument("--top-findings", type=int, default=10)
    risk.add_argument("--persist", action="store_true")

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    settings = Settings()
    conn = connect(settings)

    try:
        if args.command == "k-hop":
            rows = query_k_hop_exposure(
                conn,
                seed_address=args.address,
                max_hops=args.max_hops,
                limit=args.limit,
            )
        elif args.command == "entity-exposure":
            rows = query_entity_exposure(
                conn,
                seed_address=args.address,
                max_hops=args.max_hops,
                limit=args.limit,
            )
        elif args.command == "pattern-signals":
            rows = query_pattern_signals(
                conn,
                seed_address=args.address,
                max_hops=args.max_hops,
                limit=args.limit,
            )
        elif args.command == "pattern-matches":
            rows = query_pattern_matches(
                conn,
                seed_address=args.address,
                max_hops=args.max_hops,
                limit=args.limit,
            )
        elif args.command == "risk-score":
            report = build_risk_report(
                conn,
                seed_address=args.address,
                max_hops=args.max_hops,
                limit=args.limit,
                top_findings=args.top_findings,
            )
            if args.persist:
                with tx(conn):
                    with conn.cursor() as cur:
                        assessment_id = insert_risk_assessment(
                            cur,
                            address=args.address,
                            max_hops=args.max_hops,
                            result_limit=args.limit,
                            score=float(report["score"]),
                            risk_band=str(report["risk_band"]),
                            model_name=str(report.get("model_name") or "unknown_model"),
                            model_version=str(report.get("model_version") or "unknown_version"),
                            ruleset_id=(report.get("top_pattern_drivers") or [{}])[0].get("ruleset_id"),
                            ruleset_version=(report.get("top_pattern_drivers") or [{}])[0].get("ruleset_version"),
                            payload=report,
                        )
                        for row in report.get("finding_rows", []):
                            insert_risk_assessment_finding(
                                cur,
                                assessment_id=assessment_id,
                                finding_type=str(row.get("finding_type") or "unknown"),
                                reason_code=str(row.get("reason_code") or "UNKNOWN_REASON"),
                                base_contribution=float(row.get("base_contribution") or 0.0),
                                confidence=float(row.get("confidence") or 0.0),
                                effective_contribution=float(row.get("effective_contribution") or 0.0),
                                metadata=row.get("metadata") if isinstance(row.get("metadata"), dict) else {},
                            )
                report["assessment_id"] = assessment_id
                report["persisted"] = True
            print(json.dumps(report, indent=2, default=str))
            return
        else:
            raise ValueError(f"Unsupported command: {args.command}")

        print(json.dumps({"count": len(rows), "rows": rows}, indent=2, default=str))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
