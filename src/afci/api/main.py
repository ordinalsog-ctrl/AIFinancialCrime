from __future__ import annotations

from fastapi import FastAPI

from afci.config import Settings
from afci.db.postgres import connect, insert_risk_assessment, insert_risk_assessment_finding, tx
from afci.intel.queries import (
    query_entity_exposure,
    query_k_hop_exposure,
    query_pattern_matches,
    query_pattern_signals,
)
from afci.intel.risk_score import build_risk_report

app = FastAPI(title="AIFinancialCrime API", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/intel/k-hop")
def intel_k_hop(address: str, max_hops: int = 3, limit: int = 100) -> dict:
    settings = Settings()
    conn = connect(settings)
    try:
        rows = query_k_hop_exposure(conn, seed_address=address, max_hops=max_hops, limit=limit)
        return {"count": len(rows), "rows": rows}
    finally:
        conn.close()


@app.get("/intel/entity-exposure")
def intel_entity_exposure(address: str, max_hops: int = 3, limit: int = 50) -> dict:
    settings = Settings()
    conn = connect(settings)
    try:
        rows = query_entity_exposure(conn, seed_address=address, max_hops=max_hops, limit=limit)
        return {"count": len(rows), "rows": rows}
    finally:
        conn.close()


@app.get("/intel/pattern-signals")
def intel_pattern_signals(address: str, max_hops: int = 3, limit: int = 50) -> dict:
    settings = Settings()
    conn = connect(settings)
    try:
        rows = query_pattern_signals(conn, seed_address=address, max_hops=max_hops, limit=limit)
        return {"count": len(rows), "rows": rows}
    finally:
        conn.close()


@app.get("/intel/pattern-matches")
def intel_pattern_matches(address: str, max_hops: int = 3, limit: int = 100) -> dict:
    settings = Settings()
    conn = connect(settings)
    try:
        rows = query_pattern_matches(conn, seed_address=address, max_hops=max_hops, limit=limit)
        return {"count": len(rows), "rows": rows}
    finally:
        conn.close()


@app.get("/intel/risk-score")
def intel_risk_score(
    address: str,
    max_hops: int = 3,
    limit: int = 50,
    top_findings: int = 10,
    persist: bool = False,
) -> dict:
    settings = Settings()
    conn = connect(settings)
    try:
        report = build_risk_report(
            conn,
            seed_address=address,
            max_hops=max_hops,
            limit=limit,
            top_findings=top_findings,
        )
        if persist:
            with tx(conn):
                with conn.cursor() as cur:
                    assessment_id = insert_risk_assessment(
                        cur,
                        address=address,
                        max_hops=max_hops,
                        result_limit=limit,
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
        return report
    finally:
        conn.close()
