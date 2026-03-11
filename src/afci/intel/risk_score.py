from __future__ import annotations

from dataclasses import asdict
from typing import Any

from afci.intel.queries import query_entity_exposure, query_pattern_signals
from afci.risk.engine import RiskFinding, compute_risk

MODEL_NAME = "afci_risk_v1"
MODEL_VERSION = "1.1.0"

CATEGORY_WEIGHTS: dict[str, float] = {
    "sanction": 35.0,
    "ransomware": 30.0,
    "darknet": 28.0,
    "mixer": 24.0,
    "scam": 22.0,
    "fraud": 20.0,
    "high_risk_exchange": 16.0,
    "exchange": 8.0,
}


def _category_weight(category: str) -> float:
    lc = category.lower()
    for key, weight in CATEGORY_WEIGHTS.items():
        if key in lc:
            return weight
    return 10.0


def _reason_code(category: str) -> str:
    normalized = category.upper().replace(" ", "_").replace("-", "_")
    return f"EXPOSURE_TO_{normalized}_ENTITY"


def _risk_band(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def build_risk_report(
    conn,
    seed_address: str,
    max_hops: int = 3,
    limit: int = 50,
    top_findings: int = 10,
) -> dict[str, Any]:
    exposures = query_entity_exposure(
        conn,
        seed_address=seed_address,
        max_hops=max_hops,
        limit=limit,
    )
    patterns = query_pattern_signals(
        conn,
        seed_address=seed_address,
        max_hops=max_hops,
        limit=limit,
    )

    findings: list[RiskFinding] = []
    finding_rows: list[dict[str, Any]] = []
    details: list[dict[str, Any]] = []

    for row in exposures:
        category = str(row.get("category") or "unknown")
        entity_name = str(row.get("name") or "unknown")
        min_hop = int(row.get("min_hop") or 0)
        link_confidence = max(0.0, min(1.0, _coerce_float(row.get("max_link_confidence"), 0.0)))
        weighted_exposure = max(0.0, _coerce_float(row.get("weighted_exposure"), 0.0))

        severity_weight = _category_weight(category)
        strength = min(1.0, weighted_exposure)
        proximity = 1.0 / (1.0 + (0.5 * max(1, min_hop)))
        base_contribution = severity_weight * strength * proximity
        reason_code = _reason_code(category)
        effective_contribution = base_contribution * link_confidence

        findings.append(
            RiskFinding(
                reason_code=reason_code,
                contribution=round(base_contribution, 3),
                confidence=round(link_confidence, 3),
            )
        )

        finding_rows.append(
            {
                "finding_type": "entity_exposure",
                "reason_code": reason_code,
                "base_contribution": round(base_contribution, 3),
                "confidence": round(link_confidence, 3),
                "effective_contribution": round(effective_contribution, 3),
                "metadata": {
                    "entity_name": entity_name,
                    "entity_category": category,
                    "min_hop": min_hop,
                    "weighted_exposure": round(weighted_exposure, 3),
                    "severity_weight": severity_weight,
                    "proximity_factor": round(proximity, 3),
                },
            }
        )

        details.append(
            {
                "reason_code": reason_code,
                "entity_name": entity_name,
                "entity_category": category,
                "min_hop": min_hop,
                "weighted_exposure": round(weighted_exposure, 3),
                "link_confidence": round(link_confidence, 3),
                "severity_weight": severity_weight,
                "proximity_factor": round(proximity, 3),
                "base_contribution": round(base_contribution, 3),
                "effective_contribution": round(effective_contribution, 3),
            }
        )

    pattern_details: list[dict[str, Any]] = []
    for row in patterns:
        pattern_name = str(row.get("pattern_name") or "UNKNOWN_PATTERN")
        tx_count = int(row.get("tx_count") or 0)
        closest_hop = int(row.get("closest_hop") or 0)
        density = max(0.0, min(1.0, _coerce_float(row.get("density"), 0.0)))
        pattern_weight = max(0.0, _coerce_float(row.get("severity_weight"), 10.0))
        avg_confidence = max(0.0, min(1.0, _coerce_float(row.get("avg_confidence"), 0.5)))
        rule_ids = row.get("rule_ids") or []
        ruleset_id = str(row.get("ruleset_id") or "unknown_ruleset")
        ruleset_version = str(row.get("ruleset_version") or "unknown_version")

        proximity = 1.0 / (1.0 + (0.5 * max(1, closest_hop)))
        activity_factor = min(1.0, tx_count / 5.0)
        base_contribution = pattern_weight * density * proximity * activity_factor
        confidence = round(avg_confidence, 3)
        reason_code = f"PATTERN_{pattern_name}"
        effective_contribution = base_contribution * confidence

        findings.append(
            RiskFinding(
                reason_code=reason_code,
                contribution=round(base_contribution, 3),
                confidence=confidence,
            )
        )

        finding_rows.append(
            {
                "finding_type": "pattern_signal",
                "reason_code": reason_code,
                "base_contribution": round(base_contribution, 3),
                "confidence": confidence,
                "effective_contribution": round(effective_contribution, 3),
                "metadata": {
                    "pattern_name": pattern_name,
                    "rule_ids": rule_ids,
                    "ruleset_id": ruleset_id,
                    "ruleset_version": ruleset_version,
                    "tx_count": tx_count,
                    "closest_hop": closest_hop,
                    "density": round(density, 4),
                    "pattern_weight": pattern_weight,
                    "proximity_factor": round(proximity, 3),
                    "activity_factor": round(activity_factor, 3),
                },
            }
        )

        pattern_details.append(
            {
                "reason_code": reason_code,
                "pattern_name": pattern_name,
                "rule_ids": rule_ids,
                "ruleset_id": ruleset_id,
                "ruleset_version": ruleset_version,
                "tx_count": tx_count,
                "closest_hop": closest_hop,
                "density": round(density, 4),
                "pattern_weight": pattern_weight,
                "avg_confidence": round(avg_confidence, 3),
                "proximity_factor": round(proximity, 3),
                "activity_factor": round(activity_factor, 3),
                "base_contribution": round(base_contribution, 3),
                "effective_contribution": round(effective_contribution, 3),
            }
        )

    risk = compute_risk(findings)
    ordered_details = sorted(details, key=lambda item: item["effective_contribution"], reverse=True)
    ordered_patterns = sorted(pattern_details, key=lambda item: item["effective_contribution"], reverse=True)
    ordered_findings = sorted(finding_rows, key=lambda item: item["effective_contribution"], reverse=True)

    return {
        "address": seed_address,
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "score": risk.score,
        "risk_band": _risk_band(risk.score),
        "findings_count": len(findings),
        "findings": [asdict(f) for f in risk.findings[:top_findings]],
        "finding_rows": ordered_findings[:top_findings],
        "top_entity_drivers": ordered_details[:top_findings],
        "top_pattern_drivers": ordered_patterns[:top_findings],
        "methodology": {
            "formula": "effective = base_contribution * confidence",
            "risk_score": "score = min(100, sum(effective))",
            "entity_factors": ["severity_weight", "weighted_exposure_cap", "proximity_factor", "link_confidence"],
            "pattern_factors": ["severity_weight", "density", "proximity_factor", "activity_factor", "avg_confidence"],
        },
    }
