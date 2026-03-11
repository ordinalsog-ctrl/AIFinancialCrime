from __future__ import annotations

from dataclasses import dataclass
from typing import Any

RULESET_ID = "btc_behavioral_patterns"
RULESET_VERSION = "1.0.0"


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    pattern_name: str
    description: str
    severity_weight: float
    min_input_addr_count: int | None = None
    max_input_addr_count: int | None = None
    min_output_addr_count: int | None = None
    max_output_addr_count: int | None = None
    min_output_ratio: float | None = None

    def thresholds(self) -> dict[str, Any]:
        return {
            "min_input_addr_count": self.min_input_addr_count,
            "max_input_addr_count": self.max_input_addr_count,
            "min_output_addr_count": self.min_output_addr_count,
            "max_output_addr_count": self.max_output_addr_count,
            "min_output_ratio": self.min_output_ratio,
        }


PATTERN_RULES: list[PatternRule] = [
    PatternRule(
        rule_id="PAT-001",
        pattern_name="CONSOLIDATION_PATTERN",
        description="Many input addresses collapse into very few outputs.",
        severity_weight=14.0,
        min_input_addr_count=5,
        max_output_addr_count=2,
    ),
    PatternRule(
        rule_id="PAT-002",
        pattern_name="RAPID_SPLIT_PATTERN",
        description="Very few inputs fan out into many outputs.",
        severity_weight=18.0,
        max_input_addr_count=2,
        min_output_addr_count=8,
    ),
    PatternRule(
        rule_id="PAT-003",
        pattern_name="PEELING_CANDIDATE_PATTERN",
        description="Single input and two outputs with dominant output ratio.",
        severity_weight=12.0,
        min_input_addr_count=1,
        max_input_addr_count=1,
        min_output_addr_count=2,
        max_output_addr_count=2,
        min_output_ratio=0.70,
    ),
]


@dataclass
class PatternMatch:
    txid: str
    min_hop: int
    rule_id: str
    pattern_name: str
    reason_code: str
    confidence: float
    severity_weight: float
    feature_values: dict[str, Any]
    threshold_values: dict[str, Any]


def _passes(row: dict[str, Any], rule: PatternRule) -> bool:
    input_addr_count = int(row.get("input_addr_count") or 0)
    output_addr_count = int(row.get("output_addr_count") or 0)
    top_output_ratio = float(row.get("top_output_ratio") or 0.0)

    if rule.min_input_addr_count is not None and input_addr_count < rule.min_input_addr_count:
        return False
    if rule.max_input_addr_count is not None and input_addr_count > rule.max_input_addr_count:
        return False
    if rule.min_output_addr_count is not None and output_addr_count < rule.min_output_addr_count:
        return False
    if rule.max_output_addr_count is not None and output_addr_count > rule.max_output_addr_count:
        return False
    if rule.min_output_ratio is not None and top_output_ratio < rule.min_output_ratio:
        return False
    return True


def _confidence(row: dict[str, Any], rule: PatternRule) -> float:
    input_addr_count = float(row.get("input_addr_count") or 0)
    output_addr_count = float(row.get("output_addr_count") or 0)
    top_output_ratio = float(row.get("top_output_ratio") or 0.0)
    min_hop = max(1.0, float(row.get("min_hop") or 1))

    base = 0.45
    if rule.pattern_name == "CONSOLIDATION_PATTERN":
        base += min(0.25, input_addr_count / 20.0)
    elif rule.pattern_name == "RAPID_SPLIT_PATTERN":
        base += min(0.25, output_addr_count / 25.0)
    elif rule.pattern_name == "PEELING_CANDIDATE_PATTERN":
        base += min(0.20, max(0.0, top_output_ratio - 0.60))

    hop_penalty = min(0.20, (min_hop - 1.0) * 0.05)
    conf = max(0.35, min(0.95, base - hop_penalty))
    return round(conf, 3)


def evaluate_pattern_matches(feature_rows: list[dict[str, Any]]) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    for row in feature_rows:
        for rule in PATTERN_RULES:
            if not _passes(row, rule):
                continue
            matches.append(
                PatternMatch(
                    txid=str(row.get("txid")),
                    min_hop=int(row.get("min_hop") or 0),
                    rule_id=rule.rule_id,
                    pattern_name=rule.pattern_name,
                    reason_code=f"PATTERN_{rule.pattern_name}",
                    confidence=_confidence(row, rule),
                    severity_weight=rule.severity_weight,
                    feature_values={
                        "input_addr_count": int(row.get("input_addr_count") or 0),
                        "output_addr_count": int(row.get("output_addr_count") or 0),
                        "vin_count": int(row.get("vin_count") or 0),
                        "vout_count": int(row.get("vout_count") or 0),
                        "total_output_sats": int(row.get("total_output_sats") or 0),
                        "top_output_ratio": round(float(row.get("top_output_ratio") or 0.0), 4),
                    },
                    threshold_values=rule.thresholds(),
                )
            )
    return matches


def aggregate_pattern_signals(matches: list[PatternMatch], total_tx: int) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    denom = max(1, total_tx)

    for m in matches:
        key = m.pattern_name
        g = grouped.setdefault(
            key,
            {
                "pattern_name": m.pattern_name,
                "rule_ids": set(),
                "ruleset_id": RULESET_ID,
                "ruleset_version": RULESET_VERSION,
                "tx_count": 0,
                "closest_hop": m.min_hop,
                "avg_confidence": 0.0,
                "density": 0.0,
                "severity_weight": m.severity_weight,
            },
        )
        g["rule_ids"].add(m.rule_id)
        g["tx_count"] += 1
        g["closest_hop"] = min(g["closest_hop"], m.min_hop)
        g["avg_confidence"] += m.confidence

    out: list[dict[str, Any]] = []
    for g in grouped.values():
        tx_count = int(g["tx_count"])
        avg_conf = g["avg_confidence"] / max(1, tx_count)
        out.append(
            {
                "pattern_name": g["pattern_name"],
                "rule_ids": sorted(g["rule_ids"]),
                "ruleset_id": g["ruleset_id"],
                "ruleset_version": g["ruleset_version"],
                "tx_count": tx_count,
                "closest_hop": int(g["closest_hop"]),
                "avg_confidence": round(avg_conf, 3),
                "density": round(tx_count / denom, 4),
                "severity_weight": float(g["severity_weight"]),
            }
        )

    return sorted(out, key=lambda x: (-x["tx_count"], x["closest_hop"], x["pattern_name"]))
