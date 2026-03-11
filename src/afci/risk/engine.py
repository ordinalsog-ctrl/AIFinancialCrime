from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RiskFinding:
    reason_code: str
    contribution: float
    confidence: float


@dataclass
class RiskResult:
    score: float
    findings: list[RiskFinding]


def compute_risk(findings: list[RiskFinding]) -> RiskResult:
    raw_score = sum(max(0.0, f.contribution) * max(0.0, min(1.0, f.confidence)) for f in findings)
    score = min(100.0, round(raw_score, 2))
    return RiskResult(score=score, findings=findings)
