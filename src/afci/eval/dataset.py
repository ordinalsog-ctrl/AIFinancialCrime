from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


HIGH_RISK_LABELS = {"high_risk", "sanctioned", "scam", "ransomware", "darknet"}


@dataclass(frozen=True)
class EvalCase:
    case_id: str
    address: str
    expected_label: str
    notes: str = ""

    @property
    def expected_high_risk(self) -> bool:
        return self.expected_label.lower() in HIGH_RISK_LABELS



def load_eval_cases(path: Path) -> list[EvalCase]:
    cases: list[EvalCase] = []
    with path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            case_id = str(payload.get("case_id") or f"case_{idx}")
            address = str(payload["address"])
            expected_label = str(payload["expected_label"])
            notes = str(payload.get("notes") or "")
            cases.append(EvalCase(case_id=case_id, address=address, expected_label=expected_label, notes=notes))
    if not cases:
        raise ValueError(f"No eval cases found in {path}")
    return cases
