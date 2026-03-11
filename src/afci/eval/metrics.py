from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0



def _safe_div(a: float, b: float) -> float:
    if b == 0:
        return 0.0
    return a / b


def compute_binary_metrics(conf: Confusion) -> dict[str, float]:
    precision = _safe_div(conf.tp, conf.tp + conf.fp)
    recall = _safe_div(conf.tp, conf.tp + conf.fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    fpr = _safe_div(conf.fp, conf.fp + conf.tn)
    fnr = _safe_div(conf.fn, conf.fn + conf.tp)
    accuracy = _safe_div(conf.tp + conf.tn, conf.tp + conf.fp + conf.tn + conf.fn)
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "accuracy": round(accuracy, 4),
    }
