from __future__ import annotations

from dataclasses import dataclass

_FLAGGED = {"block", "redact"}


@dataclass(frozen=True)
class Metrics:
    bypass_rate: float
    false_positive_rate: float
    precision: float
    recall: float
    f1: float
    action_match_rate: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    n: int


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    # nearest-rank
    k = max(0, min(len(ordered) - 1, round(pct / 100.0 * (len(ordered) - 1))))
    return float(ordered[k])


def compute_metrics(rows, observed, latencies_ms) -> Metrics:
    tp = fp = fn = tn = 0
    bypass = fp_count = 0
    sensitive = benign = 0
    action_match = 0

    for row in rows:
        obs = observed[row.id]
        is_sensitive = row.expected_action in _FLAGGED
        is_flagged = obs in _FLAGGED
        if obs == row.expected_action:
            action_match += 1
        if is_sensitive:
            sensitive += 1
            if is_flagged:
                tp += 1
            else:
                fn += 1
                bypass += 1
        else:
            benign += 1
            if is_flagged:
                fp += 1
                fp_count += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    n = len(rows)
    return Metrics(
        bypass_rate=bypass / sensitive if sensitive else 0.0,
        false_positive_rate=fp_count / benign if benign else 0.0,
        precision=precision,
        recall=recall,
        f1=f1,
        action_match_rate=action_match / n if n else 0.0,
        latency_p50_ms=_percentile(latencies_ms, 50),
        latency_p95_ms=_percentile(latencies_ms, 95),
        latency_p99_ms=_percentile(latencies_ms, 99),
        n=n,
    )
