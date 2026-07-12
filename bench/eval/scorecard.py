from __future__ import annotations

import json
from dataclasses import asdict

from bench.eval.metrics import Metrics

# For each metric: True if a LOWER value is better.
_LOWER_BETTER = {
    "bypass_rate": True, "false_positive_rate": True,
    "precision": False, "recall": False, "f1": False, "action_match_rate": False,
    "latency_p50_ms": True, "latency_p95_ms": True, "latency_p99_ms": True,
}


def to_json(metrics: Metrics, *, commit: str, corpus_sha: str, profile: str) -> str:
    return json.dumps(
        {"commit": commit, "corpus_sha": corpus_sha, "profile": profile,
         "metrics": asdict(metrics)},
        sort_keys=True, indent=2,
    )


def _fmt(value: float) -> str:
    return f"{value:.4f}" if isinstance(value, float) else str(value)


def to_markdown(current: Metrics, baseline: Metrics | None) -> str:
    cur = asdict(current)
    base = asdict(baseline) if baseline else None
    lines = ["### LLMGuard eval scorecard", "", f"n = {current.n}", ""]
    if base is None:
        lines += ["| metric | value |", "| --- | --- |"]
        for key, val in cur.items():
            if key == "n":
                continue
            lines.append(f"| {key} | {_fmt(val)} |")
    else:
        lines += ["| metric | main | PR | Δ | verdict |", "| --- | --- | --- | --- | --- |"]
        for key, val in cur.items():
            if key == "n":
                continue
            b = base[key]
            delta = val - b
            if abs(delta) < 1e-9:
                verdict = "="
            else:
                improved = (delta < 0) == _LOWER_BETTER[key]
                verdict = "✅ better" if improved else "⚠️ worse"
            lines.append(f"| {key} | {_fmt(b)} | {_fmt(val)} | {delta:+.4f} | {verdict} |")
    return "\n".join(lines)
