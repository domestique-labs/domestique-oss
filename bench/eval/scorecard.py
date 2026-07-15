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

# Presentation order: correctness/quality first, wall-clock latency last.
_ORDER = [
    "bypass_rate", "false_positive_rate", "precision", "recall", "f1",
    "action_match_rate", "latency_p50_ms", "latency_p95_ms", "latency_p99_ms",
]

_LATENCY_KEYS = {"latency_p50_ms", "latency_p95_ms", "latency_p99_ms"}

# Wall-clock latency on shared CI runners is noisy: even measuring `main` and the
# PR back-to-back on the same runner, run-to-run jitter is easily 10-15%. Any
# relative change below this band is reported as "≈ noise" rather than a verdict,
# so environmental jitter stops masquerading as a real regression/improvement.
_LATENCY_NOISE_FRAC = 0.20


def to_json(metrics: Metrics, *, commit: str, corpus_sha: str, profile: str) -> str:
    return json.dumps(
        {"commit": commit, "corpus_sha": corpus_sha, "profile": profile,
         "metrics": asdict(metrics)},
        sort_keys=True, indent=2,
    )


def _fmt(value: float) -> str:
    return f"{value:.4f}" if isinstance(value, float) else str(value)


def _pct(delta: float, base: float) -> str:
    if base == 0:
        return "—"
    return f"{delta / base * 100:+.1f}%"


def verdict(key: str, main_value: float, pr_value: float) -> str:
    """Verdict for a single metric comparing PR against main.

    Quality metrics on identical code are deterministic, so an exact tie reads
    "=". Latency is non-deterministic, so a change within the noise band reads
    "≈ noise" instead of a false ✅/⚠️.
    """
    delta = pr_value - main_value
    if abs(delta) < 1e-9:
        return "="
    if key in _LATENCY_KEYS:
        denom = abs(main_value) or 1.0
        if abs(delta) / denom < _LATENCY_NOISE_FRAC:
            return "≈ noise"
    improved = (delta < 0) == _LOWER_BETTER[key]
    return "✅ better" if improved else "⚠️ worse"


def to_markdown_single(metrics: Metrics) -> str:
    """Single-run table (no peer to compare against) — used for local runs."""
    cur = asdict(metrics)
    lines = ["### Domestique eval scorecard", "", f"n = {metrics.n}", "",
             "| metric | value |", "| --- | --- |"]
    for key in _ORDER:
        lines.append(f"| {key} | {_fmt(cur[key])} |")
    return "\n".join(lines)


def to_markdown_compare(main: Metrics, pr: Metrics) -> str:
    """Comparison table: main vs PR, both measured on the same runner."""
    m = asdict(main)
    p = asdict(pr)
    lines = [
        "### Domestique eval scorecard", "",
        f"n = {pr.n}", "",
        "_`main` and `PR` are measured on the same runner in the same job, so "
        "the comparison is environment-controlled. Latency changes within "
        f"±{int(_LATENCY_NOISE_FRAC * 100)}% are treated as runner noise._", "",
        "| metric | main | PR | Δ | Δ % | verdict |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for key in _ORDER:
        mv = m[key]
        pv = p[key]
        delta = pv - mv
        lines.append(
            f"| {key} | {_fmt(mv)} | {_fmt(pv)} | {delta:+.4f} | "
            f"{_pct(delta, mv)} | {verdict(key, mv, pv)} |"
        )
    return "\n".join(lines)
