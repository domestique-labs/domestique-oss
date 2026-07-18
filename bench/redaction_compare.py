"""Render a base-vs-head redaction metrics comparison as markdown.

Used by the redaction-metrics CI workflow: both scoreboards come from
``redaction_bench.py --json`` runs **on the same runner** (absolute
latency on shared runners is noise; same-runner deltas are signal —
the same lesson the eval workflow learned in PR #25).

Usage: python bench/redaction_compare.py base.json head.json
       (base.json may be absent — e.g. the engine didn't exist at the
       merge-base — which is reported explicitly.)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

#: Relative changes inside this band are runner jitter, not signal.
NOISE_BAND_PCT = 2.0

_LATENCY_ROWS = [
    ("redact 1KB p50", ("M6", "p50_ms"), "ms"),
    ("redact 1KB p95", ("M6", "p95_ms"), "ms"),
    ("detokenize 4KB p50", ("M7", "p50_ms"), "ms"),
    ("stream/chunk p95", ("M8", "p95_ms"), "ms"),
    ("vault load 1k", ("M9", "load_1k_ms"), "ms"),
]

_TOKEN_ROWS = [
    ("avg marker chars", ("token_usage", "avg_chars"), ""),
    ("total marker chars (corpus)", ("token_usage", "total_chars"), ""),
    ("marker count (corpus)", ("token_usage", "markers"), ""),
]


def _get(scoreboard: dict[str, Any], path: tuple[str, str]) -> float | None:
    section = scoreboard.get(path[0])
    if not isinstance(section, dict):
        return None
    value = section.get(path[1])
    return float(value) if isinstance(value, (int, float)) else None


def _fmt(value: float) -> str:
    """Human-stable number: keeps one decimal for ordinary magnitudes
    (``9.0`` stays ``9.0``) and enough precision for sub-ms latencies."""
    if value >= 100:
        return f"{value:.0f}"
    if value >= 1:
        return f"{value:.1f}"
    trimmed = f"{value:.4f}".rstrip("0").rstrip(".")
    return trimmed or "0"


def _delta_cell(base: float | None, head: float | None) -> str:
    if base is None or head is None:
        return "—"
    if base == 0:
        return "n/a"
    pct = (head - base) / base * 100
    if abs(pct) <= NOISE_BAND_PCT:
        return f"≈ ({pct:+.1f}%)"
    arrow = "🔺" if pct > 0 else "🔽"
    return f"{arrow} {pct:+.1f}%"


def _table(
    title: str,
    rows: list[tuple[str, tuple[str, str], str]],
    base: dict[str, Any] | None,
    head: dict[str, Any],
) -> str:
    lines = [f"**{title}**", "", "| metric | base | head | Δ |", "|---|---|---|---|"]
    for label, path, unit in rows:
        b = _get(base, path) if base is not None else None
        h = _get(head, path)
        b_txt = f"{_fmt(b)}{unit}" if b is not None else "—"
        h_txt = f"{_fmt(h)}{unit}" if h is not None else "—"
        lines.append(f"| {label} | {b_txt} | {h_txt} | {_delta_cell(b, h)} |")
    return "\n".join(lines)


def compare(base: dict[str, Any] | None, head: dict[str, Any]) -> str:
    """Markdown report of token-usage and latency deltas between scoreboards."""
    parts: list[str] = []
    if base is None:
        parts.append(
            "_No baseline: the redaction engine (or its bench) does not exist "
            "at the merge-base — head numbers shown without deltas._"
        )
        parts.append("")
    parts.append(_table("Token usage (deterministic)", _TOKEN_ROWS, base, head))
    parts.append("")
    parts.append(
        _table("Latency (same-runner compare; ±"
               f"{NOISE_BAND_PCT:g}% is jitter)", _LATENCY_ROWS, base, head)
    )
    return "\n".join(parts)


def main() -> int:
    # cp1252 consoles (Windows) can't print Δ/🔺; CI is UTF-8 already.
    import contextlib

    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    base_path, head_path = Path(sys.argv[1]), Path(sys.argv[2])
    base = json.loads(base_path.read_text()) if base_path.exists() else None
    head = json.loads(head_path.read_text())
    print(compare(base, head))
    return 0


if __name__ == "__main__":
    sys.exit(main())
