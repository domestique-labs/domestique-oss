"""Compare-script logic for the per-PR redaction metrics report."""

from __future__ import annotations

from benchmarks.redaction_compare import compare

HEAD = {
    "M6": {"p50_ms": 0.30, "p95_ms": 0.45},
    "M7": {"p50_ms": 0.015, "p95_ms": 0.03},
    "M8": {"p95_ms": 0.002, "max_held_chars": 4.0},
    "M9": {"load_1k_ms": 20.0, "pin_write_ms": 3.0},
    "token_usage": {"markers": 24, "total_chars": 216, "avg_chars": 9.0},
    "pass": True,
    "checks": {},
}


def _base(**overrides: object) -> dict:
    base = {
        "M6": {"p50_ms": 0.20, "p95_ms": 0.50},
        "M7": {"p50_ms": 0.015, "p95_ms": 0.03},
        "M8": {"p95_ms": 0.002, "max_held_chars": 4.0},
        "M9": {"load_1k_ms": 25.0, "pin_write_ms": 3.0},
        "token_usage": {"markers": 24, "total_chars": 432, "avg_chars": 18.0},
        "pass": True,
        "checks": {},
    }
    base.update(overrides)
    return base


class TestCompare:
    def test_reports_signed_percentages(self) -> None:
        md = compare(_base(), HEAD)
        # latency p50 went 0.20 -> 0.30 = +50%
        assert "+50.0%" in md
        # token avg went 18 -> 9 = -50%
        assert "-50.0%" in md

    def test_small_changes_marked_as_noise(self) -> None:
        md = compare(_base(), HEAD)
        # M7 p50 unchanged -> within noise band
        assert "≈" in md or "~" in md

    def test_missing_baseline_is_explicit(self) -> None:
        md = compare(None, HEAD)
        assert "no baseline" in md.lower()
        assert "9.0" in md  # head numbers still shown

    def test_contains_token_usage_and_latency_sections(self) -> None:
        md = compare(_base(), HEAD)
        assert "Token usage" in md
        assert "Latency" in md
