import json

from bench.eval.metrics import Metrics
from bench.eval.scorecard import (
    to_json,
    to_markdown_compare,
    to_markdown_single,
    verdict,
)


def _m(**kw):
    base = dict(bypass_rate=0.1, false_positive_rate=0.0, precision=1.0, recall=0.9,
               f1=0.95, action_match_rate=0.9, latency_p50_ms=1.0, latency_p95_ms=2.0,
               latency_p99_ms=3.0, n=15)
    base.update(kw)
    return Metrics(**base)


def test_to_json_roundtrips_and_includes_meta():
    payload = to_json(_m(), commit="abc123", corpus_sha="deadbeef", profile="core")
    data = json.loads(payload)
    assert data["commit"] == "abc123"
    assert data["corpus_sha"] == "deadbeef"
    assert data["profile"] == "core"
    assert data["metrics"]["bypass_rate"] == 0.1


def test_single_table_lists_all_metrics():
    md = to_markdown_single(_m())
    assert "n = 15" in md
    assert "bypass_rate" in md
    assert "latency_p99_ms" in md


def test_compare_shows_delta_direction_and_percent():
    main = _m(bypass_rate=0.10)
    pr = _m(bypass_rate=0.05)          # lower bypass is better
    md = to_markdown_compare(main, pr)
    assert "bypass_rate" in md
    assert "better" in md
    assert "-50.0%" in md              # (0.05 - 0.10) / 0.10


def test_quality_regression_reads_worse():
    # recall dropped: higher-is-better metric moving down → worse
    assert verdict("recall", 0.90, 0.80) == "⚠️ worse"
    assert verdict("recall", 0.80, 0.90) == "✅ better"


def test_identical_quality_metric_is_tie():
    assert verdict("bypass_rate", 0.2727, 0.2727) == "="


def test_latency_within_band_is_noise_not_a_verdict():
    # A docs-only PR: latency wobbles by a few percent → must NOT read "better".
    assert verdict("latency_p50_ms", 22.68, 21.0) == "≈ noise"    # ~7% drop
    assert verdict("latency_p50_ms", 22.68, 24.0) == "≈ noise"    # ~6% rise


def test_latency_beyond_band_still_reported():
    # A real 10x speedup is outside the noise band and reads as better.
    assert verdict("latency_p50_ms", 22.68, 3.0) == "✅ better"
    assert verdict("latency_p95_ms", 5.0, 40.0) == "⚠️ worse"
