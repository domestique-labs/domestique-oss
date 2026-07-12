import json

from bench.eval.metrics import Metrics
from bench.eval.scorecard import to_json, to_markdown


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


def test_markdown_shows_delta_direction():
    current = _m(bypass_rate=0.05)      # improved (lower)
    baseline = _m(bypass_rate=0.10)
    md = to_markdown(current, baseline)
    assert "bypass_rate" in md
    assert "better" in md               # lower bypass is better


def test_markdown_without_baseline():
    md = to_markdown(_m(), None)
    assert "bypass_rate" in md
    assert "n = 15" in md
