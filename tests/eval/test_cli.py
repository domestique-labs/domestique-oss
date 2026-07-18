import json
from pathlib import Path

from benchmarks.eval.__main__ import compare, regressions, run_eval
from benchmarks.eval.metrics import Metrics

DATA = Path("benchmarks/eval/data/corpus.jsonl")


def _m(**kw):
    base = dict(bypass_rate=0.1, false_positive_rate=0.0, precision=1.0, recall=0.9,
               f1=0.95, action_match_rate=0.9, latency_p50_ms=1.0, latency_p95_ms=2.0,
               latency_p99_ms=3.0, n=15)
    base.update(kw)
    return Metrics(**base)


def _write(path, metrics):
    path.write_text(
        json.dumps({"commit": "x", "corpus_sha": "y", "profile": "core",
                    "metrics": metrics.__dict__}),
        encoding="utf-8",
    )


def test_run_eval_writes_results(tmp_path):
    out = tmp_path / "results.json"
    code = run_eval(DATA, out, baseline_path=None, commit="testsha", fail_on_regression=False)
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["commit"] == "testsha"
    assert "bypass_rate" in data["metrics"]
    assert data["metrics"]["n"] >= 12


def test_fail_on_regression_trips(tmp_path):
    good = tmp_path / "base.json"
    run_eval(DATA, good, baseline_path=None, commit="base", fail_on_regression=False)
    # Corrupt the baseline to a perfect score so current looks like a regression.
    payload = json.loads(good.read_text(encoding="utf-8"))
    payload["metrics"]["bypass_rate"] = 0.0
    payload["metrics"]["false_positive_rate"] = 0.0
    good.write_text(json.dumps(payload), encoding="utf-8")
    out = tmp_path / "cur.json"
    code = run_eval(DATA, out, baseline_path=good, commit="cur", fail_on_regression=True)
    # If the current corpus has any bypass at all, this must trip.
    cur = json.loads(out.read_text(encoding="utf-8"))
    expected = 1 if cur["metrics"]["bypass_rate"] > 0.001 else 0
    assert code == expected


def test_regressions_flags_quality_drops_not_latency():
    main = _m(bypass_rate=0.10, recall=0.90, f1=0.95, latency_p95_ms=5.0)
    # Latency 8x worse but quality identical → no hard regression.
    slow = _m(bypass_rate=0.10, recall=0.90, f1=0.95, latency_p95_ms=40.0)
    assert regressions(main, slow) == []

    worse = _m(bypass_rate=0.30, recall=0.70, f1=0.80)
    msgs = regressions(main, worse)
    assert any("bypass_rate" in m for m in msgs)
    assert any("recall" in m for m in msgs)


def test_compare_gate_exit_codes(tmp_path):
    main = tmp_path / "main.json"
    pr = tmp_path / "pr.json"
    _write(main, _m(bypass_rate=0.10, recall=0.90))

    _write(pr, _m(bypass_rate=0.10, recall=0.90, latency_p50_ms=99.0))
    assert compare(main, pr, fail_on_regression=True) == 0        # latency-only → pass

    _write(pr, _m(bypass_rate=0.40, recall=0.60))
    assert compare(main, pr, fail_on_regression=True) == 1        # quality drop → fail
    assert compare(main, pr, fail_on_regression=False) == 0       # gate off → report only
