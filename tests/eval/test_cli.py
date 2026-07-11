import json
from pathlib import Path

from bench.eval.__main__ import run_eval

DATA = Path("bench/eval/data/corpus.jsonl")


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
