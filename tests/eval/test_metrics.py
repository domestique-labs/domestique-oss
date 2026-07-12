from bench.eval.corpus import CorpusRow
from bench.eval.metrics import compute_metrics


def _rows():
    return [
        CorpusRow("s1", "x", "block"),
        CorpusRow("s2", "x", "redact"),
        CorpusRow("s3", "x", "block"),
        CorpusRow("b1", "x", "allow"),
        CorpusRow("b2", "x", "allow"),
    ]


def test_perfect_scores():
    observed = {"s1": "block", "s2": "redact", "s3": "block", "b1": "allow", "b2": "allow"}
    m = compute_metrics(_rows(), observed, [1.0, 2.0, 3.0, 4.0, 5.0])
    assert m.bypass_rate == 0.0
    assert m.false_positive_rate == 0.0
    assert m.recall == 1.0
    assert m.precision == 1.0
    assert m.f1 == 1.0
    assert m.action_match_rate == 1.0
    assert m.n == 5


def test_one_bypass_one_false_positive():
    # s3 slips through (bypass); b1 wrongly flagged (false positive)
    observed = {"s1": "block", "s2": "redact", "s3": "allow", "b1": "block", "b2": "allow"}
    m = compute_metrics(_rows(), observed, [10.0] * 5)
    assert round(m.bypass_rate, 3) == round(1 / 3, 3)      # 1 of 3 sensitive allowed
    assert m.false_positive_rate == 0.5                     # 1 of 2 benign flagged
    assert round(m.recall, 3) == round(2 / 3, 3)           # TP=2, FN=1
    assert round(m.precision, 3) == round(2 / 3, 3)        # TP=2, FP=1


def test_latency_percentiles():
    observed = {r.id: "allow" for r in _rows()}
    m = compute_metrics(_rows(), observed, [1, 2, 3, 4, 100])
    assert m.latency_p50_ms == 3
    assert m.latency_p99_ms == 100
