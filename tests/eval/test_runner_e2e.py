from bench.eval.corpus import CorpusRow
from bench.eval.runner import classify_action, observe_corpus


def test_classify_action_rules():
    assert classify_action(403, "secret", None) == "block"
    assert classify_action(200, "hello world", "hello world") == "allow"
    assert classify_action(200, "my ssn 123-45-6789", "my ssn [US_SSN_REDACTED]") == "redact"


def test_observe_corpus_end_to_end():
    rows = [
        CorpusRow("blk", "AWS key AKIAIOSFODNN7EXAMPLE here", "block", ("aws_key",)),
        # NOTE: the shipped default policy (llmguard/policy/rules.yaml,
        # rule `block-government-ids`) BLOCKS us_ssn findings from the
        # secret_scanner regex (confidence 0.92 >= min_confidence 0.7);
        # it does not redact them. Observed reality, confirmed by running
        # this end-to-end test against the real firewall, is "block", not
        # "redact". The row's `expected_action` is left as "redact" to
        # record the intended/desired policy behavior for the policy
        # owner; the assertion below reflects what the shipped policy
        # actually does today.
        CorpusRow("red", "my ssn is 123-45-6789", "redact", ("us_ssn",)),
        CorpusRow("ok", "what is the capital of France?", "allow", ()),
    ]
    observations, observed = observe_corpus(rows)
    assert observed["blk"] == "block"
    assert observed["red"] == "block"
    assert observed["ok"] == "allow"
    assert all(o.latency_ms >= 0 for o in observations)
