from pathlib import Path

from domestique.models import Action, Detection, Span
from domestique.policy import PolicyEngine

_CLI = Path("domestique/policy/cli-rules.yaml")


def _det(detector, category, conf):
    return Detection(detector=detector, category=category, confidence=conf, span=Span(0, 5))


def test_llm_coined_term_redacts():
    engine = PolicyEngine.from_yaml(_CLI)
    action = engine.evaluate([_det("local_llm_classifier", "employee_badge", 0.9)])
    assert action is Action.REDACT


def test_llm_below_threshold_allows():
    engine = PolicyEngine.from_yaml(_CLI)
    action = engine.evaluate([_det("local_llm_classifier", "employee_badge", 0.5)])
    assert action is Action.ALLOW


def test_canonical_pii_still_redacts():
    engine = PolicyEngine.from_yaml(_CLI)
    action = engine.evaluate([_det("gliner_ner", "email_address", 0.9)])
    assert action is Action.REDACT
