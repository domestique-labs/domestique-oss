"""Unit tests — Policy engine.

Validates rule matching, priority logic, and short-circuit behavior.
"""

from __future__ import annotations

import pytest

from llmguard.models import Action, Detection, Span
from llmguard.policy import PolicyEngine, Rule


def _det(
    detector: str = "secret_scanner",
    category: str = "aws_access_key",
    confidence: float = 0.95,
) -> Detection:
    return Detection(
        detector=detector,
        category=category,
        confidence=confidence,
        span=Span(0, 20),
        field_path="messages.0.content",
    )


@pytest.fixture
def engine() -> PolicyEngine:
    """Engine with production-like rules."""
    return PolicyEngine.from_yaml("src/llmguard/policy/rules.yaml")


class TestPolicyEvaluation:
    def test_blocks_critical_secret(self, engine: PolicyEngine) -> None:
        assert engine.evaluate([_det(category="private_key")]) is Action.BLOCK

    def test_blocks_aws_key(self, engine: PolicyEngine) -> None:
        assert engine.evaluate([_det(category="aws_access_key")]) is Action.BLOCK

    def test_blocks_github_token(self, engine: PolicyEngine) -> None:
        assert engine.evaluate([_det(category="github_token")]) is Action.BLOCK

    def test_blocks_password(self, engine: PolicyEngine) -> None:
        assert engine.evaluate([_det(category="password_literal", confidence=0.87)]) is Action.BLOCK

    def test_redacts_ssn(self, engine: PolicyEngine) -> None:
        det = _det(detector="pii_detector", category="us_ssn", confidence=0.85)
        assert engine.evaluate([det]) is Action.REDACT

    def test_redacts_email(self, engine: PolicyEngine) -> None:
        det = _det(detector="pii_detector", category="email_address", confidence=0.9)
        assert engine.evaluate([det]) is Action.REDACT

    def test_allows_when_no_detections(self, engine: PolicyEngine) -> None:
        assert engine.evaluate([]) is Action.ALLOW

    def test_allows_below_confidence_threshold(self, engine: PolicyEngine) -> None:
        det = _det(category="aws_access_key", confidence=0.3)
        assert engine.evaluate([det]) is Action.ALLOW

    def test_block_wins_over_redact(self, engine: PolicyEngine) -> None:
        """When both block and redact rules match, block takes priority."""
        detections = [
            _det(detector="pii_detector", category="email_address", confidence=0.9),
            _det(detector="secret_scanner", category="private_key", confidence=0.99),
        ]
        assert engine.evaluate(detections) is Action.BLOCK


class TestPolicyExplain:
    def test_returns_reason_on_block(self, engine: PolicyEngine) -> None:
        action, reason = engine.explain([_det(category="private_key")])
        assert action is Action.BLOCK
        assert "private_key" in reason

    def test_returns_no_findings_message(self, engine: PolicyEngine) -> None:
        action, reason = engine.explain([])
        assert action is Action.ALLOW
        assert "no findings" in reason


class TestCustomRules:
    def test_wildcard_detector(self) -> None:
        engine = PolicyEngine(rules=[Rule(name="block-all", detector="*", action=Action.BLOCK)])
        det = _det(detector="any_detector", category="anything", confidence=0.5)
        assert engine.evaluate([det]) is Action.BLOCK

    def test_category_filter(self) -> None:
        engine = PolicyEngine(rules=[
            Rule(name="only-emails", detector="pii_detector", action=Action.REDACT, categories=["email_address"]),
        ])
        # Phone should not match.
        assert engine.evaluate([_det(detector="pii_detector", category="phone_number")]) is Action.ALLOW
        # Email should match.
        assert engine.evaluate([_det(detector="pii_detector", category="email_address")]) is Action.REDACT
