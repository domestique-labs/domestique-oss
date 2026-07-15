"""Unit tests — Secret detector.

Validates all critical patterns and ensures no false positives on common
text. Tests run in < 50 ms total since the detector is pure regex.
"""

from __future__ import annotations

import pytest

from domestique.detectors.secrets import SecretDetector


@pytest.fixture
def detector() -> SecretDetector:
    return SecretDetector()


# ── True Positives ───────────────────────────────────────────────────────────


class TestTruePositives:
    """Each pattern must trigger on known-good samples."""

    @pytest.mark.parametrize(
        "text,expected_category",
        [
            ("AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
            ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret_key"),
            ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "github_token"),
            ("github_pat_11ABCDEFGHIJKLMNOPQRST_UVWXYZ", "github_fine_grained"),
            ("sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdef", "openai_key"),
            ("sk-ant-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJ", "anthropic_key"),
            ("xoxb-1234567890123-ABCDEFGHIJKLMNOPQrstuvwx", "slack_token"),
            ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
            ("-----BEGIN PRIVATE KEY-----", "private_key"),
            ("postgresql://admin:secret@db.internal:5432/prod", "connection_string"),
            ("mongodb://root:pass@cluster0.abc.mongodb.net/db", "connection_string"),
            ("redis://default:mypass@cache.internal:6379/0", "connection_string"),
            (
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                "jwt",
            ),
            ('api_key = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZab"', "generic_api_key"),
            ('password = "Super$ecret123!@#"', "password_literal"),
        ],
    )
    async def test_detects_known_secret(
        self, detector: SecretDetector, text: str, expected_category: str
    ) -> None:
        findings = await detector.scan(text)
        categories = [f.category for f in findings]
        assert expected_category in categories, f"Expected {expected_category} in {categories}"

    async def test_multiple_secrets_in_one_text(self, detector: SecretDetector) -> None:
        text = 'AKIAIOSFODNN7EXAMPLE\npassword = "hunter2hunter2"'
        findings = await detector.scan(text)
        assert len(findings) >= 2


# ── True Negatives ───────────────────────────────────────────────────────────


class TestTrueNegatives:
    """Common clean text must not trigger high-confidence detections."""

    @pytest.mark.parametrize(
        "text",
        [
            "Please help me write a sorting algorithm in Python.",
            "The capital of France is Paris.",
            "def fibonacci(n): return n if n < 2 else fibonacci(n-1) + fibonacci(n-2)",
            "SELECT * FROM users WHERE id = 42;",
            "https://github.com/company/repo/issues/123",
            "The meeting is at 3pm on Monday.",
        ],
    )
    async def test_no_detection_on_clean_text(
        self, detector: SecretDetector, text: str
    ) -> None:
        findings = await detector.scan(text)
        high_confidence = [f for f in findings if f.confidence >= 0.85]
        assert high_confidence == []


# ── Edge Cases ───────────────────────────────────────────────────────────────


class TestEdgeCases:
    async def test_empty_string(self, detector: SecretDetector) -> None:
        assert await detector.scan("") == []

    async def test_span_offsets_are_correct(self, detector: SecretDetector) -> None:
        prefix = "here is my key: "
        secret = "AKIAIOSFODNN7EXAMPLE"
        text = prefix + secret
        findings = await detector.scan(text)
        assert len(findings) >= 1
        f = next(f for f in findings if f.category == "aws_access_key")
        assert text[f.span.start : f.span.end] == secret

    async def test_detector_name_is_set(self, detector: SecretDetector) -> None:
        findings = await detector.scan("AKIAIOSFODNN7EXAMPLE")
        assert all(f.detector == "secret_scanner" for f in findings)
