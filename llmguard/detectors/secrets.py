"""LLM Firewall - Secret / credential detector.

Uses compiled regex patterns derived from industry-standard rulesets
(trufflehog, gitleaks). All patterns are evaluated in a single pass using
a combined alternation regex for O(n) scanning regardless of pattern count.

Latency target: < 1 ms for typical LLM messages (< 4 KB).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

from llmguard.models import Detection, Span

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True)
class _Pattern:
    """A named regex pattern with an associated confidence score."""

    name: str
    regex: str
    confidence: float


# Ordered from highest to lowest confidence.
_PATTERNS: list[_Pattern] = [
    _Pattern("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 0.99),
    _Pattern("aws_access_key", r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])", 0.99),
    _Pattern(
        "aws_secret_key",
        r"[Aa][Ww][Ss][_\s]*[Ss][Ee][Cc][Rr][Ee][Tt][_\s]*"
        r"[Aa][Cc][Cc][Ee][Ss][Ss][_\s]*[Kk][Ee][Yy]\s*[=:]\s*[A-Za-z0-9/+=]{40}",
        0.98,
    ),
    _Pattern(
        "connection_string",
        r"(?:mongodb|postgres(?:ql)?|mysql|redis|amqp|MongoDB|Postgres(?:ql)?"
        r"|MySQL|Redis|AMQP)://[^\s'\"]{10,}",
        0.97,
    ),
    _Pattern("github_token", r"gh[ps]_[A-Za-z0-9_]{36,}", 0.96),
    _Pattern("github_fine_grained", r"github_pat_[A-Za-z0-9_]{22,}", 0.96),
    _Pattern("anthropic_key", r"sk-ant-[A-Za-z0-9_-]{40,}", 0.95),
    _Pattern("openai_key", r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}", 0.95),
    _Pattern("slack_token", r"xox[baprs]-[0-9]{10,13}-[A-Za-z0-9-]{20,}", 0.94),
    _Pattern("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", 0.92),
    _Pattern(
        "generic_api_key",
        r"[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?",
        0.88,
    ),
    _Pattern(
        "password_literal",
        r"[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        0.87,
    ),
    # PII patterns
    _Pattern("us_ssn", r"\b\d{3}[- .]?\d{2}[- .]?\d{4}\b", 0.92),
    _Pattern(
        "credit_card",
        r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))"
        r"[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b",
        0.93,
    ),
    _Pattern("email_address", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 0.80),
    _Pattern("phone_number", r"\b(?:\+1[- ]?)?\(?[0-9]{3}\)?[- .]?[0-9]{3}[- .]?[0-9]{4}\b", 0.75),
]


class SecretDetector:
    """Fast regex-based credential and secret scanner.

    The combined regex is compiled once at construction. Scanning is purely
    CPU-bound and completes in microseconds for typical payloads.
    """

    _combined_re: ClassVar[re.Pattern[str] | None] = None
    _pattern_map: ClassVar[dict[str, _Pattern]] = {}

    def __init__(self, disabled_patterns: Sequence[str] = ()) -> None:
        self._disabled = set(disabled_patterns)
        if SecretDetector._combined_re is None:
            parts: list[str] = []
            for p in _PATTERNS:
                group_name = p.name
                parts.append(f"(?P<{group_name}>{p.regex})")
                SecretDetector._pattern_map[group_name] = p
            SecretDetector._combined_re = re.compile("|".join(parts))

    @property
    def name(self) -> str:
        return "secret_scanner"

    async def scan(self, text: str) -> list[Detection]:
        """Scan text for credentials. O(n) in text length."""
        if not text:
            return []

        findings: list[Detection] = []
        assert self._combined_re is not None  # noqa: S101

        for match in self._combined_re.finditer(text):
            group_name = match.lastgroup
            if group_name is None or group_name in self._disabled:
                continue
            pattern = self._pattern_map[group_name]
            findings.append(
                Detection(
                    detector=self.name,
                    category=pattern.name,
                    confidence=pattern.confidence,
                    span=Span(start=match.start(), end=match.end()),
                )
            )

        return findings
