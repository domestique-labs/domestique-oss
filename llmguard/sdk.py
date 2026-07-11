"""LLMGuard SDK - public API for scanning and redacting sensitive data.

This module provides the simple, user-facing functions for integrating
LLMGuard into any Python application without running the full proxy.

Functions:
    scan(text) -> ScanResult       Check text for sensitive data
    redact(text) -> RedactResult   Replace sensitive data with tokens
    is_safe(text) -> bool          Quick boolean check

All functions are thread-safe and can be called from any context.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.services.redaction import (
    RedactionAction,
    RedactionEngine,
)


@dataclass(frozen=True)
class ScanResult:
    """Result of scanning text for sensitive data.

    Attributes:
        is_safe: True if no sensitive data was found.
        categories: List of PII categories detected.
        findings: Detailed findings with positions.
        count: Number of sensitive items found.
    """

    is_safe: bool
    categories: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    count: int = 0


@dataclass
class RedactResult:
    """Result of redacting sensitive data from text.

    Attributes:
        text: The redacted text with tokens replacing sensitive data.
        original: The original input text.
        is_safe: True if no redaction was needed.
        categories: Categories of data that were redacted.
        token_count: Number of tokens generated.
    """

    text: str
    original: str
    is_safe: bool
    categories: list[str] = field(default_factory=list)
    token_count: int = 0
    _engine: RedactionEngine | None = field(default=None, repr=False)

    def restore(self, llm_response: str) -> str:
        """De-tokenize an LLM response back to original values.

        Args:
            llm_response: The LLM's response containing tokens like [SSN_1].

        Returns:
            Text with tokens replaced by the original sensitive values.
        """
        if self._engine:
            return self._engine.detokenize(llm_response)
        return llm_response


# Module-level engine (thread-safe, reusable)
_default_engine: RedactionEngine | None = None


def _get_engine() -> RedactionEngine:
    """Get or create the default redaction engine."""
    global _default_engine
    if _default_engine is None:
        _default_engine = RedactionEngine()
    return _default_engine


def scan(text: str) -> ScanResult:
    """Scan text for sensitive data without modifying it.

    This is a non-destructive check. Use `redact()` if you want to
    actually replace sensitive values with tokens.

    Args:
        text: The text to scan.

    Returns:
        ScanResult with detection details.

    Example:
        result = scan("My SSN is 123-45-6789")
        if not result.is_safe:
            print(f"Found: {result.categories}")
    """
    if not text:
        return ScanResult(is_safe=True)

    engine = _get_engine()
    result = engine.redact(text)

    if result.action == RedactionAction.ALLOW:
        return ScanResult(is_safe=True)

    findings = [
        {
            "category": f.category,
            "value": f.value,
            "start": f.start,
            "end": f.end,
        }
        for f in result.findings
    ]

    return ScanResult(
        is_safe=False,
        categories=result.categories_found,
        findings=findings,
        count=len(result.findings),
    )


def redact(text: str) -> RedactResult:
    """Scan and redact sensitive data, replacing with reversible tokens.

    The returned `RedactResult` can later de-tokenize LLM responses
    via the `.restore()` method.

    Args:
        text: The text to redact.

    Returns:
        RedactResult with redacted text and restore capability.

    Example:
        safe = redact("Email john@corp.com about the project")
        # safe.text = "Email [EMAIL_1] about the project"

        llm_response = "[EMAIL_1] should be notified"
        original = safe.restore(llm_response)
        # original = "john@corp.com should be notified"
    """
    if not text:
        return RedactResult(text=text, original=text, is_safe=True)

    # Use a fresh engine per redact call for independent token sessions
    engine = RedactionEngine()
    result = engine.redact(text)

    if result.action == RedactionAction.ALLOW:
        return RedactResult(text=text, original=text, is_safe=True)

    # BLOCK action: text is unmodified but unsafe
    # REDACT action: text has tokens replacing sensitive data
    return RedactResult(
        text=result.redacted_text,
        original=text,
        is_safe=False,
        categories=result.categories_found,
        token_count=result.token_count,
        _engine=engine,
    )


def is_safe(text: str) -> bool:
    """Quick boolean check: does the text contain sensitive data?

    Equivalent to `scan(text).is_safe` but slightly more efficient
    as it short-circuits on first detection.

    Args:
        text: The text to check.

    Returns:
        True if no sensitive data was found.
    """
    return scan(text).is_safe
