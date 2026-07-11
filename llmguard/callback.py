"""LiteLLM callback integration for LLMGuard.

Provides a drop-in callback that automatically scans all LLM requests
and responses for sensitive data when using LiteLLM.

Usage:
    import litellm
    from llmguard import LLMGuardCallback

    litellm.callbacks = [LLMGuardCallback()]

    # Now all LLM calls are automatically protected:
    response = litellm.completion(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Analyze SSN 123-45-6789"}]
    )
    # ^ This will be blocked or redacted depending on policy

Configuration:
    callback = LLMGuardCallback(
        mode="redact",          # "block" or "redact" (default: "block")
        scan_responses=True,    # Also scan LLM responses
        on_block=my_handler,    # Custom handler for blocked requests
    )
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from app.services.redaction import RedactionAction, RedactionEngine

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger("llmguard.callback")


class LLMGuardCallback:
    """LiteLLM callback that scans requests/responses for sensitive data.

    Can operate in two modes:
    - "block": Raises an exception when sensitive data is detected
    - "redact": Replaces sensitive data with tokens and continues

    Thread-safe: uses a per-request RedactionEngine instance.
    """

    def __init__(
        self,
        mode: str = "block",
        scan_responses: bool = True,
        on_block: Callable[[str, list[str]], None] | None = None,
        on_redact: Callable[[str, str, list[str]], None] | None = None,
    ) -> None:
        """Initialize the callback.

        Args:
            mode: "block" to reject, "redact" to sanitize and forward.
            scan_responses: Whether to also scan LLM responses.
            on_block: Optional handler called when content is blocked.
                      Receives (original_text, categories).
            on_redact: Optional handler called when content is redacted.
                       Receives (original, redacted, categories).
        """
        self._mode = mode
        self._scan_responses = scan_responses
        self._on_block = on_block
        self._on_redact = on_redact

    def log_pre_api_call(
        self,
        model: str,
        messages: list[dict[str, Any]],
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Called before each LLM API call. Scans message content.

        This is the LiteLLM callback interface method.
        """
        engine = RedactionEngine()
        modified = False

        for msg in messages:
            if msg.get("role") != "user":
                continue
            content = msg.get("content", "")
            if not isinstance(content, str) or not content:
                continue

            result = engine.redact(content)

            if result.action == RedactionAction.BLOCK:
                categories = result.categories_found
                if self._mode == "block":
                    if self._on_block:
                        self._on_block(content, categories)
                    raise LLMGuardBlockedError(
                        f"LLMGuard blocked request: sensitive data detected "
                        f"({', '.join(categories)})"
                    )
                # In redact mode, force redaction even for BLOCK-category items
                # Re-run with all rules set to REDACT
                from app.services.redaction import RedactionRule

                redact_rules = [
                    RedactionRule(cat, RedactionAction.REDACT)
                    for cat in set(f.category for f in result.findings)
                ]
                redact_engine = RedactionEngine(rules=redact_rules)
                redact_result = redact_engine.redact(content)
                msg["content"] = redact_result.redacted_text
                modified = True

            elif result.action == RedactionAction.REDACT:
                msg["content"] = result.redacted_text
                modified = True
                if self._on_redact:
                    self._on_redact(content, result.redacted_text, result.categories_found)

        if modified:
            logger.info(f"LLMGuard: redacted content in request to {model}")

        return kwargs

    def log_success_event(
        self,
        kwargs: dict[str, Any],
        response_obj: Any,
        start_time: float,
        end_time: float,
    ) -> None:
        """Called after successful LLM response. Scans for leaked data."""
        if not self._scan_responses:
            return

        try:
            # Extract response text (LiteLLM response format)
            content = ""
            if hasattr(response_obj, "choices"):
                for choice in response_obj.choices:
                    if hasattr(choice, "message") and choice.message:
                        content += choice.message.content or ""

            if not content:
                return

            engine = RedactionEngine()
            result = engine.redact(content)

            if result.action in (RedactionAction.BLOCK, RedactionAction.REDACT):
                logger.warning(
                    f"LLMGuard RESPONSE ALERT: sensitive data in LLM response "
                    f"({', '.join(result.categories_found)})"
                )
        except Exception as e:
            logger.debug(f"Response scan error: {e}")

    def log_failure_event(
        self, kwargs: dict[str, Any], response_obj: Any, start_time: float, end_time: float
    ) -> None:
        """Called on API failure. No-op for LLMGuard."""
        pass


class LLMGuardBlockedError(Exception):
    """Raised when LLMGuard blocks a request due to sensitive data."""

    def __init__(self, message: str, categories: list[str] | None = None) -> None:
        super().__init__(message)
        self.categories = categories or []
