"""LLM Firewall - Transport layer (upstream LLM forwarding).

Encapsulates all communication with external LLM providers behind a simple
async interface. Uses LiteLLM for multi-provider compatibility with a
persistent httpx connection pool for minimal overhead.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import litellm
import structlog

if TYPE_CHECKING:
    from llmguard.config import Settings

logger = structlog.get_logger()

# Suppress LiteLLM's verbose logging in production.
litellm.suppress_debug_info = True


class LLMProxy:
    """Forwards sanitized requests to upstream LLM providers.

    Holds no mutable state beyond the settings reference. LiteLLM manages
    its own connection pool internally.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._configure_keys(settings)

    async def forward(self, body: dict[str, Any]) -> dict[str, Any]:
        """Forward a chat-completion request and return the provider response.

        Raises on timeout or upstream error; callers should handle based on
        the configured fail-mode.
        """
        response = await litellm.acompletion(
            **body,
            timeout=self._settings.upstream_timeout_s,
        )
        return response.model_dump()  # type: ignore[union-attr]

    @staticmethod
    def _configure_keys(settings: Settings) -> None:
        """Inject API keys into LiteLLM's environment once at startup."""
        import os

        if settings.openai_api_key:
            os.environ.setdefault("OPENAI_API_KEY", settings.openai_api_key)
        if settings.anthropic_api_key:
            os.environ.setdefault("ANTHROPIC_API_KEY", settings.anthropic_api_key)
        if settings.azure_api_key:
            os.environ.setdefault("AZURE_API_KEY", settings.azure_api_key)
        if settings.azure_api_base:
            os.environ.setdefault("AZURE_API_BASE", settings.azure_api_base)
