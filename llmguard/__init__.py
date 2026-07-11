"""LLMGuard - Enterprise LLM Firewall SDK.

Use LLMGuard as a library to scan and redact sensitive data before sending
to LLMs. Works standalone (no proxy required) or as a LiteLLM callback.

Quick Start:
    from llmguard import scan, redact, is_safe

    # Check if text contains sensitive data
    result = scan("My SSN is 123-45-6789")
    if not result.is_safe:
        print(f"Blocked: {result.categories}")

    # Redact and get safe text
    safe = redact("Email me at john@corp.com")
    print(safe.text)  # "Email me at [EMAIL_1]"

    # De-tokenize LLM response
    restored = safe.restore("Contact [EMAIL_1] for details")
    print(restored)  # "Contact john@corp.com for details"

LiteLLM Integration:
    import litellm
    from llmguard import LLMGuardCallback

    litellm.callbacks = [LLMGuardCallback()]
    # All LLM calls are now automatically scanned
"""

from __future__ import annotations

from llmguard.callback import LLMGuardCallback
from llmguard.sdk import RedactResult, ScanResult, is_safe, redact, scan

__all__ = [
    "scan",
    "redact",
    "is_safe",
    "ScanResult",
    "RedactResult",
    "LLMGuardCallback",
]
