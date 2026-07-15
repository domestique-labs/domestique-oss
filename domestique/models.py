"""LLM Firewall - Domain models.

Shared value objects used across detection, policy, and audit boundaries.
These are intentionally plain dataclasses for zero-overhead construction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Action(StrEnum):
    """Policy action to take on a request."""

    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"


@dataclass(frozen=True)
class Span:
    """A character-level span within a text field."""

    start: int
    end: int


@dataclass()
class Detection:
    """A single finding from a detector.

    Attributes:
        detector: Name of the detector that produced this finding.
        category: Classification (e.g. ``aws_access_key``, ``email_address``).
        confidence: Score in [0, 1]; higher means more certain.
        span: Character offsets within the source text.
        field_path: Dot-notation path to the request field (e.g. ``messages.0.content``).
    """

    detector: str
    category: str
    confidence: float
    span: Span
    field_path: str = ""


@dataclass()
class Verdict:
    """The firewall's final decision for a request.

    Attributes:
        action: What to do - allow, block, or redact.
        reason: Human-readable explanation (shown to user on block).
        detections: All findings that contributed to this decision.
        sanitized_body: If action is REDACT, the cleaned request body.
    """

    action: Action
    reason: str = ""
    detections: list[Detection] = field(default_factory=list)
    sanitized_body: dict[str, Any] | None = None
