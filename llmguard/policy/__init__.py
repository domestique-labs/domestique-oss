"""LLM Firewall - Policy engine.

Evaluates a list of detections against declarative YAML rules and returns
the most restrictive applicable action.

Rules are evaluated in priority order: block > redact > allow.
Short-circuits on the first ``block`` match for minimal latency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import structlog
import yaml

from llmguard.models import Action, Detection

logger = structlog.get_logger()


@dataclass(frozen=True)
class Rule:
    """A single policy rule parsed from YAML."""

    name: str
    detector: str  # detector name, or "*" for any
    action: Action
    categories: list[str] = field(default_factory=list)  # empty = match all
    min_confidence: float = 0.0


class PolicyEngine:
    """Evaluates findings against an ordered ruleset.

    Thread-safe: rules are loaded once and never mutated at runtime.
    """

    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyEngine:
        """Load rules from a YAML file. Falls back to defaults on error."""
        path = Path(path)
        if not path.exists():
            logger.warning("policy_file_missing", path=str(path))
            return cls(rules=_DEFAULT_RULES)

        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            rules = [
                Rule(
                    name=r["name"],
                    detector=r.get("detector", "*"),
                    action=Action(r["action"]),
                    categories=r.get("categories", []),
                    min_confidence=r.get("min_confidence", 0.0),
                )
                for r in raw.get("rules", [])
            ]
            logger.info("policy_loaded", rule_count=len(rules), path=str(path))
            return cls(rules=rules)
        except Exception:
            logger.exception("policy_load_error", path=str(path))
            return cls(rules=_DEFAULT_RULES)

    def evaluate(self, detections: list[Detection]) -> Action:
        """Return the most restrictive action that matches any detection.

        Complexity: O(rules × detections) - typically < 20 × 10 = 200 ops.
        """
        if not detections:
            return Action.ALLOW

        worst = Action.ALLOW
        priority = {Action.ALLOW: 0, Action.REDACT: 1, Action.BLOCK: 2}

        for rule in self._rules:
            for det in detections:
                if not self._matches(rule, det):
                    continue
                if priority[rule.action] > priority[worst]:
                    worst = rule.action
                if worst is Action.BLOCK:
                    return Action.BLOCK  # short-circuit

        return worst

    def explain(self, detections: list[Detection]) -> tuple[Action, str]:
        """Like ``evaluate`` but also returns a human-readable reason."""
        if not detections:
            return Action.ALLOW, "no findings"

        worst = Action.ALLOW
        reason = "no matching rules"
        priority = {Action.ALLOW: 0, Action.REDACT: 1, Action.BLOCK: 2}

        for rule in self._rules:
            for det in detections:
                if not self._matches(rule, det):
                    continue
                if priority[rule.action] > priority[worst]:
                    worst = rule.action
                    reason = (
                        f"rule '{rule.name}': {det.category} (confidence {det.confidence:.0%})"
                    )
                if worst is Action.BLOCK:
                    return worst, reason

        return worst, reason

    @staticmethod
    def _matches(rule: Rule, det: Detection) -> bool:
        if rule.detector != "*" and rule.detector != det.detector:
            return False
        if rule.categories and det.category not in rule.categories:
            return False
        return not det.confidence < rule.min_confidence


# Sensible defaults when no policy file is present.
_DEFAULT_RULES: list[Rule] = [
    Rule(
        name="block-secrets",
        detector="secret_scanner",
        action=Action.BLOCK,
        categories=[
            "private_key",
            "aws_access_key",
            "aws_secret_key",
            "connection_string",
            "github_token",
            "github_fine_grained",
            "openai_key",
            "anthropic_key",
            "slack_token",
        ],
        min_confidence=0.9,
    ),
    Rule(
        name="block-passwords",
        detector="secret_scanner",
        action=Action.BLOCK,
        categories=["password_literal", "jwt"],
        min_confidence=0.85,
    ),
    Rule(
        name="redact-pii-ids",
        detector="pii_detector",
        action=Action.REDACT,
        categories=["us_ssn", "credit_card", "us_passport", "us_driver_license", "iban_code"],
        min_confidence=0.7,
    ),
    Rule(
        name="redact-pii-contact",
        detector="pii_detector",
        action=Action.REDACT,
        categories=["email_address", "phone_number"],
        min_confidence=0.8,
    ),
]
