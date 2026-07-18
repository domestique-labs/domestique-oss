"""Policy-as-code engine - YAML-based configurable firewall rules.

Lets operators define detection and response policies declaratively.
Policies are version-controlled, hot-reloadable, and support:
- Per-destination rules (different rules for ChatGPT vs internal LLM)
- Per-category actions (block SSN, redact email, allow name)
- Time-based policies (stricter during business hours)
- Allowlists (internal endpoints that bypass scanning)

Policy File Format (YAML):
    version: 2
    rules:
      - name: block-ssn-everywhere
        match: { category: SSN }
        action: block
        notify: security-team@corp.com

      - name: redact-email-chatgpt
        match: { category: EMAIL, destination: "chatgpt.com" }
        action: redact

      - name: allow-internal-llm
        match: { destination: "llm.internal.corp.io" }
        action: allow

Usage:
    engine = PolicyEngine.from_file("policy.yaml")
    decision = engine.evaluate(request_context)
    # decision.action == "block" | "redact" | "allow"
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger("domestique.policy")


class PolicyAction(Enum):
    """Actions a policy rule can prescribe."""

    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    ALERT = "alert"  # Log + notify but don't modify


@dataclass(frozen=True)
class MatchCondition:
    """Conditions that must all be true for a rule to apply."""

    category: str | None = None  # PII category (SSN, EMAIL, etc.)
    destination: str | None = None  # Target host or wildcard
    source_app: str | None = None  # Application name
    time_range: str | None = None  # "HH:MM-HH:MM" (e.g., "09:00-17:00")
    min_confidence: float | None = None  # Minimum detection confidence

    def matches(self, context: RequestContext) -> bool:
        """Check if all conditions match the given context."""
        if self.category and self.category != context.category:
            return False
        if self.destination and not self._matches_destination(context.destination):
            return False
        if self.source_app and self.source_app != context.source_app:
            return False
        if self.time_range and not self._in_time_range():
            return False
        return not (self.min_confidence is not None and context.confidence < self.min_confidence)

    def _matches_destination(self, dest: str) -> bool:
        """Match destination with wildcard support."""
        pattern = self.destination
        if not pattern:
            return True
        if pattern.startswith("*."):
            # Wildcard: *.openai.com matches api.openai.com
            suffix = pattern[1:]  # ".openai.com"
            return dest.endswith(suffix) or dest == pattern[2:]
        return dest == pattern

    def _in_time_range(self) -> bool:
        """Check if current time is within the specified range."""
        if not self.time_range:
            return True
        try:
            start_str, end_str = self.time_range.split("-")
            now = datetime.now().time()
            start = datetime.strptime(start_str.strip(), "%H:%M").time()
            end = datetime.strptime(end_str.strip(), "%H:%M").time()

            if start <= end:
                return start <= now <= end
            else:
                # Overnight range (e.g., 18:00-08:00)
                return now >= start or now <= end
        except (ValueError, AttributeError):
            return True


@dataclass
class PolicyRule:
    """A single policy rule with match conditions and action."""

    name: str
    match: MatchCondition
    action: PolicyAction
    priority: int = 0  # Higher priority rules evaluated first
    notify: str | None = None  # Email/channel to notify
    enabled: bool = True
    description: str = ""

    def applies_to(self, context: RequestContext) -> bool:
        """Check if this rule matches the given request context."""
        return self.enabled and self.match.matches(context)


@dataclass
class RequestContext:
    """Context about the current request being evaluated."""

    destination: str  # Target host (e.g., "api.openai.com")
    category: str = ""  # PII category detected (e.g., "SSN")
    source_app: str = ""  # Application name (e.g., "Safari", "curl")
    confidence: float = 1.0  # Detection confidence [0.0, 1.0]
    content_preview: str = ""  # First N chars of content (for logging)
    method: str = "POST"
    path: str = ""
    user: str = "local"


@dataclass(frozen=True)
class PolicyDecision:
    """The engine's decision after evaluating all rules."""

    action: PolicyAction
    rule_name: str  # Which rule made the decision
    notify: str | None  # Who to notify (if any)
    reason: str = ""  # Human-readable explanation


class PolicyEngine:
    """Evaluates requests against a set of policy rules.

    Rules are evaluated in priority order. The first matching rule wins.
    If no rules match, the default action is applied (configurable).
    """

    def __init__(
        self,
        rules: list[PolicyRule] | None = None,
        default_action: PolicyAction = PolicyAction.BLOCK,
    ) -> None:
        self._rules = sorted(rules or [], key=lambda r: r.priority, reverse=True)
        self._default_action = default_action
        self._lock = threading.Lock()
        self._stats = {"evaluations": 0, "blocks": 0, "allows": 0, "redacts": 0}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyEngine:
        """Create a PolicyEngine from a parsed YAML/JSON dictionary.

        Expected format:
            {
                "version": 2,
                "default_action": "block",
                "rules": [
                    {"name": "...", "match": {...}, "action": "block", ...}
                ]
            }
        """
        default = PolicyAction(data.get("default_action", "block"))
        rules = []

        for rule_data in data.get("rules", []):
            match_data = rule_data.get("match", {})
            match = MatchCondition(
                category=match_data.get("category"),
                destination=match_data.get("destination"),
                source_app=match_data.get("source_app"),
                time_range=match_data.get("time"),
                min_confidence=match_data.get("min_confidence"),
            )
            rule = PolicyRule(
                name=rule_data["name"],
                match=match,
                action=PolicyAction(rule_data["action"]),
                priority=rule_data.get("priority", 0),
                notify=rule_data.get("notify"),
                enabled=rule_data.get("enabled", True),
                description=rule_data.get("description", ""),
            )
            rules.append(rule)

        return cls(rules=rules, default_action=default)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> PolicyEngine:
        """Create a PolicyEngine from a YAML string."""
        try:
            import yaml

            data = yaml.safe_load(yaml_str)
        except ImportError:
            # Fallback: basic YAML-like parsing for simple cases
            import json

            data = json.loads(yaml_str)
        return cls.from_dict(data)

    @classmethod
    def from_file(cls, path: Path) -> PolicyEngine:
        """Load policy from a YAML file."""
        content = Path(path).read_text()
        return cls.from_yaml(content)

    def evaluate(self, context: RequestContext) -> PolicyDecision:
        """Evaluate a request against all policy rules.

        Returns the decision from the first matching rule (by priority).
        If no rules match, applies the default action.
        """
        with self._lock:
            self._stats["evaluations"] += 1

        for rule in self._rules:
            if rule.applies_to(context):
                decision = PolicyDecision(
                    action=rule.action,
                    rule_name=rule.name,
                    notify=rule.notify,
                    reason=rule.description or f"Matched rule: {rule.name}",
                )
                self._track_decision(decision)
                return decision

        # No rule matched - apply default
        decision = PolicyDecision(
            action=self._default_action,
            rule_name="<default>",
            notify=None,
            reason="No matching rule - default action applied",
        )
        self._track_decision(decision)
        return decision

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a rule and re-sort by priority."""
        with self._lock:
            self._rules.append(rule)
            self._rules.sort(key=lambda r: r.priority, reverse=True)

    def remove_rule(self, name: str) -> bool:
        """Remove a rule by name. Returns True if found and removed."""
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.name != name]
            return len(self._rules) < before

    @property
    def rules(self) -> list[PolicyRule]:
        """Current rules (sorted by priority)."""
        return list(self._rules)

    @property
    def stats(self) -> dict[str, int]:
        """Evaluation statistics."""
        return self._stats.copy()

    def _track_decision(self, decision: PolicyDecision) -> None:
        """Track decision statistics."""
        with self._lock:
            if decision.action == PolicyAction.BLOCK:
                self._stats["blocks"] += 1
            elif decision.action == PolicyAction.ALLOW:
                self._stats["allows"] += 1
            elif decision.action == PolicyAction.REDACT:
                self._stats["redacts"] += 1


class PolicyWatcher:
    """Watches a policy file for changes and hot-reloads.

    Polls the file's mtime periodically. When a change is detected,
    reloads the policy and swaps the engine atomically.
    """

    def __init__(
        self,
        policy_path: Path,
        reload_interval: float = 10.0,
        on_reload: callable | None = None,
    ) -> None:
        self._path = Path(policy_path)
        self._interval = reload_interval
        self._on_reload = on_reload
        self._running = False
        self._thread: threading.Thread | None = None
        self._last_mtime = 0.0
        self._engine: PolicyEngine | None = None
        self._lock = threading.Lock()

    @property
    def engine(self) -> PolicyEngine | None:
        """Get the current policy engine."""
        with self._lock:
            return self._engine

    def start(self) -> None:
        """Start watching the policy file."""
        if self._running:
            return
        self._load()
        self._running = True
        self._thread = threading.Thread(
            target=self._watch_loop, daemon=True, name="policy-watcher"
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop watching."""
        self._running = False

    def _load(self) -> None:
        """Load or reload the policy file."""
        if not self._path.exists():
            logger.warning(f"Policy file not found: {self._path}")
            return
        try:
            engine = PolicyEngine.from_file(self._path)
            with self._lock:
                self._engine = engine
            self._last_mtime = self._path.stat().st_mtime
            logger.info(f"Policy loaded: {len(engine.rules)} rules from {self._path}")
            if self._on_reload:
                self._on_reload(engine)
        except Exception as e:
            logger.error(f"Failed to load policy: {e}")

    def _watch_loop(self) -> None:
        """Poll for file changes."""
        while self._running:
            try:
                if self._path.exists():
                    mtime = self._path.stat().st_mtime
                    if mtime > self._last_mtime:
                        logger.info("Policy file changed - reloading")
                        self._load()
            except Exception as e:
                logger.error(f"Policy watch error: {e}")
            time.sleep(self._interval)
