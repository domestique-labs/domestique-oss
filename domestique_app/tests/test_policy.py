"""Tests for the policy-as-code engine."""

from __future__ import annotations

import json
import time

import pytest

from domestique_app.services.policy import (
    MatchCondition,
    PolicyAction,
    PolicyEngine,
    PolicyRule,
    PolicyWatcher,
    RequestContext,
)


@pytest.fixture
def basic_policy():
    """Simple policy with a few rules."""
    return PolicyEngine(
        rules=[
            PolicyRule(
                name="block-ssn",
                match=MatchCondition(category="SSN"),
                action=PolicyAction.BLOCK,
                priority=10,
            ),
            PolicyRule(
                name="redact-email-chatgpt",
                match=MatchCondition(category="EMAIL", destination="chatgpt.com"),
                action=PolicyAction.REDACT,
                priority=5,
            ),
            PolicyRule(
                name="allow-internal",
                match=MatchCondition(destination="llm.internal.corp.io"),
                action=PolicyAction.ALLOW,
                priority=20,
            ),
        ]
    )


class TestPolicyEvaluation:
    """Test rule matching and evaluation."""

    def test_matches_by_category(self, basic_policy):
        ctx = RequestContext(destination="api.openai.com", category="SSN")
        decision = basic_policy.evaluate(ctx)
        assert decision.action == PolicyAction.BLOCK
        assert decision.rule_name == "block-ssn"

    def test_matches_by_destination(self, basic_policy):
        ctx = RequestContext(destination="llm.internal.corp.io", category="SSN")
        decision = basic_policy.evaluate(ctx)
        # Allow-internal has higher priority (20 > 10)
        assert decision.action == PolicyAction.ALLOW
        assert decision.rule_name == "allow-internal"

    def test_matches_combined_conditions(self, basic_policy):
        ctx = RequestContext(destination="chatgpt.com", category="EMAIL")
        decision = basic_policy.evaluate(ctx)
        assert decision.action == PolicyAction.REDACT
        assert decision.rule_name == "redact-email-chatgpt"

    def test_default_action_when_no_match(self):
        engine = PolicyEngine(rules=[], default_action=PolicyAction.BLOCK)
        ctx = RequestContext(destination="unknown.com", category="UNKNOWN")
        decision = engine.evaluate(ctx)
        assert decision.action == PolicyAction.BLOCK
        assert decision.rule_name == "<default>"

    def test_priority_ordering(self):
        """Higher priority rules should be evaluated first."""
        engine = PolicyEngine(
            rules=[
                PolicyRule(
                    name="low-priority",
                    match=MatchCondition(category="SSN"),
                    action=PolicyAction.REDACT,
                    priority=1,
                ),
                PolicyRule(
                    name="high-priority",
                    match=MatchCondition(category="SSN"),
                    action=PolicyAction.BLOCK,
                    priority=100,
                ),
            ]
        )
        ctx = RequestContext(destination="api.openai.com", category="SSN")
        decision = engine.evaluate(ctx)
        assert decision.action == PolicyAction.BLOCK
        assert decision.rule_name == "high-priority"

    def test_disabled_rules_skipped(self):
        engine = PolicyEngine(
            rules=[
                PolicyRule(
                    name="disabled-rule",
                    match=MatchCondition(category="SSN"),
                    action=PolicyAction.BLOCK,
                    enabled=False,
                ),
            ],
            default_action=PolicyAction.ALLOW,
        )
        ctx = RequestContext(destination="api.openai.com", category="SSN")
        decision = engine.evaluate(ctx)
        assert decision.action == PolicyAction.ALLOW


class TestMatchConditions:
    """Test individual match condition logic."""

    def test_wildcard_destination(self):
        match = MatchCondition(destination="*.openai.com")
        ctx = RequestContext(destination="api.openai.com")
        assert match.matches(ctx)

    def test_wildcard_destination_no_match(self):
        match = MatchCondition(destination="*.openai.com")
        ctx = RequestContext(destination="chatgpt.com")
        assert not match.matches(ctx)

    def test_exact_destination(self):
        match = MatchCondition(destination="chatgpt.com")
        ctx = RequestContext(destination="chatgpt.com")
        assert match.matches(ctx)

    def test_category_match(self):
        match = MatchCondition(category="SSN")
        ctx = RequestContext(destination="any.com", category="SSN")
        assert match.matches(ctx)

    def test_category_no_match(self):
        match = MatchCondition(category="EMAIL")
        ctx = RequestContext(destination="any.com", category="SSN")
        assert not match.matches(ctx)

    def test_time_range_match(self):
        match = MatchCondition(time_range="00:00-23:59")
        ctx = RequestContext(destination="any.com")
        assert match.matches(ctx)  # Always true for all-day range

    def test_confidence_threshold(self):
        match = MatchCondition(min_confidence=0.8)
        ctx_high = RequestContext(destination="a.com", confidence=0.9)
        ctx_low = RequestContext(destination="a.com", confidence=0.5)
        assert match.matches(ctx_high)
        assert not match.matches(ctx_low)

    def test_empty_match_matches_everything(self):
        match = MatchCondition()
        ctx = RequestContext(destination="anything.com", category="ANY")
        assert match.matches(ctx)


class TestPolicyFromDict:
    """Test loading policy from dictionary/YAML."""

    def test_from_dict_basic(self):
        data = {
            "version": 2,
            "default_action": "allow",
            "rules": [
                {
                    "name": "block-ssn",
                    "match": {"category": "SSN"},
                    "action": "block",
                    "priority": 10,
                },
                {
                    "name": "allow-internal",
                    "match": {"destination": "internal.com"},
                    "action": "allow",
                },
            ],
        }
        engine = PolicyEngine.from_dict(data)
        assert len(engine.rules) == 2

        ctx = RequestContext(destination="api.openai.com", category="SSN")
        decision = engine.evaluate(ctx)
        assert decision.action == PolicyAction.BLOCK

    def test_from_json_string(self):
        json_str = json.dumps(
            {
                "version": 2,
                "rules": [{"name": "test", "match": {"category": "EMAIL"}, "action": "redact"}],
            }
        )
        engine = PolicyEngine.from_yaml(json_str)
        assert len(engine.rules) == 1

    def test_from_file(self, tmp_path):
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(
            json.dumps(
                {
                    "version": 2,
                    "rules": [
                        {"name": "block-all-ssn", "match": {"category": "SSN"}, "action": "block"}
                    ],
                }
            )
        )
        engine = PolicyEngine.from_file(policy_file)
        assert len(engine.rules) == 1


class TestPolicyManagement:
    """Test adding/removing rules dynamically."""

    def test_add_rule(self, basic_policy):
        initial_count = len(basic_policy.rules)
        basic_policy.add_rule(
            PolicyRule(
                name="new-rule",
                match=MatchCondition(category="PHONE"),
                action=PolicyAction.ALERT,
            )
        )
        assert len(basic_policy.rules) == initial_count + 1

    def test_remove_rule(self, basic_policy):
        assert basic_policy.remove_rule("block-ssn")
        assert not any(r.name == "block-ssn" for r in basic_policy.rules)

    def test_remove_nonexistent_rule(self, basic_policy):
        assert not basic_policy.remove_rule("nonexistent")

    def test_stats_tracking(self, basic_policy):
        ctx = RequestContext(destination="api.openai.com", category="SSN")
        basic_policy.evaluate(ctx)
        basic_policy.evaluate(ctx)
        stats = basic_policy.stats
        assert stats["evaluations"] == 2
        assert stats["blocks"] == 2


class TestPolicyWatcher:
    """Test hot-reload functionality."""

    def test_loads_on_start(self, tmp_path):
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(
            json.dumps(
                {
                    "version": 2,
                    "rules": [{"name": "r1", "match": {"category": "SSN"}, "action": "block"}],
                }
            )
        )

        watcher = PolicyWatcher(policy_file, reload_interval=0.1)
        watcher.start()
        time.sleep(0.2)

        assert watcher.engine is not None
        assert len(watcher.engine.rules) == 1
        watcher.stop()

    def test_reloads_on_change(self, tmp_path):
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(
            json.dumps(
                {
                    "version": 2,
                    "rules": [{"name": "r1", "match": {}, "action": "block"}],
                }
            )
        )

        reloaded = []
        watcher = PolicyWatcher(
            policy_file,
            reload_interval=0.1,
            on_reload=lambda e: reloaded.append(e),
        )
        watcher.start()
        time.sleep(0.2)

        # Modify file
        time.sleep(0.1)
        policy_file.write_text(
            json.dumps(
                {
                    "version": 2,
                    "rules": [
                        {"name": "r1", "match": {}, "action": "block"},
                        {"name": "r2", "match": {}, "action": "allow"},
                    ],
                }
            )
        )
        time.sleep(0.3)

        assert len(watcher.engine.rules) == 2
        assert len(reloaded) >= 2  # Initial load + reload
        watcher.stop()

    def test_handles_missing_file(self, tmp_path):
        watcher = PolicyWatcher(tmp_path / "nonexistent.json")
        watcher.start()
        time.sleep(0.1)
        assert watcher.engine is None
        watcher.stop()
