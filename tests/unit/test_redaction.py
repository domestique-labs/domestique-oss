"""Tests for smart redaction and tokenization engine."""

from __future__ import annotations

from domestique.redaction import (
    RedactionAction,
    RedactionEngine,
    RedactionRule,
    TokenStore,
)


class TestTokenStore:
    """Test bidirectional token storage."""

    def test_tokenize_returns_sequential_tokens(self):
        store = TokenStore()
        t1 = store.tokenize("123-45-6789", "SSN")
        t2 = store.tokenize("987-65-4321", "SSN")
        assert t1 == "[SSN_1]"
        assert t2 == "[SSN_2]"

    def test_same_value_returns_same_token(self):
        store = TokenStore()
        t1 = store.tokenize("john@corp.com", "EMAIL")
        t2 = store.tokenize("john@corp.com", "EMAIL")
        assert t1 == t2 == "[EMAIL_1]"

    def test_different_categories_independent_counters(self):
        store = TokenStore()
        t1 = store.tokenize("123-45-6789", "SSN")
        t2 = store.tokenize("john@corp.com", "EMAIL")
        assert t1 == "[SSN_1]"
        assert t2 == "[EMAIL_1]"

    def test_detokenize_replaces_all_tokens(self):
        store = TokenStore()
        store.tokenize("123-45-6789", "SSN")
        store.tokenize("john@corp.com", "EMAIL")

        text = "User [SSN_1] has email [EMAIL_1]"
        result = store.detokenize(text)
        assert result == "User 123-45-6789 has email john@corp.com"

    def test_detokenize_with_no_tokens(self):
        store = TokenStore()
        text = "No tokens here"
        assert store.detokenize(text) == text

    def test_clear_removes_all_mappings(self):
        store = TokenStore()
        store.tokenize("123-45-6789", "SSN")
        assert store.size == 1
        store.clear()
        assert store.size == 0

    def test_thread_safety(self):
        """Multiple threads can tokenize concurrently."""
        import threading

        store = TokenStore()
        results = []

        def tokenize_many():
            for i in range(100):
                token = store.tokenize(f"value-{i}", "TEST")
                results.append(token)

        threads = [threading.Thread(target=tokenize_many) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All tokens should be unique
        assert store.size == 100  # 100 unique values

    def test_cleanup_expired(self):
        store = TokenStore(ttl=0.0)  # Expire immediately
        store.tokenize("123-45-6789", "SSN")
        import time

        time.sleep(0.01)
        removed = store.cleanup_expired()
        assert removed == 1
        assert store.size == 0


class TestRedactionEngine:
    """Test the redaction engine with pattern detection."""

    def test_detect_ssn(self):
        engine = RedactionEngine()
        result = engine.redact("My SSN is 123-45-6789")
        assert len(result.findings) == 1
        assert result.findings[0].category == "SSN"
        assert result.findings[0].value == "123-45-6789"

    def test_detect_email(self):
        engine = RedactionEngine()
        result = engine.redact("Contact me at john.doe@company.com please")
        assert any(f.category == "email" for f in result.findings)

    def test_detect_api_key(self):
        engine = RedactionEngine()
        result = engine.redact("Use key sk-proj-abc123def456ghi789jkl0")
        assert any(f.category == "API_key" for f in result.findings)

    def test_detect_aws_key(self):
        engine = RedactionEngine()
        result = engine.redact("AWS key is AKIAIOSFODNN7EXAMPLE")
        assert any(f.category == "AWS_key" for f in result.findings)

    def test_detect_private_key(self):
        engine = RedactionEngine()
        text = "Key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"
        result = engine.redact(text)
        assert any(f.category == "private_key" for f in result.findings)

    def test_no_findings_clean_text(self):
        engine = RedactionEngine()
        result = engine.redact("Hello, how can I help you today?")
        assert result.action == RedactionAction.ALLOW
        assert len(result.findings) == 0
        assert not result.was_modified

    def test_block_action_for_ssn(self):
        """Default rules: SSN triggers BLOCK."""
        engine = RedactionEngine()
        result = engine.redact("SSN: 123-45-6789")
        assert result.action == RedactionAction.BLOCK

    def test_redact_action_for_email(self):
        """Default rules: email triggers REDACT."""
        rules = [RedactionRule("email", RedactionAction.REDACT)]
        engine = RedactionEngine(rules=rules)
        result = engine.redact("Email: test@example.com")
        assert result.action == RedactionAction.REDACT
        assert "[EMAIL_1]" in result.redacted_text
        assert "test@example.com" not in result.redacted_text

    def test_redact_replaces_with_tokens(self):
        """Redaction should replace values with meaningful tokens."""
        rules = [
            RedactionRule("email", RedactionAction.REDACT),
            RedactionRule("phone", RedactionAction.REDACT),
        ]
        engine = RedactionEngine(rules=rules)
        result = engine.redact("Call 555-123-4567 or email test@corp.com")
        assert "[PHONE_1]" in result.redacted_text
        assert "[EMAIL_1]" in result.redacted_text
        assert "555-123-4567" not in result.redacted_text
        assert "test@corp.com" not in result.redacted_text

    def test_multiple_same_category(self):
        """Multiple values in same category get sequential tokens."""
        rules = [RedactionRule("email", RedactionAction.REDACT)]
        engine = RedactionEngine(rules=rules)
        result = engine.redact("Send to alice@corp.com and bob@corp.com")
        assert "[EMAIL_1]" in result.redacted_text
        assert "[EMAIL_2]" in result.redacted_text

    def test_bidirectional_flow(self):
        """Full roundtrip: tokenize request -> de-tokenize response."""
        rules = [RedactionRule("email", RedactionAction.REDACT)]
        engine = RedactionEngine(rules=rules)

        # User's request
        request = "Analyze: john@corp.com is responsible for project X"
        result = engine.redact(request)
        assert "[EMAIL_1]" in result.redacted_text

        # LLM's response (uses our token)
        llm_response = "[EMAIL_1] should be notified about the deadline"
        restored = engine.detokenize(llm_response)
        assert restored == "john@corp.com should be notified about the deadline"

    def test_categories_found(self):
        rules = [
            RedactionRule("email", RedactionAction.REDACT),
            RedactionRule("SSN", RedactionAction.BLOCK),
        ]
        engine = RedactionEngine(rules=rules)
        result = engine.redact("SSN 123-45-6789, email a@b.com")
        assert "SSN" in result.categories_found
        assert "email" in result.categories_found

    def test_set_rule_updates_behavior(self):
        engine = RedactionEngine()
        # Change SSN from BLOCK to REDACT
        engine.set_rule("SSN", RedactionAction.REDACT)
        result = engine.redact("SSN: 123-45-6789")
        assert result.action == RedactionAction.REDACT
        assert "[SSN_1]" in result.redacted_text

    def test_mask_action_irreversible(self):
        """MASK action replaces with asterisks (not reversible)."""
        rules = [RedactionRule("email", RedactionAction.MASK)]
        engine = RedactionEngine(rules=rules)
        result = engine.redact("Email: test@example.com")
        assert "test@example.com" not in result.redacted_text
        assert "***" in result.redacted_text
        # Masking is irreversible
        assert result.token_count == 0


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_text(self):
        engine = RedactionEngine()
        result = engine.redact("")
        assert result.action == RedactionAction.ALLOW

    def test_overlapping_patterns(self):
        """When patterns overlap, both should be detected."""
        rules = [
            RedactionRule("email", RedactionAction.REDACT),
            RedactionRule("SSN", RedactionAction.BLOCK),
        ]
        engine = RedactionEngine(rules=rules)
        # SSN + email in same text - BLOCK wins
        result = engine.redact("SSN 123-45-6789 email x@y.com")
        assert result.action == RedactionAction.BLOCK

    def test_token_store_persists_across_calls(self):
        """Same engine should reuse tokens for same values."""
        rules = [RedactionRule("email", RedactionAction.REDACT)]
        engine = RedactionEngine(rules=rules)

        r1 = engine.redact("From: alice@corp.com")
        r2 = engine.redact("To: alice@corp.com")

        # Same value -> same token
        assert "[EMAIL_1]" in r1.redacted_text
        assert "[EMAIL_1]" in r2.redacted_text

    def test_credit_card_detection(self):
        engine = RedactionEngine()
        result = engine.redact("Card: 4111-1111-1111-1111")
        assert any(f.category == "credit_card" for f in result.findings)
