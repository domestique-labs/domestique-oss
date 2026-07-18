"""Tests for Domestique SDK - scan, redact, is_safe, and LiteLLM callback."""

from unittest.mock import MagicMock

import pytest

from domestique.sdk import is_safe, redact, scan


class TestScan:
    """Tests for the scan() function."""

    def test_safe_text(self):
        result = scan("Hello, world!")
        assert result.is_safe is True
        assert result.categories == []
        assert result.count == 0

    def test_empty_text(self):
        result = scan("")
        assert result.is_safe is True

    def test_detects_ssn(self):
        result = scan("My SSN is 123-45-6789")
        assert result.is_safe is False
        assert "SSN" in result.categories
        assert result.count >= 1

    def test_detects_email(self):
        result = scan("Contact john.doe@company.com for info")
        assert result.is_safe is False
        assert any("email" in c.lower() for c in result.categories)

    def test_detects_credit_card(self):
        result = scan("Card: 4111-1111-1111-1111")
        assert result.is_safe is False
        assert any("credit" in c.lower() for c in result.categories)

    def test_multiple_findings(self):
        result = scan("SSN 123-45-6789 and email test@corp.com")
        assert result.is_safe is False
        assert result.count >= 2

    def test_findings_have_detail(self):
        result = scan("My SSN is 123-45-6789")
        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert "category" in finding
        assert "value" in finding


class TestRedact:
    """Tests for the redact() function."""

    def test_safe_text_unchanged(self):
        result = redact("Hello, world!")
        assert result.text == "Hello, world!"
        assert result.is_safe is True
        assert result.token_count == 0

    def test_empty_text(self):
        result = redact("")
        assert result.text == ""
        assert result.is_safe is True

    def test_redacts_ssn(self):
        # Default rule for SSN is BLOCK, so redact returns blocked state
        result = redact("My SSN is 123-45-6789")
        assert result.is_safe is False
        assert "SSN" in result.categories

    def test_redacts_email(self):
        result = redact("Contact admin@example.com")
        assert "admin@example.com" not in result.text
        assert "[EMAIL_" in result.text  # Token placeholder
        assert result.is_safe is False

    def test_preserves_original(self):
        original = "Email: user@test.com"
        result = redact(original)
        assert result.original == original

    def test_restore_reverses_redaction(self):
        result = redact("Send to john@corp.com")
        # Simulate an LLM response that includes the token
        token = result.text.replace("Send to ", "")
        llm_response = f"I'll forward to {token}"
        restored = result.restore(llm_response)
        assert "john@corp.com" in restored

    def test_restore_noop_when_safe(self):
        result = redact("Hello world")
        assert result.restore("test response") == "test response"

    def test_token_count_emails(self):
        # Use emails (REDACT action by default) to test token counting
        result = redact("Email a@b.com and c@d.com")
        assert result.token_count >= 2


class TestIsSafe:
    """Tests for the is_safe() function."""

    def test_safe_text(self):
        assert is_safe("Normal text without PII") is True

    def test_unsafe_ssn(self):
        assert is_safe("SSN: 123-45-6789") is False

    def test_unsafe_email(self):
        assert is_safe("admin@company.com") is False

    def test_empty_is_safe(self):
        assert is_safe("") is True


class TestDomestiqueCallback:
    """Tests for the LiteLLM callback integration."""

    def test_import(self):
        from domestique import DomestiqueCallback

        cb = DomestiqueCallback()
        assert cb is not None

    def test_blocks_sensitive_request(self):
        from domestique import DomestiqueCallback
        from domestique.callback import DomestiqueBlockedError

        cb = DomestiqueCallback(mode="block")
        messages = [{"role": "user", "content": "My SSN is 123-45-6789"}]

        with pytest.raises(DomestiqueBlockedError):
            cb.log_pre_api_call("gpt-4o", messages, {})

    def test_redact_mode_modifies_content(self):
        from domestique import DomestiqueCallback

        cb = DomestiqueCallback(mode="redact")
        messages = [{"role": "user", "content": "My SSN is 123-45-6789"}]

        cb.log_pre_api_call("gpt-4o", messages, {})
        assert "123-45-6789" not in messages[0]["content"]

    def test_allows_safe_content(self):
        from domestique import DomestiqueCallback

        cb = DomestiqueCallback(mode="block")
        messages = [{"role": "user", "content": "What is the weather?"}]

        cb.log_pre_api_call("gpt-4o", messages, {})
        assert messages[0]["content"] == "What is the weather?"

    def test_skips_assistant_messages(self):
        from domestique import DomestiqueCallback

        cb = DomestiqueCallback(mode="block")
        messages = [
            {"role": "assistant", "content": "SSN: 123-45-6789"},
            {"role": "user", "content": "Hello"},
        ]

        # Should not raise - assistant messages not scanned on request
        cb.log_pre_api_call("gpt-4o", messages, {})

    def test_on_block_callback(self):
        from domestique import DomestiqueCallback
        from domestique.callback import DomestiqueBlockedError

        handler = MagicMock()
        cb = DomestiqueCallback(mode="block", on_block=handler)
        messages = [{"role": "user", "content": "SSN 123-45-6789"}]

        with pytest.raises(DomestiqueBlockedError):
            cb.log_pre_api_call("gpt-4o", messages, {})

        handler.assert_called_once()

    def test_response_scanning(self):
        from domestique import DomestiqueCallback

        cb = DomestiqueCallback(scan_responses=True)

        # Mock LiteLLM response
        response = MagicMock()
        choice = MagicMock()
        choice.message.content = "The SSN is 123-45-6789"
        response.choices = [choice]

        # Should not raise, just log warning
        cb.log_success_event({}, response, 0.0, 1.0)

    def test_response_scanning_disabled(self):
        from domestique import DomestiqueCallback

        cb = DomestiqueCallback(scan_responses=False)

        response = MagicMock()
        choice = MagicMock()
        choice.message.content = "The SSN is 123-45-6789"
        response.choices = [choice]

        # Should be a no-op
        cb.log_success_event({}, response, 0.0, 1.0)
