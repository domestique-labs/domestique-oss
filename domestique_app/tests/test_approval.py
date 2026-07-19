"""Tests for the user approval flow.

Covers:
- ApprovalManager state management and thread safety
- PendingApproval lifecycle (pending -> approved/denied/expired)
- Redaction of preview content
- API endpoint handling
- Addon integration with approval mode
"""

from __future__ import annotations

import threading
import time

import pytest

from domestique_app.services.approval import (
    ApprovalManager,
    ApprovalStatus,
    PendingApproval,
)

# --- ApprovalManager Unit Tests -----------------------------------------


class TestApprovalManager:
    """Tests for the ApprovalManager singleton."""

    def setup_method(self):
        self.mgr = ApprovalManager()

    def test_submit_creates_approval(self):
        approval = self.mgr.submit(
            host="api.openai.com",
            path="/v1/chat/completions",
            findings=["SSN", "email"],
            content_preview="my ssn is ***-**-1234",
        )
        assert approval.id is not None
        assert len(approval.id) > 10  # URL-safe random
        assert approval.status == ApprovalStatus.PENDING
        assert approval.host == "api.openai.com"
        assert approval.findings == ["SSN", "email"]

    def test_submit_truncates_path(self):
        approval = self.mgr.submit(
            host="api.openai.com",
            path="/" + "x" * 200,
            findings=["SSN"],
            content_preview="test",
        )
        assert len(approval.path) <= 100

    def test_submit_truncates_preview(self):
        approval = self.mgr.submit(
            host="api.openai.com",
            path="/test",
            findings=["SSN"],
            content_preview="x" * 500,
        )
        assert len(approval.content_preview) <= 300

    def test_get_returns_approval(self):
        approval = self.mgr.submit(
            host="api.openai.com",
            path="/test",
            findings=["SSN"],
            content_preview="test",
        )
        fetched = self.mgr.get(approval.id)
        assert fetched is not None
        assert fetched.id == approval.id

    def test_get_returns_none_for_unknown(self):
        assert self.mgr.get("nonexistent-id") is None

    def test_decide_approve(self):
        approval = self.mgr.submit(
            host="api.openai.com",
            path="/test",
            findings=["email"],
            content_preview="test",
        )
        result = self.mgr.decide(approval.id, ApprovalStatus.APPROVED)
        assert result.status == ApprovalStatus.APPROVED
        assert result.decided_at is not None

    def test_decide_deny(self):
        approval = self.mgr.submit(
            host="api.openai.com",
            path="/test",
            findings=["SSN"],
            content_preview="test",
        )
        result = self.mgr.decide(approval.id, ApprovalStatus.DENIED)
        assert result.status == ApprovalStatus.DENIED

    def test_decide_already_decided_raises(self):
        approval = self.mgr.submit(
            host="api.openai.com",
            path="/test",
            findings=["SSN"],
            content_preview="test",
        )
        self.mgr.decide(approval.id, ApprovalStatus.APPROVED)
        with pytest.raises(ValueError, match="already approved"):
            self.mgr.decide(approval.id, ApprovalStatus.DENIED)

    def test_decide_invalid_decision_raises(self):
        approval = self.mgr.submit(
            host="api.openai.com",
            path="/test",
            findings=["SSN"],
            content_preview="test",
        )
        with pytest.raises(ValueError, match="Invalid decision"):
            self.mgr.decide(approval.id, ApprovalStatus.EXPIRED)

    def test_decide_unknown_returns_none(self):
        assert self.mgr.decide("unknown", ApprovalStatus.APPROVED) is None

    def test_auto_expire(self):
        approval = self.mgr.submit(
            host="api.openai.com",
            path="/test",
            findings=["SSN"],
            content_preview="test",
            timeout_seconds=0,  # Immediate expiry
        )
        # Give a tiny bit of time to ensure it's past
        time.sleep(0.01)
        fetched = self.mgr.get(approval.id)
        assert fetched.status == ApprovalStatus.EXPIRED

    def test_decide_expired_raises(self):
        approval = self.mgr.submit(
            host="api.openai.com",
            path="/test",
            findings=["SSN"],
            content_preview="test",
            timeout_seconds=0,
        )
        time.sleep(0.01)
        with pytest.raises(ValueError, match="expired"):
            self.mgr.decide(approval.id, ApprovalStatus.APPROVED)

    def test_list_pending(self):
        a1 = self.mgr.submit(
            host="api.openai.com",
            path="/test",
            findings=["SSN"],
            content_preview="test",
        )
        a2 = self.mgr.submit(
            host="api.anthropic.com",
            path="/test",
            findings=["email"],
            content_preview="test",
        )
        self.mgr.decide(a1.id, ApprovalStatus.APPROVED)
        pending = self.mgr.list_pending()
        assert len(pending) == 1
        assert pending[0].id == a2.id

    def test_list_recent(self):
        for i in range(5):
            self.mgr.submit(
                host=f"host{i}.com",
                path="/test",
                findings=["SSN"],
                content_preview="test",
            )
        recent = self.mgr.list_recent(limit=3)
        assert len(recent) == 3

    def test_pending_count(self):
        self.mgr.submit(
            host="api.openai.com",
            path="/test",
            findings=["SSN"],
            content_preview="test",
        )
        self.mgr.submit(
            host="api.anthropic.com",
            path="/test",
            findings=["email"],
            content_preview="test",
        )
        assert self.mgr.pending_count() == 2

    def test_csrf_token_is_generated(self):
        assert len(self.mgr.csrf_token) > 20

    def test_to_dict(self):
        approval = self.mgr.submit(
            host="api.openai.com",
            path="/v1/chat/completions",
            findings=["SSN"],
            content_preview="test content",
            timeout_seconds=30,
        )
        d = approval.to_dict()
        assert d["host"] == "api.openai.com"
        assert d["status"] == "pending"
        assert "remaining_seconds" in d
        assert d["remaining_seconds"] > 0

    def test_thread_safety(self):
        """Multiple threads submitting and deciding concurrently."""
        results = []
        errors = []

        def worker(i):
            try:
                a = self.mgr.submit(
                    host=f"host{i}.com",
                    path="/test",
                    findings=["SSN"],
                    content_preview="test",
                )
                self.mgr.decide(a.id, ApprovalStatus.APPROVED)
                results.append(a.id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 20


# --- Redaction Tests ----------------------------------------------------


class TestRedaction:
    """Test preview redaction in the mitm addon."""

    def _get_redact(self):
        """Import the redaction method."""
        pytest.importorskip("mitmproxy")  # [browser-proxy] extra; skip cleanly when absent
        from domestique_app.services.mitm_addon import DomestiqueAddon

        addon = DomestiqueAddon()
        return addon._redact_for_preview

    def test_redact_ssn(self):
        redact = self._get_redact()
        assert redact("my ssn is 123-45-6789") == "my ssn is ***-**-6789"

    def test_redact_email(self):
        redact = self._get_redact()
        result = redact("email: john.doe@example.com")
        assert "@example.com" in result
        assert "john.doe" not in result

    def test_redact_api_key(self):
        redact = self._get_redact()
        result = redact("key: sk-abc123def456ghi789")
        assert "sk-***" in result
        assert "abc123" not in result

    def test_redact_credit_card(self):
        redact = self._get_redact()
        result = redact("card: 4111 1111 1111 1234")
        assert "**** **** **** 1234" in result
        assert "4111" not in result

    def test_redact_preserves_non_pii(self):
        redact = self._get_redact()
        text = "Hello, this is a normal message about weather"
        assert redact(text) == text


# --- Approval Flow Integration Tests -----------------------------------


class TestApprovalFlowIntegration:
    """Integration tests for the approval request flow."""

    def test_approval_mode_check_default(self):
        """Default config should have approval_mode=False."""
        from domestique_app.config.schema import AppConfig

        config = AppConfig()
        assert config.approval_mode is False
        assert config.approval_timeout_seconds == 30

    def test_approval_mode_serialization(self):
        """Approval mode should round-trip through to_dict/from_dict."""
        from domestique_app.config.schema import AppConfig

        config = AppConfig(approval_mode=True, approval_timeout_seconds=60)
        d = config.to_dict()
        restored = AppConfig.from_dict(d)
        assert restored.approval_mode is True
        assert restored.approval_timeout_seconds == 60

    def test_pending_approval_expiry_logic(self):
        """Verify the is_expired property works correctly."""
        approval = PendingApproval(
            id="test-123",
            created_at=time.time() - 100,
            host="test.com",
            path="/test",
            findings=["SSN"],
            content_preview="test",
            timeout_seconds=30,
        )
        assert approval.is_expired is True

        fresh = PendingApproval(
            id="test-456",
            created_at=time.time(),
            host="test.com",
            path="/test",
            findings=["SSN"],
            content_preview="test",
            timeout_seconds=30,
        )
        assert fresh.is_expired is False

    def test_to_dict_remaining_seconds(self):
        """Remaining seconds should decrease over time."""
        approval = PendingApproval(
            id="test-789",
            created_at=time.time() - 10,
            host="test.com",
            path="/test",
            findings=["SSN"],
            content_preview="test",
            timeout_seconds=30,
        )
        d = approval.to_dict()
        assert d["remaining_seconds"] <= 20
        assert d["remaining_seconds"] >= 0

    def test_cleanup_removes_old_decided(self):
        """Decided approvals older than 5 minutes should be cleaned up."""
        mgr = ApprovalManager()
        approval = mgr.submit(
            host="test.com",
            path="/test",
            findings=["SSN"],
            content_preview="test",
        )
        mgr.decide(approval.id, ApprovalStatus.APPROVED)
        # Manually backdate the decided_at
        mgr._pending[approval.id].decided_at = time.time() - 600
        # Trigger cleanup
        mgr.list_pending()
        assert mgr.get(approval.id) is None
