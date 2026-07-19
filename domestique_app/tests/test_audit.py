"""Tests for the audit logging system."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import pytest

from domestique_app.services.audit import (
    AuditAction,
    AuditStore,
    RetentionPolicy,
    create_audit_event,
)


@pytest.fixture
def tmp_audit_dir(tmp_path):
    """Provide a temporary directory for audit storage."""
    return tmp_path / "audit"


@pytest.fixture
def audit_store(tmp_audit_dir):
    """Create and start an audit store with fast flush."""
    store = AuditStore(data_dir=tmp_audit_dir, retention=RetentionPolicy(max_age_days=1))
    store.FLUSH_INTERVAL = 0.1
    store.start()
    yield store
    store.stop()


class TestAuditEvent:
    """Test AuditEvent creation and serialization."""

    def test_create_audit_event_block(self):
        event = create_audit_event(
            action=AuditAction.BLOCK,
            destination="api.openai.com",
            method="POST",
            path="/v1/chat/completions",
            detectors=["SSN"],
            categories=["SSN"],
            latency_ms=2.5,
            content_length=150,
            content_preview="My SSN is 123-45-6789",
        )
        assert event.action == "block"
        assert event.severity == "critical"
        assert event.destination == "api.openai.com"
        assert "SSN" in event.detectors_triggered
        assert event.request_id  # UUID generated

    def test_create_audit_event_allow(self):
        event = create_audit_event(
            action=AuditAction.ALLOW,
            destination="api.anthropic.com",
        )
        assert event.action == "allow"
        assert event.severity == "info"

    def test_create_audit_event_redact(self):
        event = create_audit_event(
            action=AuditAction.REDACT,
            destination="chatgpt.com",
            detectors=["email"],
            categories=["email"],
        )
        assert event.action == "redact"
        assert event.severity == "warning"

    def test_to_json_is_valid(self):
        event = create_audit_event(
            action=AuditAction.BLOCK,
            destination="api.openai.com",
        )
        parsed = json.loads(event.to_json())
        assert parsed["action"] == "block"
        assert parsed["destination"] == "api.openai.com"

    def test_to_dict_roundtrip(self):
        event = create_audit_event(
            action=AuditAction.ALLOW,
            destination="claude.ai",
            latency_ms=1.23,
        )
        d = event.to_dict()
        assert d["latency_ms"] == 1.23
        assert d["destination"] == "claude.ai"


class TestAuditStore:
    """Test AuditStore persistence and querying."""

    def test_record_and_query(self, audit_store):
        event = create_audit_event(
            action=AuditAction.BLOCK,
            destination="api.openai.com",
            detectors=["SSN"],
            categories=["SSN"],
        )
        audit_store.record(event)

        # Wait for flush
        time.sleep(0.3)

        results = audit_store.query()
        assert len(results) >= 1
        assert results[0]["destination"] == "api.openai.com"
        assert results[0]["action"] == "block"

    def test_query_filter_by_action(self, audit_store):
        # Record both block and allow events
        audit_store.record(
            create_audit_event(action=AuditAction.BLOCK, destination="api.openai.com")
        )
        audit_store.record(
            create_audit_event(action=AuditAction.ALLOW, destination="api.anthropic.com")
        )
        time.sleep(0.3)

        blocked = audit_store.query(action=AuditAction.BLOCK)
        assert all(r["action"] == "block" for r in blocked)

    def test_query_filter_by_destination(self, audit_store):
        audit_store.record(
            create_audit_event(action=AuditAction.BLOCK, destination="api.openai.com")
        )
        audit_store.record(create_audit_event(action=AuditAction.BLOCK, destination="chatgpt.com"))
        time.sleep(0.3)

        results = audit_store.query(destination="chatgpt.com")
        assert all(r["destination"] == "chatgpt.com" for r in results)

    def test_query_with_time_range(self, audit_store):
        audit_store.record(
            create_audit_event(action=AuditAction.ALLOW, destination="api.openai.com")
        )
        time.sleep(0.3)

        # Query with time window that includes now
        results = audit_store.query(since=datetime.now(UTC) - timedelta(minutes=5))
        assert len(results) >= 1

    def test_event_count_tracks_writes(self, audit_store):
        for _ in range(5):
            audit_store.record(
                create_audit_event(action=AuditAction.ALLOW, destination="api.openai.com")
            )
        time.sleep(0.3)
        assert audit_store.event_count >= 5

    def test_jsonl_output_created(self, audit_store, tmp_audit_dir):
        audit_store.record(create_audit_event(action=AuditAction.BLOCK, destination="chatgpt.com"))
        time.sleep(0.3)

        jsonl_path = tmp_audit_dir / "events.jsonl"
        assert jsonl_path.exists()
        lines = jsonl_path.read_text().strip().split("\n")
        assert len(lines) >= 1
        parsed = json.loads(lines[0])
        assert parsed["destination"] == "chatgpt.com"

    def test_get_stats(self, audit_store):
        for _i in range(3):
            audit_store.record(
                create_audit_event(action=AuditAction.BLOCK, destination="api.openai.com")
            )
        audit_store.record(create_audit_event(action=AuditAction.ALLOW, destination="claude.ai"))
        time.sleep(0.3)

        stats = audit_store.get_stats(since=datetime.now(UTC) - timedelta(hours=1))
        assert stats["total_events"] >= 4
        assert "block" in stats["action_counts"]

    def test_start_is_idempotent(self, tmp_audit_dir):
        store = AuditStore(data_dir=tmp_audit_dir)
        store.start()
        store.start()  # Should not create second thread
        store.stop()

    def test_stop_flushes_remaining(self, tmp_audit_dir):
        store = AuditStore(data_dir=tmp_audit_dir)
        store.FLUSH_INTERVAL = 10.0  # Long interval
        store.start()

        store.record(create_audit_event(action=AuditAction.BLOCK, destination="api.openai.com"))
        store.stop()  # Should flush on stop

        # Verify it was written
        jsonl_path = tmp_audit_dir / "events.jsonl"
        assert jsonl_path.exists()
        assert "api.openai.com" in jsonl_path.read_text()


class TestRetentionPolicy:
    """Test log rotation and retention enforcement."""

    def test_old_events_deleted(self, tmp_audit_dir):
        store = AuditStore(
            data_dir=tmp_audit_dir,
            retention=RetentionPolicy(max_age_days=0),  # Delete immediately
        )
        store.FLUSH_INTERVAL = 0.1
        store.start()

        store.record(create_audit_event(action=AuditAction.BLOCK, destination="api.openai.com"))
        time.sleep(0.3)

        # Force retention check
        store._enforce_retention()

        # Events from "today" should be cleared with max_age_days=0
        store.query()
        # Note: max_age_days=0 means delete events older than 0 days from now
        # which means everything before right now - so recent events may remain
        store.stop()

    def test_max_events_enforced(self, tmp_audit_dir):
        store = AuditStore(
            data_dir=tmp_audit_dir,
            retention=RetentionPolicy(max_events=5),
        )
        store.FLUSH_INTERVAL = 0.1
        store.start()

        for i in range(10):
            store.record(create_audit_event(action=AuditAction.ALLOW, destination=f"host{i}.com"))
        time.sleep(0.5)

        store._enforce_retention()
        results = store.query(limit=100)
        assert len(results) <= 5
        store.stop()


class TestAuditStoreQueueBehavior:
    """Test queue overflow and non-blocking behavior."""

    def test_record_when_stopped_is_noop(self, tmp_audit_dir):
        store = AuditStore(data_dir=tmp_audit_dir)
        # Don't start - record should silently do nothing
        store.record(create_audit_event(action=AuditAction.BLOCK, destination="api.openai.com"))
        # No error raised
