"""Tests for `domestique report` aggregation, loading, and rendering."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from domestique.report import aggregate, load_events, render_text, to_json


def _ev(action: str, categories: list[str], ts: str | None = None) -> dict:
    event = {"action": action, "categories": categories}
    if ts is not None:
        event["ts"] = ts
    return event


def test_aggregate_counts_per_category_and_action() -> None:
    events = [
        _ev("redact", ["us_ssn", "email_address"]),
        _ev("redact", ["us_ssn"]),
        _ev("block", ["private_key"]),
    ]
    data = aggregate(events)
    assert data.total_events == 3
    assert data.by_category["us_ssn"]["redact"] == 2
    assert data.by_category["email_address"]["redact"] == 1
    assert data.by_category["private_key"]["block"] == 1
    assert data.action_totals["redact"] == 2
    assert data.action_totals["block"] == 1


def test_aggregate_empty() -> None:
    data = aggregate([])
    assert data.total_events == 0
    assert data.by_category == {}
    assert data.action_totals == {}


def test_load_events_skips_malformed_lines(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    p.write_text(
        '{"action":"redact","categories":["us_ssn"]}\n'
        "not json at all\n"
        '{"action":"block","categories":["private_key"]}\n'
    )
    events = load_events(p)
    assert len(events) == 2


def test_load_events_missing_file_returns_empty(tmp_path) -> None:
    assert load_events(tmp_path / "does-not-exist.jsonl") == []


def test_load_events_filters_by_days(tmp_path) -> None:
    now = datetime.now(UTC)
    old = (now - timedelta(days=5)).isoformat()
    recent = now.isoformat()
    p = tmp_path / "audit.jsonl"
    p.write_text(
        json.dumps({"action": "redact", "categories": ["us_ssn"], "ts": old})
        + "\n"
        + json.dumps({"action": "redact", "categories": ["email_address"], "ts": recent})
        + "\n"
    )
    events = load_events(p, since_days=1)
    cats = [c for e in events for c in e["categories"]]
    assert "email_address" in cats
    assert "us_ssn" not in cats


def test_render_text_uses_friendly_labels() -> None:
    data = aggregate([_ev("block", ["aws_secret_key"]), _ev("redact", ["us_ssn"])])
    out = render_text(data)
    assert "US SSN" in out  # friendly label for us_ssn
    assert "AWS secret key" in out or "AWS Secret Key" in out


def test_render_text_reports_empty_state() -> None:
    out = render_text(aggregate([]))
    assert "no" in out.lower()  # e.g. "no events recorded yet"


def test_to_json_is_parseable() -> None:
    data = aggregate([_ev("redact", ["us_ssn"]), _ev("block", ["private_key"])])
    parsed = json.loads(to_json(data))
    assert parsed["total_events"] == 2
    assert parsed["by_category"]["us_ssn"]["redact"] == 1
    assert parsed["by_category"]["private_key"]["block"] == 1
