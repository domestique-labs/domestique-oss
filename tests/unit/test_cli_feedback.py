"""Tests for the wedge CLI: live ticker, --quiet/--strict, and `report`."""

from __future__ import annotations

import json
import os
from pathlib import Path

from domestique.cli import _live_feedback_enabled, _make_ticker, main
from domestique.detectors import status as st
from domestique.models import Action


def test_live_feedback_enabled_logic() -> None:
    assert _live_feedback_enabled(quiet=False, isatty=True) is True
    assert _live_feedback_enabled(quiet=True, isatty=True) is False
    assert _live_feedback_enabled(quiet=False, isatty=False) is False


def test_ticker_renders_redact_and_block() -> None:
    lines: list[str] = []
    cb = _make_ticker(color=False, emit=lines.append)
    cb(Action.REDACT, ["aws_access_key", "email_address"], "api.anthropic.com")
    cb(Action.BLOCK, ["private_key"], "api.openai.com")
    assert any(
        "redacted" in ln and "AWS access key" in ln and "api.anthropic.com" in ln for ln in lines
    )
    assert any("blocked" in ln and "Private key" in ln and "api.openai.com" in ln for ln in lines)


def test_report_command_empty_state(capsys) -> None:
    rc = main(["report"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no events" in out.lower()


def test_report_command_shows_counts(capsys) -> None:
    path = Path(os.environ["DOMESTIQUE_AUDIT_LOG"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"action": "redact", "categories": ["us_ssn"]}) + "\n"
        + json.dumps({"action": "block", "categories": ["private_key"]}) + "\n"
    )
    rc = main(["report"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "US SSN" in out
    assert "Private key" in out


def test_report_json_output(capsys) -> None:
    path = Path(os.environ["DOMESTIQUE_AUDIT_LOG"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"action": "redact", "categories": ["us_ssn"]}) + "\n")
    rc = main(["report", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    parsed = json.loads(out)
    assert parsed["total_events"] == 1
    assert parsed["by_category"]["us_ssn"]["redact"] == 1


def test_start_strict_refuses_when_tier_unavailable(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "domestique.cli.detector_status",
        lambda settings, deep=False: [
            st.TierStatus("pii", "PII detection", True, False, "install 'domestique[pii]'")
        ],
    )
    ran = {"v": False}
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: ran.__setitem__("v", True))
    rc = main(["start", "--strict", "--port", "8123"])
    assert rc != 0
    assert ran["v"] is False  # proxy must never bind
    out = capsys.readouterr().out
    assert "strict" in out.lower()
    assert "pii" in out.lower()


def test_start_warns_but_serves_when_not_strict(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "domestique.cli.detector_status",
        lambda settings, deep=False: [
            st.TierStatus("pii", "PII detection", True, False, "install 'domestique[pii]'")
        ],
    )
    ran = {"v": False}
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: ran.__setitem__("v", True))
    rc = main(["start", "--port", "8124"])
    assert rc == 0
    assert ran["v"] is True  # still serves (fail-open)
    out = capsys.readouterr().out
    assert "unavailable" in out.lower()
