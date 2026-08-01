"""Logging-related configuration defaults.

Two product defaults are asserted here because a reviewer checks them first:
audit events land under the user's home rather than the launch directory, and
cleartext prompt logging is off until explicitly requested.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from domestique.config import Settings


def test_audit_path_defaults_under_home() -> None:
    expected = str(Path.home() / ".domestique" / "audit.jsonl")
    assert Settings().audit_log_path == expected


def test_audit_path_is_absolute() -> None:
    """A relative default wrote ./logs/audit.jsonl into whatever cwd was."""
    assert Path(Settings().audit_log_path).is_absolute()


def test_explicit_audit_path_still_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOMESTIQUE_AUDIT_LOG_PATH", "/tmp/custom-audit.jsonl")
    assert Settings().audit_log_path == "/tmp/custom-audit.jsonl"


def test_raw_prompt_logging_off_by_default() -> None:
    assert Settings().log_raw_prompts is False


def test_raw_prompt_logging_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOMESTIQUE_LOG_RAW_PROMPTS", "true")
    assert Settings().log_raw_prompts is True


def test_startup_warns_when_raw_logging_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from domestique.app import _warn_if_raw_prompt_logging

    warnings: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "domestique.app.logger",
        type("L", (), {"warning": lambda _s, ev, **kw: warnings.append((ev, kw))})(),
    )

    _warn_if_raw_prompt_logging(Settings(log_raw_prompts=True))
    assert warnings and warnings[0][0] == "raw_prompt_logging_enabled"
    assert "debug_trace.jsonl" in warnings[0][1]["detail"]

    warnings.clear()
    _warn_if_raw_prompt_logging(Settings(log_raw_prompts=False))
    assert warnings == []
