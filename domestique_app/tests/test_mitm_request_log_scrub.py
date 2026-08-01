"""request_log.jsonl must not carry cleartext prompts unless opted into.

The browser MITM path writes its own log file, separate from the debug trace,
so it needs its own gate on the same flag.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from domestique_app.services.mitm_addon import DomestiqueAddon

SECRET = "sk-live-51H8xQqRtVwXyZ0123456789"


def _addon(tmp_path: Path) -> DomestiqueAddon:
    """A bare addon with only the attributes _log_request touches."""
    addon = DomestiqueAddon.__new__(DomestiqueAddon)
    addon._log_file = tmp_path / "request_log.jsonl"
    return addon


def test_request_log_drops_prompt_by_default(tmp_path: Path) -> None:
    addon = _addon(tmp_path)
    addon._log_request(
        {
            "action": "blocked",
            "host": "claude.ai",
            "prompt": SECRET,
            "reasons": ["secret"],
        }
    )

    text = addon._log_file.read_text()
    assert SECRET not in text
    entry = json.loads(text.strip())
    assert entry["host"] == "claude.ai"
    assert entry["action"] == "blocked"
    assert entry["reasons"] == ["secret"]
    assert "prompt" not in entry


def test_request_log_keeps_redacted_prompt(tmp_path: Path) -> None:
    addon = _addon(tmp_path)
    addon._log_request(
        {
            "action": "redacted",
            "prompt": SECRET,
            "redacted_prompt": "[REDACTED_SECRET_1]",
        }
    )

    entry = json.loads(addon._log_file.read_text().strip())
    assert entry["redacted_prompt"] == "[REDACTED_SECRET_1]"
    assert "prompt" not in entry


def test_request_log_keeps_prompt_when_opted_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DOMESTIQUE_LOG_RAW_PROMPTS", "1")
    addon = _addon(tmp_path)
    addon._log_request({"action": "blocked", "prompt": SECRET})

    assert json.loads(addon._log_file.read_text().strip())["prompt"] == SECRET
