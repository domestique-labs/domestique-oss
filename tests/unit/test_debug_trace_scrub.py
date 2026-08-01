"""Prompt content must not reach the debug trace unless explicitly opted in.

The debug trace exists to explain a firewall decision. Explaining the decision
needs the metadata, not the prompt, so prompt text is dropped by default and
``redacted_prompt`` is the only channel through which any prompt content
survives.
"""

from __future__ import annotations

import json
from pathlib import Path

from domestique.debug_trace import (
    append_debug_trace,
    raw_prompt_logging_enabled,
    scrub_entry,
)

SECRET = "sk-live-51H8xQqRtVwXyZ0123456789"


def test_prompt_text_dropped_by_default() -> None:
    out = scrub_entry(
        {
            "action": "pass",
            "prompt": SECRET,
            "prompt_fields": [{"field_path": "body", "text": SECRET, "length": len(SECRET)}],
        }
    )
    assert "prompt" not in out
    assert "prompt_fields" not in out
    assert out["action"] == "pass"


def test_raw_dumps_replaced_with_marker() -> None:
    out = scrub_entry(
        {
            "raw_body": SECRET,
            "request_json": {"messages": [{"content": SECRET}]},
            "raw_body_preview": SECRET,
        }
    )
    for key in ("raw_body", "request_json", "raw_body_preview"):
        assert key not in out
        assert out[f"{key}_omitted"] is True
        assert out[f"{key}_length"] > 0
    assert SECRET not in json.dumps(out)


def test_redacted_prompt_survives() -> None:
    fields = [{"field_path": "body", "text": "[REDACTED_SECRET_1]", "length": 19}]
    out = scrub_entry(
        {"redacted_prompt": "[REDACTED_SECRET_1]", "redacted_prompt_fields": fields}
    )
    assert out["redacted_prompt"] == "[REDACTED_SECRET_1]"
    assert out["redacted_prompt_fields"] == fields


def test_metadata_always_kept() -> None:
    entry = {
        "request_id": "r1",
        "source": "api_proxy",
        "direction": "outbound",
        "action": "redact",
        "reason": "secret detected",
        "reasons": ["secret"],
        "host": "api.anthropic.com",
        "method": "POST",
        "path": "/v1/messages",
        "model": "claude-opus-5",
        "content_length": 12,
        "detections": [{"detector": "secrets", "category": "secret"}],
        "findings": 1,
        "latency_ms": 1.5,
        "user_id": "local",
        "endpoint": "/v1/messages",
    }
    assert scrub_entry(dict(entry)) == entry


def test_clean_pass_carries_no_prompt_text() -> None:
    """The ~95% case: nothing detected, so a "redacted" copy would be the raw prompt."""
    out = scrub_entry({"action": "pass", "prompt": SECRET, "detections": []})
    assert "prompt" not in out
    assert "redacted_prompt" not in out
    assert SECRET not in json.dumps(out)


def test_block_without_redaction_carries_no_prompt_text() -> None:
    out = scrub_entry(
        {
            "action": "block",
            "prompt": SECRET,
            "detections": [{"detector": "secrets", "category": "secret"}],
        }
    )
    assert "prompt" not in out
    assert "redacted_prompt" not in out
    assert out["detections"] == [{"detector": "secrets", "category": "secret"}]


def test_scrub_does_not_mutate_caller_entry() -> None:
    entry = {"action": "pass", "prompt": SECRET}
    scrub_entry(entry)
    assert entry["prompt"] == SECRET


def test_append_scrubs_by_default(tmp_path: Path) -> None:
    path = tmp_path / "debug_trace.jsonl"
    append_debug_trace({"action": "pass", "prompt": SECRET}, path=path)
    text = path.read_text(encoding="utf-8")
    assert SECRET not in text
    written = json.loads(text.strip())
    assert written["raw_prompt_logged"] is False
    assert written["action"] == "pass"


def test_append_keeps_raw_when_opted_in(tmp_path: Path) -> None:
    path = tmp_path / "debug_trace.jsonl"
    append_debug_trace({"action": "pass", "prompt": SECRET}, path=path, log_raw=True)
    written = json.loads(path.read_text(encoding="utf-8").strip())
    assert written["prompt"] == SECRET
    assert written["raw_prompt_logged"] is True


def test_env_var_enables_raw(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DOMESTIQUE_LOG_RAW_PROMPTS", "1")
    path = tmp_path / "debug_trace.jsonl"
    append_debug_trace({"action": "pass", "prompt": SECRET}, path=path)
    assert json.loads(path.read_text(encoding="utf-8").strip())["prompt"] == SECRET


def test_env_var_off_values_do_not_enable_raw(monkeypatch) -> None:
    for value in ("", "0", "false", "no", "off", "maybe"):
        monkeypatch.setenv("DOMESTIQUE_LOG_RAW_PROMPTS", value)
        assert raw_prompt_logging_enabled() is False
    for value in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv("DOMESTIQUE_LOG_RAW_PROMPTS", value)
        assert raw_prompt_logging_enabled() is True
