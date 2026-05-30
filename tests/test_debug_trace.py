"""Tests for raw prompt decision tracing."""

from __future__ import annotations

from pathlib import Path

from llmguard.debug_trace import append_debug_trace, read_debug_trace


def test_append_and_read_debug_trace(tmp_path: Path) -> None:
    trace_path = tmp_path / "debug_trace.jsonl"

    append_debug_trace(
        {
            "source": "api_proxy",
            "action": "blocked",
            "prompt": "send this prompt",
            "reason": "test detector",
        },
        path=trace_path,
    )

    entries = read_debug_trace(path=trace_path)

    assert len(entries) == 1
    assert entries[0]["action"] == "blocked"
    assert entries[0]["prompt"] == "send this prompt"
    assert entries[0]["raw_prompt_logged"] is True


def test_read_debug_trace_filters_by_action(tmp_path: Path) -> None:
    trace_path = tmp_path / "debug_trace.jsonl"
    append_debug_trace({"action": "allowed", "prompt": "ok"}, path=trace_path)
    append_debug_trace({"action": "blocked", "prompt": "secret"}, path=trace_path)

    entries = read_debug_trace(action_filter="blocked", path=trace_path)

    assert len(entries) == 1
    assert entries[0]["prompt"] == "secret"
