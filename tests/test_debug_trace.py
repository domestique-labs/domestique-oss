"""Tests for decision tracing.

Prompt content is scrubbed by default; see ``test_debug_trace_scrub.py`` for the
scrubbing rules themselves. These tests cover the append/read round trip.
"""

from __future__ import annotations

from pathlib import Path

from domestique.debug_trace import append_debug_trace, read_debug_trace


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
    assert entries[0]["reason"] == "test detector"
    assert entries[0]["source"] == "api_proxy"
    # The decision is recorded; the prompt that triggered it is not.
    assert "prompt" not in entries[0]
    assert entries[0]["raw_prompt_logged"] is False


def test_append_and_read_debug_trace_raw_opt_in(tmp_path: Path) -> None:
    trace_path = tmp_path / "debug_trace.jsonl"

    append_debug_trace(
        {"source": "api_proxy", "action": "blocked", "prompt": "send this prompt"},
        path=trace_path,
        log_raw=True,
    )

    entries = read_debug_trace(path=trace_path)

    assert len(entries) == 1
    assert entries[0]["prompt"] == "send this prompt"
    assert entries[0]["raw_prompt_logged"] is True


def test_read_debug_trace_filters_by_action(tmp_path: Path) -> None:
    trace_path = tmp_path / "debug_trace.jsonl"
    append_debug_trace({"action": "allowed", "reason": "clean"}, path=trace_path)
    append_debug_trace({"action": "blocked", "reason": "aws_key"}, path=trace_path)

    entries = read_debug_trace(action_filter="blocked", path=trace_path)

    assert len(entries) == 1
    assert entries[0]["reason"] == "aws_key"
