"""Raw decision trace for local debugging.

This module writes a local JSONL trail of the exact prompt content the firewall
inspected and the action it chose. The trace intentionally contains raw prompt
text, so it is separate from the compact audit log.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

TRACE_PATH = Path.home() / ".llmguard" / "debug_trace.jsonl"
MAX_TRACE_ENTRIES = 1000


def append_debug_trace(entry: dict[str, Any], *, path: Path | None = None) -> None:
    """Append one debug trace entry. Never raises into the request path."""
    try:
        trace_path = path or TRACE_PATH
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "ts": datetime.now(UTC).isoformat(),
            **entry,
            "raw_prompt_logged": True,
        }
        with open(trace_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(_json_safe(event), ensure_ascii=False) + "\n")
        _trim_trace(trace_path)
    except Exception:
        return


def read_debug_trace(
    *,
    limit: int = 100,
    action_filter: str | None = None,
    path: Path | None = None,
) -> list[dict[str, Any]]:
    """Read recent debug trace entries, newest first."""
    trace_path = path or TRACE_PATH
    entries: list[dict[str, Any]] = []
    try:
        if not trace_path.exists():
            return entries
        lines = trace_path.read_text(encoding="utf-8").splitlines()
        for line in reversed(lines):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if action_filter and entry.get("action") != action_filter:
                continue
            entries.append(entry)
            if len(entries) >= limit:
                break
    except OSError:
        return []
    return entries


def prompt_fields(texts: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Convert extracted text tuples into trace-friendly prompt fields."""
    return [
        {"field_path": field_path, "text": text, "length": len(text)} for field_path, text in texts
    ]


def join_prompts(texts: list[tuple[str, str]]) -> str:
    """Join extracted prompt fields into one readable debug string."""
    return "\n\n".join(text for _field_path, text in texts)


def detection_fields(detections: list[Any]) -> list[dict[str, Any]]:
    """Convert detector results to stable JSON for the trace file."""
    fields: list[dict[str, Any]] = []
    for detection in detections:
        span = getattr(detection, "span", None)
        fields.append(
            {
                "detector": getattr(detection, "detector", ""),
                "category": getattr(detection, "category", ""),
                "confidence": getattr(detection, "confidence", None),
                "field_path": getattr(detection, "field_path", ""),
                "span": {
                    "start": getattr(span, "start", None),
                    "end": getattr(span, "end", None),
                },
            }
        )
    return fields


def _trim_trace(path: Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_TRACE_ENTRIES:
            path.write_text(
                "\n".join(lines[-MAX_TRACE_ENTRIES:]) + "\n",
                encoding="utf-8",
            )
    except OSError:
        return


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return _json_safe(asdict(value))
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return str(value)
