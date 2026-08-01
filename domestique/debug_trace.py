"""Decision trace for local debugging.

This module writes a local JSONL trail explaining what the firewall did to a
request. Explaining a decision needs the metadata — the action, the categories
detected, the endpoint — not the prompt itself, so prompt content is scrubbed
before it reaches disk.

Raw capture is available for debugging a detector that missed something, but it
is opt-in via ``DOMESTIQUE_LOG_RAW_PROMPTS`` and writes cleartext prompts to
disk. See :func:`scrub_entry` for exactly what survives by default.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

TRACE_PATH = Path.home() / ".domestique" / "debug_trace.jsonl"
MAX_TRACE_ENTRIES = 1000

#: Environment variable opting into cleartext prompt logging.
RAW_PROMPT_ENV = "DOMESTIQUE_LOG_RAW_PROMPTS"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

#: Keys carrying prompt text. Dropped unless raw logging is opted into.
_PROMPT_TEXT_KEYS = ("prompt", "prompt_fields")

#: Keys carrying whole request bodies, which have no redacted counterpart.
_RAW_DUMP_KEYS = ("raw_body", "request_json", "raw_body_preview")


def raw_prompt_logging_enabled() -> bool:
    """True when the operator explicitly opted into cleartext prompt logging."""
    return os.getenv(RAW_PROMPT_ENV, "").strip().lower() in _TRUTHY


def _dump_length(value: Any) -> int:
    """Size of an omitted payload, so the entry still shows content existed."""
    if isinstance(value, str):
        return len(value)
    try:
        return len(json.dumps(_json_safe(value), ensure_ascii=False))
    except (TypeError, ValueError):
        return len(str(value))


def scrub_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Strip prompt content from a trace entry, keeping decision metadata.

    Prompt text is dropped in every case, whatever the action or detection
    state; ``redacted_prompt`` is the only channel through which prompt content
    survives. Two consequences follow, both intended: a clean ``pass`` yields no
    prompt text, because nothing was masked and a "redacted" copy would be the
    raw prompt verbatim; and a ``block`` that never computed a redacted variant
    likewise yields none.

    Whole-body dumps are replaced with a presence marker and a length, so an
    entry still records that content was there.

    Note the residual limitation: content the detectors *missed* can survive
    inside ``redacted_prompt``, since only detected spans are masked. Redacting
    a log with the same engine whose misses you are debugging cannot do better —
    that is what the opt-in raw mode is for.
    """
    scrubbed = dict(entry)
    for key in _PROMPT_TEXT_KEYS:
        scrubbed.pop(key, None)
    for key in _RAW_DUMP_KEYS:
        if key in scrubbed:
            value = scrubbed.pop(key)
            scrubbed[f"{key}_omitted"] = True
            scrubbed[f"{key}_length"] = _dump_length(value)
    return scrubbed


def append_debug_trace(
    entry: dict[str, Any], *, path: Path | None = None, log_raw: bool | None = None
) -> None:
    """Append one debug trace entry. Never raises into the request path.

    Prompt content is scrubbed unless raw logging is enabled, either explicitly
    via ``log_raw`` or through the ``DOMESTIQUE_LOG_RAW_PROMPTS`` environment
    variable. Passing ``log_raw`` bypasses the environment entirely, which is
    what the tests rely on.
    """
    try:
        raw = raw_prompt_logging_enabled() if log_raw is None else log_raw
        trace_path = path or TRACE_PATH
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "ts": datetime.now(UTC).isoformat(),
            **(entry if raw else scrub_entry(entry)),
            "raw_prompt_logged": raw,
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
