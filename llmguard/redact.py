"""Write redacted text back into nested request-body fields by dot-path."""

from __future__ import annotations

import copy
from typing import Any


def set_by_path(obj: Any, path: str, value: str) -> None:
    """Set a value in a nested dict/list using a dot-notation path."""
    parts = path.split(".")
    for part in parts[:-1]:
        obj = obj[int(part)] if part.isdigit() else obj[part]
    last = parts[-1]
    if last.isdigit():
        obj[int(last)] = value
    else:
        obj[last] = value


def apply_field_redactions(
    body: dict[str, Any], redactions: list[tuple[str, str]]
) -> dict[str, Any]:
    """Return a deep copy of *body* with each ``(field_path, redacted_text)`` written in."""
    out = copy.deepcopy(body)
    for field_path, redacted_text in redactions:
        set_by_path(out, field_path, redacted_text)
    return out
