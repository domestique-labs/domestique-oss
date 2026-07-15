"""Provider-aware extraction of scannable prompt text from request bodies.

Returns ``(field_path, text)`` pairs where ``field_path`` is a dot-notation
path into the JSON body (e.g. ``messages.0.content``). Used by the reverse
proxy to know which fields to scan and, after redaction, to write back.
"""

from __future__ import annotations

from typing import Any


def extract_texts(body: dict[str, Any], kind: str) -> list[tuple[str, str]]:
    """Extract scannable ``(field_path, text)`` pairs for the given request kind."""
    if kind == "openai_chat":
        return _openai_messages(body)
    if kind == "openai_completions":
        return _list_or_str(body.get("prompt", ""), "prompt")
    if kind == "openai_embeddings":
        return _list_or_str(body.get("input", ""), "input")
    if kind == "anthropic_messages":
        return _anthropic(body)
    return []


def _openai_messages(body: dict[str, Any]) -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = []
    for i, msg in enumerate(body.get("messages", [])):
        texts.extend(_content(msg.get("content", ""), f"messages.{i}.content"))
    return texts


def _anthropic(body: dict[str, Any]) -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = []
    texts.extend(_content(body.get("system", ""), "system"))
    for i, msg in enumerate(body.get("messages", [])):
        texts.extend(_content(msg.get("content", ""), f"messages.{i}.content"))
    return texts


def _content(content: Any, path: str) -> list[tuple[str, str]]:
    """Handle a field that is either a plain string or a list of content blocks."""
    if isinstance(content, str):
        return [(path, content)] if content else []
    if isinstance(content, list):
        out: list[tuple[str, str]] = []
        for j, part in enumerate(content):
            if isinstance(part, dict) and part.get("type") == "text":
                text = part.get("text", "")
                if isinstance(text, str) and text:
                    out.append((f"{path}.{j}.text", text))
        return out
    return []


def _list_or_str(value: Any, path: str) -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)] if value else []
    if isinstance(value, list):
        return [(f"{path}.{i}", v) for i, v in enumerate(value) if isinstance(v, str) and v]
    return []
