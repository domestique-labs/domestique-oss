from __future__ import annotations

from llmguard.redact import apply_field_redactions, set_by_path


def test_set_by_path_nested_list_and_dict():
    body = {"messages": [{"content": "old"}]}
    set_by_path(body, "messages.0.content", "new")
    assert body["messages"][0]["content"] == "new"


def test_set_by_path_content_block():
    body = {"messages": [{"content": [{"type": "text", "text": "old"}]}]}
    set_by_path(body, "messages.0.content.0.text", "new")
    assert body["messages"][0]["content"][0]["text"] == "new"


def test_apply_field_redactions_does_not_mutate_input():
    body = {"system": "s", "messages": [{"content": "hi"}]}
    out = apply_field_redactions(
        body, [("system", "[REDACTED]"), ("messages.0.content", "safe")]
    )
    assert out["system"] == "[REDACTED]"
    assert out["messages"][0]["content"] == "safe"
    # original untouched
    assert body["system"] == "s"
    assert body["messages"][0]["content"] == "hi"
