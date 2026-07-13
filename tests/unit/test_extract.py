from __future__ import annotations

from llmguard.extract import extract_texts


def test_openai_chat_string_content():
    body = {"messages": [{"role": "user", "content": "hello"}]}
    assert extract_texts(body, "openai_chat") == [("messages.0.content", "hello")]


def test_openai_chat_content_blocks():
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "block-a"},
                    {"type": "image_url", "image_url": {"url": "x"}},
                ],
            }
        ]
    }
    assert extract_texts(body, "openai_chat") == [("messages.0.content.0.text", "block-a")]


def test_openai_completions_string_and_list():
    assert extract_texts({"prompt": "hi"}, "openai_completions") == [("prompt", "hi")]
    assert extract_texts({"prompt": ["a", "b"]}, "openai_completions") == [
        ("prompt.0", "a"),
        ("prompt.1", "b"),
    ]


def test_openai_embeddings():
    assert extract_texts({"input": "e"}, "openai_embeddings") == [("input", "e")]


def test_anthropic_system_string_and_messages():
    body = {
        "system": "sys-secret",
        "messages": [
            {"role": "user", "content": "hi there"},
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "blk"},
                    {"type": "tool_use", "id": "1"},
                ],
            },
        ],
    }
    assert extract_texts(body, "anthropic_messages") == [
        ("system", "sys-secret"),
        ("messages.0.content", "hi there"),
        ("messages.1.content.0.text", "blk"),
    ]


def test_anthropic_system_block_list():
    body = {"system": [{"type": "text", "text": "sys-blk"}], "messages": []}
    assert extract_texts(body, "anthropic_messages") == [("system.0.text", "sys-blk")]


def test_unknown_kind_returns_empty():
    assert extract_texts({"messages": []}, "nope") == []
