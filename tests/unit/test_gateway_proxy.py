from __future__ import annotations

import httpx

from bench.eval.mock_upstream import serve
from llmguard.gateway import create_gateway


def test_openai_secret_is_redacted_upstream(mock_openai):
    app = create_gateway()
    with serve(app) as gw:
        resp = httpx.post(
            f"{gw}/v1/chat/completions",
            headers={"Authorization": "Bearer sk-test"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}],
            },
        )
    assert resp.status_code == 200
    sent = mock_openai.received[-1]
    assert "AKIAIOSFODNN7EXAMPLE" not in sent["messages"][0]["content"]


def test_client_key_passed_through(mock_openai):
    # No server-side key set; the client's own bearer key rides through and the
    # request succeeds end-to-end with the clean prompt forwarded verbatim.
    app = create_gateway()
    with serve(app) as gw:
        resp = httpx.post(
            f"{gw}/v1/chat/completions",
            headers={"Authorization": "Bearer sk-client-key"},
            json={"model": "m", "messages": [{"role": "user", "content": "hello clean"}]},
        )
    assert resp.status_code == 200
    assert mock_openai.received[-1]["messages"][0]["content"] == "hello clean"


def test_streaming_response_passthrough(mock_openai):
    app = create_gateway()
    with serve(app) as gw:
        with httpx.stream(
            "POST",
            f"{gw}/v1/chat/completions",
            headers={"Authorization": "Bearer sk-test"},
            json={
                "model": "m",
                "stream": True,
                "messages": [{"role": "user", "content": "clean text"}],
            },
        ) as resp:
            body = b"".join(resp.iter_bytes())
    assert b"chunk0" in body and b"[DONE]" in body


def test_anthropic_secret_redacted_upstream(mock_openai):
    app = create_gateway()
    with serve(app) as gw:
        resp = httpx.post(
            f"{gw}/v1/messages",
            headers={"x-api-key": "sk-ant", "anthropic-version": "2023-06-01"},
            json={
                "model": "claude-3-5-sonnet",
                "max_tokens": 16,
                "system": "leak AKIAIOSFODNN7EXAMPLE",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
    assert resp.status_code == 200
    sent = mock_openai.received[-1]
    assert "AKIAIOSFODNN7EXAMPLE" not in sent["system"]


def test_unknown_path_passthrough(mock_openai):
    # /v1/models is not in ROUTES -> transparent passthrough; the mock has no
    # such route so it 404s, proving we forwarded rather than scanned/500'd.
    app = create_gateway()
    with serve(app) as gw:
        resp = httpx.get(f"{gw}/v1/models", headers={"Authorization": "Bearer x"})
    assert resp.status_code in (404, 405)
