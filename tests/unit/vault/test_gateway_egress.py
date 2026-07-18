"""Gateway inline detokenization: responses reach the client with originals
restored (M1 end-to-end), streaming included (M5), hallucinated tokens
untouched, and token-free traffic proxied verbatim."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from bench.eval.mock_upstream import serve
from domestique.gateway import create_gateway
from domestique.vault.service import TokenService
from domestique.vault.session import SessionStore


class EchoProvider:
    """Echoes the received (already-redacted) user content back as the
    assistant message — non-streaming JSON or SSE with a mid-token split."""

    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []

    def build_app(self) -> FastAPI:
        app = FastAPI()

        async def handle(request: Request) -> Any:
            body = await request.json()
            self.received.append(body)
            content = body["messages"][-1]["content"]
            if body.get("stream"):
                mid = len(content) // 2

                async def gen() -> AsyncIterator[bytes]:
                    for piece in (content[:mid], content[mid:]):
                        event = {"choices": [{"delta": {"content": piece}}]}
                        yield f"data: {json.dumps(event)}\n\n".encode()
                    yield b"data: [DONE]\n\n"

                return StreamingResponse(gen(), media_type="text/event-stream")
            return JSONResponse(
                {"choices": [{"message": {"role": "assistant", "content": f"echo: {content}"}}]}
            )

        app.add_api_route("/v1/chat/completions", handle, methods=["POST"])

        @app.post("/v1/raw")
        async def raw(request: Request) -> Response:
            return Response(content=b"RAW-MARKER-BYTES", media_type="application/octet-stream")

        return app


def _post(gw: str, content: str, *, stream: bool = False) -> httpx.Response:
    return httpx.post(
        f"{gw}/v1/chat/completions",
        headers={"Authorization": "Bearer sk-test"},
        json={"model": "m", "stream": stream, "messages": [{"role": "user", "content": content}]},
        timeout=30,
    )


def _gateway_with_service(
    monkeypatch: Any, provider: EchoProvider
) -> tuple[Any, TokenService]:
    svc = TokenService(SessionStore(), None)
    app = create_gateway(token_service=svc)
    return app, svc


def test_non_streaming_response_detokenized(monkeypatch: Any) -> None:
    provider = EchoProvider()
    with serve(provider.build_app()) as base:
        monkeypatch.setenv("DOMESTIQUE_OPENAI_UPSTREAM", base)
        app, _svc = _gateway_with_service(monkeypatch, provider)
        with serve(app) as gw:
            resp = _post(gw, "my ssn is 123-45-6789 thanks")

    assert resp.status_code == 200
    upstream_content = provider.received[-1]["messages"][-1]["content"]
    assert "123-45-6789" not in upstream_content  # tokenized on the way out
    body = resp.json()
    assert body["choices"][0]["message"]["content"] == "echo: my ssn is 123-45-6789 thanks"


def test_streaming_sse_detokenized_across_mid_token_split(monkeypatch: Any) -> None:
    provider = EchoProvider()
    with serve(provider.build_app()) as base:
        monkeypatch.setenv("DOMESTIQUE_OPENAI_UPSTREAM", base)
        app, _svc = _gateway_with_service(monkeypatch, provider)
        with serve(app) as gw:
            with httpx.stream(
                "POST",
                f"{gw}/v1/chat/completions",
                headers={"Authorization": "Bearer sk-test"},
                json={
                    "model": "m",
                    "stream": True,
                    "messages": [{"role": "user", "content": "ssn 123-45-6789 end"}],
                },
                timeout=30,
            ) as resp:
                raw = b"".join(resp.iter_bytes())

    text_parts: list[str] = []
    for line in raw.decode().splitlines():
        if line.startswith("data:") and "[DONE]" not in line:
            event = json.loads(line[5:].strip())
            delta = event["choices"][0]["delta"].get("content", "")
            text_parts.append(delta)
    combined = "".join(text_parts)
    assert "123-45-6789" in combined  # restored despite the mid-token SSE split
    assert "[SSN_" not in combined
    assert raw.decode().rstrip().endswith("data: [DONE]")


def test_hallucinated_token_passes_through(monkeypatch: Any) -> None:
    provider = EchoProvider()
    with serve(provider.build_app()) as base:
        monkeypatch.setenv("DOMESTIQUE_OPENAI_UPSTREAM", base)
        app, _svc = _gateway_with_service(monkeypatch, provider)
        with serve(app) as gw:
            # [SSN_7] was never minted; ssn ensures redaction is active
            resp = _post(gw, "ssn 123-45-6789 and fake [SSN_7]")

    content = resp.json()["choices"][0]["message"]["content"]
    assert "[SSN_7]" in content
    assert "123-45-6789" in content


def test_token_free_request_is_proxied_verbatim(monkeypatch: Any) -> None:
    provider = EchoProvider()
    with serve(provider.build_app()) as base:
        monkeypatch.setenv("DOMESTIQUE_OPENAI_UPSTREAM", base)
        app, _svc = _gateway_with_service(monkeypatch, provider)
        with serve(app) as gw:
            resp = _post(gw, "perfectly clean message")

    body = resp.json()
    assert body["choices"][0]["message"]["content"] == "echo: perfectly clean message"
