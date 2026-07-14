"""Shared fixtures for the wedge gateway tests.

Defines an in-process mock provider (OpenAI + Anthropic paths) that records the
request bodies it receives and can echo or stream a response, plus a fixture
that serves it and points the gateway's upstream env vars at it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from bench.eval.mock_upstream import serve


class MockProvider:
    """Records received bodies; echoes non-streaming, or emits 3 SSE chunks."""

    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []

    def build_app(self) -> FastAPI:
        app = FastAPI()

        async def handle(request: Request) -> Any:
            body = await request.json()
            self.received.append(body)
            if body.get("stream"):

                async def gen() -> AsyncIterator[bytes]:
                    for i in range(3):
                        yield f"data: chunk{i}\n\n".encode()
                    yield b"data: [DONE]\n\n"

                return StreamingResponse(gen(), media_type="text/event-stream")
            return JSONResponse({"ok": True, "echo": body})

        for path in ("/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/messages"):
            app.add_api_route(path, handle, methods=["POST"])
        return app


@pytest.fixture()
def mock_openai(monkeypatch: pytest.MonkeyPatch) -> Iterator[MockProvider]:
    provider = MockProvider()
    with serve(provider.build_app()) as base:
        monkeypatch.setenv("LLMGUARD_OPENAI_UPSTREAM", base)
        monkeypatch.setenv("LLMGUARD_ANTHROPIC_UPSTREAM", base)
        yield provider
