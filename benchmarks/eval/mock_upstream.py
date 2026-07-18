from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import uvicorn
from fastapi import FastAPI, Request

_CANNED_RESPONSE: dict[str, Any] = {
    "id": "chatcmpl-mock",
    "object": "chat.completion",
    "created": 0,
    "model": "gpt-4o-mini",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
    ],
    "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
}


class MockUpstream:
    """OpenAI-compatible echo server: records each request body verbatim."""

    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []

    def build_app(self) -> FastAPI:
        app = FastAPI()

        @app.get("/health")
        async def health() -> dict[str, str]:
            return {"status": "ok"}

        @app.post("/v1/chat/completions")
        async def chat(request: Request) -> dict[str, Any]:
            self.received.append(await request.json())
            return _CANNED_RESPONSE

        return app


@dataclass
class MockUpstreamHandle:
    base_url: str
    mock: MockUpstream


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


@contextmanager
def serve(app: Any) -> Iterator[str]:
    """Run any ASGI app in a background uvicorn thread; yield its root base URL."""
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(250):
        if server.started:
            break
        time.sleep(0.02)
    else:
        raise RuntimeError("ASGI app did not start in time")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@contextmanager
def running_mock() -> Iterator[MockUpstreamHandle]:
    mock = MockUpstream()
    with serve(mock.build_app()) as root:
        yield MockUpstreamHandle(base_url=f"{root}/v1", mock=mock)
