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

from benchmarks.eval.mock_upstream import serve


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


@pytest.fixture(autouse=True)
def _isolate_audit_log(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the wedge audit log at a temp file so tests never touch ~/.domestique.

    Both names are needed and they are not interchangeable:
    ``DOMESTIQUE_AUDIT_LOG_PATH`` is the Settings field ``audit_log_path``
    (env_prefix + field name) and controls where the proxy *writes*;
    ``DOMESTIQUE_AUDIT_LOG`` is read by ``domestique/report.py`` and controls
    where ``report`` *reads*. Setting only the latter — as this fixture did —
    left writes going to the real ``~/.domestique/audit.jsonl`` once the default
    moved there, so running the suite appended to the developer's own audit log.
    """
    monkeypatch.setenv("DOMESTIQUE_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("DOMESTIQUE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))


@pytest.fixture(autouse=True)
def _isolate_taxonomy_store(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the taxonomy store at a temp file so tests never touch ~/.domestique.

    Any non-canonical category reaches ``default_store()`` — via the LLM tier
    coining a term, or ``category_prefix`` resolving a prefix — which otherwise
    reads *and writes* the developer's real ~/.domestique/taxonomy.json. That
    both leaks machine state into assertions and permanently mutates the user's
    config from a test run.
    """
    import domestique.taxonomy_store as taxonomy_store

    monkeypatch.setattr(
        taxonomy_store, "_DEFAULT", taxonomy_store.TaxonomyStore(path=tmp_path / "taxonomy.json")
    )


@pytest.fixture()
def mock_openai(monkeypatch: pytest.MonkeyPatch) -> Iterator[MockProvider]:
    provider = MockProvider()
    with serve(provider.build_app()) as base:
        monkeypatch.setenv("DOMESTIQUE_OPENAI_UPSTREAM", base)
        monkeypatch.setenv("DOMESTIQUE_ANTHROPIC_UPSTREAM", base)
        yield provider
