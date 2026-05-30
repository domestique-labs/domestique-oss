"""Integration tests — Full request pipeline (app-level).

Uses the real FastAPI app with mocked upstream to verify end-to-end behavior.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from llmguard.app import create_app
from llmguard.config import Settings
from llmguard.debug_trace import read_debug_trace


@pytest.fixture
def settings() -> Settings:
    return Settings(
        enable_pii_detection=False,  # skip Presidio in CI (no spaCy model)
        enable_secret_detection=True,
        fail_mode="closed",
    )


@pytest.fixture
def client(settings: Settings) -> AsyncClient:
    app = create_app(settings)
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


class TestHealthEndpoint:
    async def test_returns_healthy(self, client: AsyncClient) -> None:
        r = await client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"


class TestBlockBehavior:
    """Requests containing secrets must be blocked (HTTP 403)."""

    async def test_blocks_aws_key(self, client: AsyncClient) -> None:
        r = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "My key: AKIAIOSFODNN7EXAMPLE"}],
            },
        )
        assert r.status_code == 403
        assert r.json()["error"]["type"] == "firewall_block"

    async def test_blocks_private_key(self, client: AsyncClient) -> None:
        r = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "-----BEGIN RSA PRIVATE KEY-----\nMII..."}],
            },
        )
        assert r.status_code == 403

    async def test_blocks_connection_string(self, client: AsyncClient) -> None:
        r = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Use postgresql://admin:pass@db:5432/prod"}],
            },
        )
        assert r.status_code == 403

    async def test_blocks_github_token(self, client: AsyncClient) -> None:
        r = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}],
            },
        )
        assert r.status_code == 403


class TestAllowBehavior:
    """Clean requests must be forwarded to upstream."""

    @patch("llmguard.transport.litellm.acompletion")
    async def test_forwards_clean_request(self, mock_llm: AsyncMock, client: AsyncClient) -> None:
        mock_llm.return_value = AsyncMock(
            model_dump=lambda: {"choices": [{"message": {"content": "Paris"}}], "model": "gpt-4"}
        )

        r = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "What is the capital of France?"}],
            },
        )
        assert r.status_code == 200
        assert "Paris" in r.json()["choices"][0]["message"]["content"]
        mock_llm.assert_called_once()

    @patch("llmguard.transport.litellm.acompletion")
    async def test_writes_debug_trace_for_allowed_request(
        self,
        mock_llm: AsyncMock,
        client: AsyncClient,
        tmp_path: Path,
    ) -> None:
        trace_path = tmp_path / "debug_trace.jsonl"
        mock_llm.return_value = AsyncMock(
            model_dump=lambda: {"choices": [{"message": {"content": "Paris"}}], "model": "gpt-4"}
        )

        with patch("llmguard.debug_trace.TRACE_PATH", trace_path):
            r = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [
                        {"role": "user", "content": "What is the capital of France?"}
                    ],
                },
            )

        entries = read_debug_trace(path=trace_path)
        assert r.status_code == 200
        assert entries[0]["action"] == "allowed"
        assert entries[0]["prompt"] == "What is the capital of France?"


class TestErrorHandling:
    async def test_invalid_json_returns_400(self, client: AsyncClient) -> None:
        r = await client.post(
            "/v1/chat/completions",
            content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert r.status_code == 400

    @patch("llmguard.transport.litellm.acompletion", side_effect=TimeoutError("upstream timeout"))
    async def test_upstream_failure_returns_502_in_closed_mode(
        self, _mock: AsyncMock, client: AsyncClient
    ) -> None:
        r = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
        )
        assert r.status_code == 502
        assert "fail-closed" in r.json()["error"]["message"]
