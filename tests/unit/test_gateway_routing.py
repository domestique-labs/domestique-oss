from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from llmguard.gateway import ROUTES, build_wedge_pipeline, create_gateway, upstream_base
from llmguard.models import Action


def test_routes_cover_openai_and_anthropic():
    assert ROUTES["/v1/chat/completions"] == ("openai", "openai_chat")
    assert ROUTES["/v1/completions"] == ("openai", "openai_completions")
    assert ROUTES["/v1/embeddings"] == ("openai", "openai_embeddings")
    assert ROUTES["/v1/messages"] == ("anthropic", "anthropic_messages")


def test_upstream_base_defaults(monkeypatch):
    monkeypatch.delenv("LLMGUARD_OPENAI_UPSTREAM", raising=False)
    monkeypatch.delenv("LLMGUARD_ANTHROPIC_UPSTREAM", raising=False)
    assert upstream_base("openai") == "https://api.openai.com"
    assert upstream_base("anthropic") == "https://api.anthropic.com"


def test_upstream_base_env_override(monkeypatch):
    monkeypatch.setenv("LLMGUARD_OPENAI_UPSTREAM", "http://127.0.0.1:9999")
    assert upstream_base("openai") == "http://127.0.0.1:9999"


def test_build_wedge_pipeline_uses_redact_policy():
    pipe = build_wedge_pipeline()
    result = asyncio.run(pipe.inspect("key AKIAIOSFODNN7EXAMPLE here"))
    assert result.action is Action.REDACT


def test_health_endpoint():
    client = TestClient(create_gateway())
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "healthy"}
