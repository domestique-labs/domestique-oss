"""Live end-to-end integration tests against REAL provider APIs.

These are skipped by default (keeping the unit suite hermetic and CI green).
They run only when you export a real key, and prove the wedge redacts a planted
secret *on the wire* through a real model — deterministically, because the
assertion is the ABSENCE of the secret in the response (a model that only ever
saw ``[AWS_ACCESS_KEY_REDACTED]`` cannot echo the raw key back).

Run the OpenAI door (defaults to api.openai.com / gpt-4o-mini):

    LLMGUARD_LIVE_OPENAI_KEY=sk-... \
      python -m pytest tests/integration/test_live_providers.py -v

Point the OpenAI door at any OpenAI-compatible host (Groq / OpenRouter /
Bedrock-openai-compat) instead:

    LLMGUARD_LIVE_OPENAI_KEY=... \
    LLMGUARD_OPENAI_UPSTREAM=https://api.groq.com/openai \
    LLMGUARD_LIVE_OPENAI_MODEL=llama-3.1-8b-instant \
      python -m pytest tests/integration/test_live_providers.py -k openai -v

Run the Anthropic door (api.anthropic.com / claude-haiku-4-5):

    LLMGUARD_LIVE_ANTHROPIC_KEY=sk-ant-... \
      python -m pytest tests/integration/test_live_providers.py -k anthropic -v

Cost per full run is a fraction of a cent (tiny prompts, max_tokens small).
"""

from __future__ import annotations

import json
import os

import httpx
import pytest

from bench.eval.mock_upstream import serve
from llmguard.gateway import create_gateway

# The planted secret is a canonical AWS access key id -> category aws_access_key
# (regex confidence 0.99), which the wedge policy REDACTS. If it appears in a
# model's echo, redaction failed on the wire.
_SECRET = "AKIAIOSFODNN7EXAMPLE"
_ECHO_PROMPT = f"Echo the following line back verbatim, output nothing else:\ntoken {_SECRET} done"

_OPENAI_KEY = os.environ.get("LLMGUARD_LIVE_OPENAI_KEY")
_ANTHROPIC_KEY = os.environ.get("LLMGUARD_LIVE_ANTHROPIC_KEY")
_OPENAI_MODEL = os.environ.get("LLMGUARD_LIVE_OPENAI_MODEL", "gpt-4o-mini")
_ANTHROPIC_MODEL = os.environ.get("LLMGUARD_LIVE_ANTHROPIC_MODEL", "claude-haiku-4-5")

_TIMEOUT = 30.0

_needs_openai = pytest.mark.skipif(
    not _OPENAI_KEY, reason="set LLMGUARD_LIVE_OPENAI_KEY to run the live OpenAI-door test"
)
_needs_anthropic = pytest.mark.skipif(
    not _ANTHROPIC_KEY, reason="set LLMGUARD_LIVE_ANTHROPIC_KEY to run the live Anthropic-door test"
)


@_needs_openai
def test_openai_door_redacts_live():
    with serve(create_gateway()) as gw:
        resp = httpx.post(
            f"{gw}/v1/chat/completions",
            headers={"Authorization": f"Bearer {_OPENAI_KEY}"},
            json={
                "model": _OPENAI_MODEL,
                "temperature": 0,
                "max_tokens": 40,
                "messages": [{"role": "user", "content": _ECHO_PROMPT}],
            },
            timeout=_TIMEOUT,
        )
    assert resp.status_code == 200, resp.text
    text = json.dumps(resp.json())
    assert _SECRET not in text, f"secret leaked to the model / response: {text}"


@_needs_openai
def test_openai_door_streaming_live():
    received = b""
    with serve(create_gateway()) as gw:
        with httpx.stream(
            "POST",
            f"{gw}/v1/chat/completions",
            headers={"Authorization": f"Bearer {_OPENAI_KEY}"},
            json={
                "model": _OPENAI_MODEL,
                "temperature": 0,
                "max_tokens": 40,
                "stream": True,
                "messages": [{"role": "user", "content": _ECHO_PROMPT}],
            },
            timeout=_TIMEOUT,
        ) as resp:
            assert resp.status_code == 200
            for chunk in resp.iter_bytes():
                received += chunk
    assert b"data:" in received  # SSE framing arrived
    assert _SECRET.encode() not in received, "secret leaked in the streamed response"


@_needs_anthropic
def test_anthropic_door_redacts_live():
    with serve(create_gateway()) as gw:
        resp = httpx.post(
            f"{gw}/v1/messages",
            headers={"x-api-key": _ANTHROPIC_KEY, "anthropic-version": "2023-06-01"},
            json={
                "model": _ANTHROPIC_MODEL,
                "max_tokens": 40,
                "temperature": 0,
                "messages": [{"role": "user", "content": _ECHO_PROMPT}],
            },
            timeout=_TIMEOUT,
        )
    assert resp.status_code == 200, resp.text
    text = json.dumps(resp.json())
    assert _SECRET not in text, f"secret leaked to the model / response: {text}"


@_needs_anthropic
def test_anthropic_door_streaming_live():
    received = b""
    with serve(create_gateway()) as gw:
        with httpx.stream(
            "POST",
            f"{gw}/v1/messages",
            headers={"x-api-key": _ANTHROPIC_KEY, "anthropic-version": "2023-06-01"},
            json={
                "model": _ANTHROPIC_MODEL,
                "max_tokens": 40,
                "temperature": 0,
                "stream": True,
                "messages": [{"role": "user", "content": _ECHO_PROMPT}],
            },
            timeout=_TIMEOUT,
        ) as resp:
            assert resp.status_code == 200
            for chunk in resp.iter_bytes():
                received += chunk
    assert b"event:" in received or b"data:" in received  # Anthropic SSE framing
    assert _SECRET.encode() not in received, "secret leaked in the streamed response"
