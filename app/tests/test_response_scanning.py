"""Tests for response scanning (bidirectional DLP)."""

from __future__ import annotations

import json
import re
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from app.services.mitm_addon import LLMGuardAddon
from llmguard.detectors.registry import Finding, InspectionResult
from llmguard.models import Action


_TEST_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "us_ssn"),
    (r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}", "openai_key"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key"),
]


class _StubPipeline:
    """Minimal pipeline used in tests - no Presidio / spaCy required.

    Mirrors the contract of ``llmguard.detectors.registry.DetectorPipeline``:
    awaits ``inspect(text)`` and returns an ``InspectionResult`` with
    ``should_block``, ``findings`` (each carrying ``.description``), and
    ``redacted_text``.
    """

    async def inspect(self, text: str) -> InspectionResult:
        findings: list[Finding] = []
        for pattern, category in _TEST_PATTERNS:
            for _ in re.finditer(pattern, text):
                findings.append(
                    Finding(detector="stub", category=category, confidence=0.99)
                )
        if not findings:
            return InspectionResult(action=Action.ALLOW, reason="clean")
        return InspectionResult(
            action=Action.BLOCK,
            reason="stub: sensitive content",
            findings=findings,
        )


@pytest.fixture(autouse=True)
def mock_ctx():
    """Mock mitmproxy.ctx for tests."""
    with patch("app.services.mitm_addon.ctx") as mock:
        mock.log = MagicMock()
        yield mock


@pytest.fixture
def addon():
    """Addon wired to a deterministic in-memory test pipeline."""
    a = LLMGuardAddon()
    a._detector = _StubPipeline()
    return a


def _make_flow(
    host: str = "api.openai.com",
    request_path: str = "/v1/chat/completions",
    response_body: bytes = b"",
    response_headers: dict = None,
    status_code: int = 200,
):
    """Create a mock mitmproxy flow with response."""
    flow = MagicMock()
    flow.request.pretty_host = host
    flow.request.path = request_path
    flow.request.method = "POST"

    flow.response = MagicMock()
    flow.response.content = response_body
    # Use a real dict for headers so we can check writes
    flow.response.headers = response_headers if response_headers is not None else {"content-type": "application/json"}
    flow.response.status_code = status_code
    return flow


class TestResponseScanning:
    """Test the response() hook for detecting leaked sensitive data."""

    async def test_alerts_on_ssn_in_response(self, addon):
        """SSN in LLM response should trigger alert."""
        body = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "The SSN on file is 123-45-6789."
                }
            }]
        }
        flow = _make_flow(response_body=json.dumps(body).encode())

        await addon.response(flow)

        # Should add alert header (not block)
        assert "X-LLMGuard-Alert" in flow.response.headers
        assert "ssn" in flow.response.headers["X-LLMGuard-Alert"].lower()

    async def test_no_alert_on_clean_response(self, addon):
        """Clean response should pass without alert."""
        body = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Hello! How can I help you today?"
                }
            }]
        }
        flow = _make_flow(response_body=json.dumps(body).encode())

        await addon.response(flow)

        # No alert header should be set
        assert "X-LLMGuard-Alert" not in flow.response.headers

    async def test_alerts_on_api_key_in_response(self, addon):
        """API key leak in response should trigger alert."""
        body = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Use this key: sk-proj-abc123def456ghi789jkl012mno345"
                }
            }]
        }
        flow = _make_flow(response_body=json.dumps(body).encode())

        await addon.response(flow)

        assert "X-LLMGuard-Alert" in flow.response.headers

    async def test_alerts_on_private_key_in_response(self, addon):
        """Private key leak should trigger alert."""
        body = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Here's the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."
                }
            }]
        }
        flow = _make_flow(response_body=json.dumps(body).encode())

        await addon.response(flow)

        assert "X-LLMGuard-Alert" in flow.response.headers

    async def test_ignores_non_llm_responses(self, addon):
        """Responses from non-LLM hosts should be ignored."""
        body = {"data": "SSN: 123-45-6789"}
        flow = _make_flow(
            host="example.com",
            response_body=json.dumps(body).encode(),
        )

        await addon.response(flow)

        assert "X-LLMGuard-Alert" not in flow.response.headers

    async def test_ignores_empty_responses(self, addon):
        """Empty responses should be ignored."""
        flow = _make_flow(response_body=b"")
        await addon.response(flow)
        assert "X-LLMGuard-Alert" not in flow.response.headers

    async def test_ignores_small_responses(self, addon):
        """Very small responses should be ignored."""
        flow = _make_flow(response_body=b"ok")
        await addon.response(flow)
        assert "X-LLMGuard-Alert" not in flow.response.headers


class TestSSEResponseExtraction:
    """Test extraction from streaming (SSE) responses."""

    def test_extract_openai_sse(self, addon):
        """Should extract text from OpenAI streaming format."""
        sse_data = (
            'data: {"choices":[{"delta":{"content":"Hello "}}]}\n\n'
            'data: {"choices":[{"delta":{"content":"world"}}]}\n\n'
            'data: [DONE]\n\n'
        )
        flow = _make_flow(
            response_body=sse_data.encode(),
            response_headers={"content-type": "text/event-stream"},
        )

        text = addon._extract_response_content(flow)
        assert text == "Hello world"

    def test_extract_anthropic_sse(self, addon):
        """Should extract text from Anthropic streaming format."""
        sse_data = (
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi "}}\n\n'
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"there"}}\n\n'
        )
        flow = _make_flow(
            response_body=sse_data.encode(),
            response_headers={"content-type": "text/event-stream"},
        )

        text = addon._extract_response_content(flow)
        assert text == "Hi there"


class TestResponseTextExtraction:
    """Test extraction from various JSON response formats."""

    def test_openai_response_format(self, addon):
        body = {
            "choices": [{
                "message": {"role": "assistant", "content": "The answer is 42."}
            }]
        }
        text = addon._extract_response_text(body)
        assert text == "The answer is 42."

    def test_anthropic_response_format(self, addon):
        body = {
            "content": [
                {"type": "text", "text": "Here is my analysis."}
            ]
        }
        text = addon._extract_response_text(body)
        assert text == "Here is my analysis."

    def test_google_response_format(self, addon):
        body = {
            "candidates": [{
                "content": {
                    "parts": [{"text": "Gemini says hello."}]
                }
            }]
        }
        text = addon._extract_response_text(body)
        assert text == "Gemini says hello."

    def test_generic_response_field(self, addon):
        body = {"response": "Some generic LLM output."}
        text = addon._extract_response_text(body)
        assert text == "Some generic LLM output."

    def test_multiple_choices(self, addon):
        body = {
            "choices": [
                {"message": {"content": "Option A"}},
                {"message": {"content": "Option B"}},
            ]
        }
        text = addon._extract_response_text(body)
        assert "Option A" in text
        assert "Option B" in text


class TestResponseAuditIntegration:
    """Test that response alerts create audit events."""

    @patch("app.services.mitm_addon.LLMGuardAddon._emit_audit_event")
    async def test_audit_event_emitted_on_alert(self, mock_emit, addon):
        body = {
            "choices": [{
                "message": {"content": "SSN is 123-45-6789"}
            }]
        }
        flow = _make_flow(response_body=json.dumps(body).encode())
        await addon.response(flow)

        mock_emit.assert_called_once()
        call_kwargs = mock_emit.call_args[1]
        assert call_kwargs["action"] == "response_alert"
        assert call_kwargs["method"] == "RESPONSE"
        assert any("ssn" in r.lower() for r in call_kwargs["reasons"])
