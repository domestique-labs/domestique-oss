"""Tests for async, non-blocking response scanning (browser-mode perf fix).

Context: ``response()`` used to call ``flow.response.content``, which
forces mitmproxy to buffer the ENTIRE response before releasing anything
to the browser -- breaking ChatGPT's token-by-token streaming and making
replies feel like they "took too long." The fix:

  * ``responseheaders()`` installs ``flow.response.stream`` (a tee
    callable) for LLM-host, JSON/SSE responses, so mitmproxy forwards
    each body chunk to the browser AS IT ARRIVES, never buffering.
  * The tee also copies each chunk into an in-memory buffer.
  * ``response()`` (which mitmproxy calls after the streamed body has
    already reached the browser) kicks off a background
    ``asyncio.create_task`` to scan the teed copy and returns immediately
    -- it never awaits the scan, so it can never block.
  * A detected leak can only be logged/alerted (stats, request log, audit
    trail) -- it cannot block or modify a response that already left.

The outbound prompt/request DLP path (``request()``) is unchanged: it
still blocks synchronously, before forwarding, fail-closed.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest
from mitmproxy import http as mitm_http
from mitmproxy.test import tflow, tutils

from app.services.mitm_addon import LLMGuardAddon
from llmguard.detectors.registry import Finding, InspectionResult
from llmguard.models import Action


class _StubPipeline:
    """Deterministic async pipeline double: BLOCK iff an SSN is present."""

    async def inspect(self, text: str) -> InspectionResult:
        if "123-45-6789" in text:
            return InspectionResult(
                action=Action.BLOCK,
                reason="stub: sensitive content",
                findings=[Finding(detector="stub", category="us_ssn", confidence=0.95)],
            )
        return InspectionResult(action=Action.ALLOW, reason="clean")


@pytest.fixture(autouse=True)
def mock_ctx():
    with patch("app.services.mitm_addon.ctx") as mock:
        mock.log = MagicMock()
        yield mock


def _addon() -> LLMGuardAddon:
    addon = LLMGuardAddon()
    addon._detector = _StubPipeline()
    return addon


def _flow(
    path: str = "/v1/chat/completions",
    content_type: str = "text/event-stream",
    host: str = "api.openai.com",
):
    """A real mitmproxy flow (not a MagicMock) so responseheaders()'s
    ``flow.response.stream = ...`` assignment and mitmproxy's own
    ``Message.stream`` default (``False``) behave exactly as they would
    against real traffic."""
    req = tutils.treq(
        host=host,
        method=b"POST",
        path=path.encode(),
        headers=mitm_http.Headers(((b"content-type", b"application/json"),)),
        content=b'{"messages":[{"role":"user","content":"hi"}]}',
    )
    flow = tflow.tflow(req=req)
    flow.response = tutils.tresp(
        headers=mitm_http.Headers(((b"content-type", content_type.encode()),)),
        content=b"",
    )
    return flow


async def _drain_background_tasks():
    pending = [t for t in asyncio.all_tasks() if not t.done() and t is not asyncio.current_task()]
    if pending:
        await asyncio.gather(*pending)


class TestResponseStreamsThrough:
    """responseheaders() must install a streaming tee instead of letting
    mitmproxy buffer -- this is what keeps token streaming intact."""

    async def test_installs_stream_for_sse_conversation_response(self):
        addon = _addon()
        flow = _flow(content_type="text/event-stream")

        await addon.responseheaders(flow)

        assert callable(flow.response.stream)
        assert flow.metadata["llmguard_streamed"] is True

    async def test_installs_stream_for_json_response(self):
        addon = _addon()
        flow = _flow(content_type="application/json")

        await addon.responseheaders(flow)

        assert callable(flow.response.stream)

    async def test_tee_returns_chunk_unmodified_and_immediately(self):
        """The browser must get the exact same bytes back with no
        transformation and no wait for scanning to finish."""
        addon = _addon()
        flow = _flow()
        await addon.responseheaders(flow)

        chunk = b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
        out = flow.response.stream(chunk)

        assert out == chunk
        assert bytes(flow.metadata["llmguard_response_buf"]) == chunk

    async def test_non_api_content_type_not_streamed(self):
        """Static assets (HTML/JS/CSS) on an LLM host are left at
        mitmproxy's default (non-streamed) handling -- nothing to scan,
        nothing to tee."""
        addon = _addon()
        flow = _flow(content_type="text/html")

        await addon.responseheaders(flow)

        assert flow.response.stream is False
        assert "llmguard_streamed" not in flow.metadata


class TestAsyncScanSurfacesLeakWithoutBlocking:
    """response() must return immediately (never await the scan) and the
    background task must still surface a detected leak afterward."""

    async def test_response_hook_does_not_block_on_the_scan(self):
        addon = _addon()
        flow = _flow()
        await addon.responseheaders(flow)
        leak_chunk = b'data: {"choices":[{"delta":{"content":"SSN 123-45-6789"}}]}\n\n'
        flow.response.stream(leak_chunk)

        await addon.response(flow)

        # response() returned already -- the scan is still pending, so
        # nothing has been recorded yet. If response() awaited the scan
        # inline, this would already be 1.
        assert addon._stats["response_alerts"] == 0

    async def test_background_scan_surfaces_leak_to_stats_and_log(self):
        addon = _addon()
        flow = _flow()
        await addon.responseheaders(flow)
        leak_chunk = b'data: {"choices":[{"delta":{"content":"SSN 123-45-6789"}}]}\n\n'
        flow.response.stream(leak_chunk)

        await addon.response(flow)
        await _drain_background_tasks()

        assert addon._stats["response_alerts"] == 1

    async def test_clean_response_records_no_alert(self):
        addon = _addon()
        flow = _flow()
        await addon.responseheaders(flow)
        flow.response.stream(b'data: {"choices":[{"delta":{"content":"hi there"}}]}\n\n')

        await addon.response(flow)
        await _drain_background_tasks()

        assert addon._stats["response_alerts"] == 0

    async def test_leak_does_not_modify_the_already_streamed_response(self):
        """No header injection, no status-code change, no body rewrite on
        the async path -- the response already left; a leak can only be
        logged, never blocked or altered."""
        addon = _addon()
        flow = _flow()
        await addon.responseheaders(flow)
        flow.response.stream(b'data: {"choices":[{"delta":{"content":"SSN 123-45-6789"}}]}\n\n')

        await addon.response(flow)
        await _drain_background_tasks()

        assert flow.response.status_code == 200
        assert "X-LLMGuard-Alert" not in flow.response.headers

    async def test_background_scan_failure_is_swallowed(self):
        """A background scan must never raise into the proxied flow --
        the flow already completed from the browser's perspective."""
        addon = _addon()
        addon._detector = MagicMock()
        addon._detector.inspect = MagicMock(side_effect=RuntimeError("boom"))
        flow = _flow()
        await addon.responseheaders(flow)
        flow.response.stream(b'data: {"choices":[{"delta":{"content":"hello world"}}]}\n\n')

        await addon.response(flow)
        await _drain_background_tasks()  # must not raise


class TestRequestDlpUnchanged:
    """The outbound prompt/request path must still block synchronously,
    before forwarding, fail-closed -- untouched by the response-side
    async change."""

    async def test_block_action_still_blocks_synchronously_before_forwarding(self):
        addon = _addon()
        req = tutils.treq(
            host="api.openai.com",
            method=b"POST",
            path=b"/v1/chat/completions",
            headers=mitm_http.Headers(((b"content-type", b"application/json"),)),
            content=json.dumps(
                {"messages": [{"role": "user", "content": "my ssn is 123-45-6789"}]}
            ).encode(),
        )
        flow = tflow.tflow(req=req)

        await addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert body["error"]["type"] == "firewall_block"

    async def test_allow_action_leaves_request_untouched(self):
        addon = _addon()
        req = tutils.treq(
            host="api.openai.com",
            method=b"POST",
            path=b"/v1/chat/completions",
            headers=mitm_http.Headers(((b"content-type", b"application/json"),)),
            content=json.dumps(
                {"messages": [{"role": "user", "content": "hello there"}]}
            ).encode(),
        )
        flow = tflow.tflow(req=req)

        await addon.request(flow)

        assert flow.response is None
