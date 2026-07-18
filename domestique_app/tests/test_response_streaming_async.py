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

pytest.importorskip("mitmproxy")  # requires the [browser-proxy] extra; skip cleanly when absent

from mitmproxy import http as mitm_http
from mitmproxy.net import encoding as mitm_encoding
from mitmproxy.test import tflow, tutils

from domestique.detectors.registry import Finding, InspectionResult
from domestique.models import Action
from domestique_app.services.mitm_addon import DomestiqueAddon


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
    with patch("domestique_app.services.mitm_addon.ctx") as mock:
        mock.log = MagicMock()
        yield mock


def _addon() -> DomestiqueAddon:
    addon = DomestiqueAddon()
    addon._detector = _StubPipeline()
    return addon


def _flow(
    path: str = "/v1/chat/completions",
    content_type: str = "text/event-stream",
    host: str = "api.openai.com",
    content_encoding: str | None = None,
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
    resp_headers = [(b"content-type", content_type.encode())]
    if content_encoding:
        resp_headers.append((b"content-encoding", content_encoding.encode()))
    flow.response = tutils.tresp(
        headers=mitm_http.Headers(tuple(resp_headers)),
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
        assert flow.metadata["domestique_streamed"] is True

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
        assert bytes(flow.metadata["domestique_response_buf"]) == chunk

    async def test_non_api_content_type_not_streamed(self):
        """Static assets (HTML/JS/CSS) on an LLM host are left at
        mitmproxy's default (non-streamed) handling -- nothing to scan,
        nothing to tee."""
        addon = _addon()
        flow = _flow(content_type="text/html")

        await addon.responseheaders(flow)

        assert flow.response.stream is False
        assert "domestique_streamed" not in flow.metadata


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
        assert "X-Domestique-Alert" not in flow.response.headers

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


class TestResponseScanScopedToConversationEndpoints:
    """responseheaders()/response() must apply the SAME conversation-path
    filter request() uses, so telemetry/polling/asset responses on an LLM
    host are neither streamed-and-teed nor logged as inspected -- this is
    what cuts the ~99-entries-per-interaction noise a real ChatGPT session
    used to generate."""

    async def test_telemetry_endpoint_not_teed_for_scanning(self):
        addon = _addon()
        flow = _flow(path="/backend-api/telemetry/event", content_type="application/json")

        await addon.responseheaders(flow)

        assert flow.response.stream is False
        assert "domestique_streamed" not in flow.metadata

    async def test_sentinel_endpoint_not_teed_for_scanning(self):
        addon = _addon()
        flow = _flow(path="/sentinel/chat-requirements", content_type="application/json")

        await addon.responseheaders(flow)

        assert flow.response.stream is False

    async def test_conversation_endpoint_still_teed(self):
        """Sanity check: the scoping filter doesn't over-exclude --
        genuine conversation endpoints are still streamed and scanned."""
        addon = _addon()
        flow = _flow(path="/backend-api/f/conversation", content_type="text/event-stream")

        await addon.responseheaders(flow)

        assert callable(flow.response.stream)

    async def test_fallback_path_skips_non_conversation_response(self):
        """A response responseheaders() never teed (e.g. a caller that
        attaches content directly, mirroring the non-streamed fallback)
        on a non-conversation path must not be scanned or logged."""
        addon = _addon()
        flow = _flow(path="/telemetry/event", content_type="application/json")
        body = json.dumps({"choices": [{"message": {"content": "SSN 123-45-6789"}}]}).encode()
        flow.response.content = body

        await addon.response(flow)

        assert addon._stats["response_alerts"] == 0
        assert "X-Domestique-Alert" not in flow.response.headers


class TestCompressedResponseIsDecodedBeforeScanning:
    """CRITICAL regression coverage: the async tee captures RAW wire bytes
    off ``flow.response.stream`` -- BEFORE mitmproxy's normal
    auto-decompression, which only fires on ``.content``/``.text`` access
    (never touched on this path, by design, to keep streaming intact). A
    real upstream behind Cloudflare/nginx routinely sends
    Content-Encoding: gzip (or br). Without decoding the teed copy first,
    ``_extract_text_from_body`` hands JSON parsing (and the SSE parser)
    compressed bytes -> JSON parse fails -> falls back to
    ``raw.decode("utf-8", errors="replace")`` -> garbage -> detectors match
    nothing -> a genuine leak reaches the browser with NO log/stats/alert.
    These tests build REAL gzip/br compressed bodies (not mocks) and
    assert the leak is still detected."""

    async def test_gzip_encoded_json_leak_is_detected(self):
        """A gzip Content-Encoding JSON response containing an SSN must
        still be detected by the background scan."""
        addon = _addon()
        flow = _flow(
            path="/backend-api/f/conversation",
            content_type="application/json",
            content_encoding="gzip",
        )
        await addon.responseheaders(flow)

        plaintext = json.dumps(
            {"choices": [{"message": {"content": "Your SSN is 123-45-6789"}}]}
        ).encode()
        gzip_bytes = mitm_encoding.encode(plaintext, "gzip")
        flow.response.stream(gzip_bytes)

        await addon.response(flow)
        await _drain_background_tasks()

        assert addon._stats["response_alerts"] == 1
        assert addon._stats["response_scan_errors"] == 0

    async def test_gzip_encoded_sse_leak_is_detected(self):
        """Same as above but SSE (the real ChatGPT streaming shape),
        gzip-compressed."""
        addon = _addon()
        flow = _flow(content_type="text/event-stream", content_encoding="gzip")
        await addon.responseheaders(flow)

        plaintext = (
            b'data: {"choices":[{"delta":{"content":"SSN 123-45-6789"}}]}\n\ndata: [DONE]\n\n'
        )
        gzip_bytes = mitm_encoding.encode(plaintext, "gzip")
        flow.response.stream(gzip_bytes)

        await addon.response(flow)
        await _drain_background_tasks()

        assert addon._stats["response_alerts"] == 1

    async def test_brotli_encoded_json_leak_is_detected(self):
        """Same regression, brotli (the other very common web encoding)."""
        addon = _addon()
        flow = _flow(
            path="/backend-api/f/conversation",
            content_type="application/json",
            content_encoding="br",
        )
        await addon.responseheaders(flow)

        plaintext = json.dumps(
            {"choices": [{"message": {"content": "SSN on file: 123-45-6789"}}]}
        ).encode()
        br_bytes = mitm_encoding.encode(plaintext, "br")
        flow.response.stream(br_bytes)

        await addon.response(flow)
        await _drain_background_tasks()

        assert addon._stats["response_alerts"] == 1

    async def test_gzip_encoded_clean_response_records_no_alert(self):
        addon = _addon()
        flow = _flow(content_type="application/json", content_encoding="gzip")
        await addon.responseheaders(flow)

        plaintext = json.dumps(
            {"choices": [{"message": {"content": "hello, nice to meet you"}}]}
        ).encode()
        flow.response.stream(mitm_encoding.encode(plaintext, "gzip"))

        await addon.response(flow)
        await _drain_background_tasks()

        assert addon._stats["response_alerts"] == 0
        assert addon._stats["response_scan_errors"] == 0

    async def test_identity_uncompressed_body_still_scanned(self):
        """No Content-Encoding header (or 'identity') -- the common case
        -- must keep working exactly as before: raw bytes used as-is."""
        addon = _addon()
        flow = _flow(content_type="application/json")  # no content_encoding
        await addon.responseheaders(flow)

        plaintext = json.dumps({"choices": [{"message": {"content": "SSN 123-45-6789"}}]}).encode()
        flow.response.stream(plaintext)

        await addon.response(flow)
        await _drain_background_tasks()

        assert addon._stats["response_alerts"] == 1

    async def test_explicit_identity_encoding_header_still_scanned(self):
        addon = _addon()
        flow = _flow(content_type="application/json", content_encoding="identity")
        await addon.responseheaders(flow)

        plaintext = json.dumps({"choices": [{"message": {"content": "SSN 123-45-6789"}}]}).encode()
        flow.response.stream(plaintext)

        await addon.response(flow)
        await _drain_background_tasks()

        assert addon._stats["response_alerts"] == 1

    async def test_undecodable_body_is_recorded_not_silently_allowed(self):
        """Content-Encoding says gzip but the bytes are NOT valid gzip
        (corrupt/truncated, or a server lying about the encoding). This
        must be recorded as un-scannable -- never silently treated as
        'scanned, clean' -- and must NOT raise into the proxied flow."""
        addon = _addon()
        flow = _flow(content_type="application/json", content_encoding="gzip")
        await addon.responseheaders(flow)

        not_actually_gzip = b'{"choices":[{"message":{"content":"SSN 123-45-6789"}}]}'
        flow.response.stream(not_actually_gzip)

        await addon.response(flow)
        await _drain_background_tasks()

        assert addon._stats["response_alerts"] == 0
        assert addon._stats["response_scan_errors"] == 1

    async def test_unknown_encoding_is_recorded_not_silently_allowed(self):
        """An encoding mitmproxy/stdlib codecs don't know how to decode at
        all must also be recorded as un-scannable, not silently dropped."""
        addon = _addon()
        flow = _flow(
            content_type="application/json",
            content_encoding="x-unknown-codec",
        )
        await addon.responseheaders(flow)

        flow.response.stream(b'{"choices":[{"message":{"content":"hello"}}]}')

        await addon.response(flow)
        await _drain_background_tasks()

        assert addon._stats["response_alerts"] == 0
        assert addon._stats["response_scan_errors"] == 1


class TestBackgroundTaskRetention:
    """IMPORTANT regression coverage: response() must keep a strong
    reference to the background scan task it creates. Per the asyncio
    docs, "the event loop only keeps weak references to tasks... without
    a reference held ... a task can disappear mid-execution." A
    fire-and-forget ``asyncio.create_task(...)`` whose return value is
    discarded is exactly that bug -- on the DLP path it means a scan can
    be silently GC'd before it ever runs."""

    async def test_task_is_retained_in_registry_while_running_and_evicted_after(self):
        addon = _addon()
        flow = _flow()
        await addon.responseheaders(flow)
        flow.response.stream(b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n')

        assert addon._background_tasks == set()
        await addon.response(flow)
        # response() returned already, but the task it created must be
        # held live in the registry -- not just floating, unreferenced.
        assert len(addon._background_tasks) == 1
        task = next(iter(addon._background_tasks))
        assert isinstance(task, asyncio.Task)

        await _drain_background_tasks()

        # Once the task completes, the done callback must evict it --
        # the registry isn't allowed to grow unbounded over a long-lived
        # proxy session.
        assert addon._background_tasks == set()

    async def test_multiple_concurrent_scans_are_all_retained(self):
        addon = _addon()
        for _ in range(3):
            flow = _flow()
            await addon.responseheaders(flow)
            flow.response.stream(b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n')
            await addon.response(flow)

        assert len(addon._background_tasks) == 3
        await _drain_background_tasks()
        assert addon._background_tasks == set()
