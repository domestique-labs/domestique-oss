"""Regression guard: the mitm addon's async inspect path must stay awaited.

Context: a live browser-testing session surfaced

    Addon error: 'coroutine' object is not subscriptable
    TypeError: 'coroutine' object is not subscriptable

from a mitmproxy addon's ``request``/``response`` hook. That specific
failure mode is what you get when an ``async def`` function (here,
``DomestiqueAddon._inspect`` or ``DetectorPipeline.inspect``) is called
*without* ``await`` and the resulting coroutine object is then subscripted
(``result["action"]``) as if it were the dict/result it eventually resolves
to.

Investigation into *this* repository's ``app/services/mitm_addon.py`` found
every call site already correctly awaited (``request()`` line ~428,
``response()`` line ~1002, both awaiting ``self._inspect(...)``; ``_inspect()``
itself awaiting ``self._detector.inspect(...)`` at ~line 902; the warmup
thread using ``loop.run_until_complete(...)`` at ~line 230) - see the fix
report for the full trace. No source change was needed here. This test
exists so that if a future edit ever drops one of those ``await`` keywords,
CI catches it immediately as a hard failure (a propagated ``TypeError``)
instead of a silently-swallowed ``RuntimeWarning: coroutine ... was never
awaited`` (which is exactly what happens in the *unrelated* pre-existing
bug in ``app/tests/test_response_scanning.py``, where sync ``def test_...``
methods call ``addon.response(flow)`` without ``await`` - see the fix
report; that file is out of scope for this change).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("mitmproxy")  # requires the [browser-proxy] extra; skip cleanly when absent

from mitmproxy.test import tflow, tutils

from domestique.detectors.registry import Finding, InspectionResult
from domestique.models import Action
from domestique_app.services.mitm_addon import DomestiqueAddon


class _StubPipeline:
    """Deterministic async pipeline double honoring the real contract:
    ``async def inspect(text) -> InspectionResult``.

    Because this is a real coroutine function (not a MagicMock), any call
    site that forgets ``await`` will get back an un-awaited coroutine
    object instead of an ``InspectionResult`` - and subscripting/attribute
    access on it downstream will raise immediately, exactly like the real
    bug did.
    """

    def __init__(
        self,
        action: Action,
        findings: list[Finding] | None = None,
        redacted_text: str | None = None,
    ) -> None:
        self._action = action
        self._findings = findings or []
        self._redacted_text = redacted_text

    async def inspect(self, text: str) -> InspectionResult:
        return InspectionResult(
            action=self._action,
            reason="stub",
            findings=self._findings,
            redacted_text=self._redacted_text,
        )


@pytest.fixture(autouse=True)
def mock_ctx():
    with patch("domestique_app.services.mitm_addon.ctx") as mock:
        mock.log = MagicMock()
        yield mock


def _make_request_flow(body: dict) -> tflow.HTTPFlow:
    req = tutils.treq(
        host="api.openai.com",
        method=b"POST",
        path=b"/v1/chat/completions",
        headers=__import__("mitmproxy").http.Headers(((b"content-type", b"application/json"),)),
        content=json.dumps(body).encode(),
    )
    return tflow.tflow(req=req)


def _addon_with(pipeline: _StubPipeline) -> DomestiqueAddon:
    """Build an addon wired to *pipeline*, and pin the config-change
    fingerprint so ``_inspect()``'s hot-reload check (it rebuilds the real
    pipeline from ``~/.domestique/config.json`` whenever the config's mtime/hash
    differs from what it last saw) does not silently swap our stub back out
    for the real, environment-dependent pipeline.
    """
    from domestique_app.services.pipeline_config import (
        config_hash,
        config_mtime_ns,
        load_config_dict,
    )

    addon = DomestiqueAddon()
    addon._detector = pipeline
    addon._config_mtime = config_mtime_ns()
    addon._config_hash = config_hash(load_config_dict())
    return addon


class TestRequestInspectPath:
    """Drives DomestiqueAddon.request() end-to-end against the real,
    awaited async pipeline contract - no TypeError, correct action."""

    @pytest.mark.asyncio
    async def test_block_sets_403_response_without_typeerror(self):
        pipeline = _StubPipeline(
            action=Action.BLOCK,
            findings=[Finding(detector="stub", category="aws_access_key", confidence=0.99)],
        )
        addon = _addon_with(pipeline)
        flow = _make_request_flow({"messages": [{"role": "user", "content": "my key is AKIA..."}]})

        await addon.request(
            flow
        )  # must not raise TypeError: 'coroutine' object is not subscriptable

        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert body["error"]["type"] == "firewall_block"

    @pytest.mark.asyncio
    async def test_allow_leaves_request_untouched(self):
        pipeline = _StubPipeline(action=Action.ALLOW)
        addon = _addon_with(pipeline)
        flow = _make_request_flow(
            {"messages": [{"role": "user", "content": "hello there, how are you?"}]}
        )

        await addon.request(flow)

        assert flow.response is None  # nothing blocked -> flow passes through untouched

    @pytest.mark.asyncio
    async def test_redact_rewrites_request_body(self):
        pipeline = _StubPipeline(
            action=Action.REDACT,
            findings=[Finding(detector="stub", category="email_address", confidence=0.9)],
            redacted_text="my email is [EMAIL_ADDRESS_REDACTED]",
        )
        addon = _addon_with(pipeline)
        flow = _make_request_flow(
            {"messages": [{"role": "user", "content": "my email is test@example.com"}]}
        )

        await addon.request(flow)

        assert flow.response is None
        new_body = json.loads(flow.request.content)
        assert new_body["messages"][0]["content"] == "my email is [EMAIL_ADDRESS_REDACTED]"


class TestResponseInspectPath:
    """Drives DomestiqueAddon.response() end-to-end - the exact hook whose
    missing ``await`` produced the historical TypeError."""

    @pytest.mark.asyncio
    async def test_block_action_on_response_adds_alert_header_without_typeerror(self):
        pipeline = _StubPipeline(
            action=Action.BLOCK,
            findings=[Finding(detector="stub", category="us_ssn", confidence=0.95)],
        )
        addon = _addon_with(pipeline)
        flow = _make_request_flow({"messages": [{"role": "user", "content": "hi"}]})
        flow.response = tutils.tresp(
            content=json.dumps(
                {"choices": [{"message": {"content": "your ssn is 123-45-6789 for real"}}]}
            ).encode(),
            headers=__import__("mitmproxy").http.Headers(
                ((b"content-type", b"application/json"),)
            ),
        )

        await addon.response(
            flow
        )  # must not raise TypeError: 'coroutine' object is not subscriptable

        assert "X-Domestique-Alert" in flow.response.headers

    @pytest.mark.asyncio
    async def test_allow_action_on_response_leaves_headers_alone(self):
        pipeline = _StubPipeline(action=Action.ALLOW)
        addon = _addon_with(pipeline)
        flow = _make_request_flow({"messages": [{"role": "user", "content": "hi"}]})
        flow.response = tutils.tresp(
            content=json.dumps({"choices": [{"message": {"content": "hello!"}}]}).encode(),
            headers=__import__("mitmproxy").http.Headers(
                ((b"content-type", b"application/json"),)
            ),
        )

        await addon.response(flow)

        assert "X-Domestique-Alert" not in flow.response.headers
