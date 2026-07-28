"""Integration tests for injecting the in-page block widget into top-level
HTML responses from intercepted LLM hosts. Mocked flows; no real browser.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("mitmproxy")  # requires the [browser-proxy] extra; skip cleanly when absent

from domestique_app.services.inpage_feedback import INJECTION_MARKER
from domestique_app.services.mitm_addon import DomestiqueAddon


@pytest.fixture(autouse=True)
def mock_ctx():
    with patch("domestique_app.services.mitm_addon.ctx") as mock:
        mock.log = MagicMock()
        yield mock


def _html_flow(
    host: str = "chatgpt.com",
    path: str = "/",
    method: str = "GET",
    body: bytes = b"<html><head></head><body>chat</body></html>",
    headers: dict | None = None,
    status_code: int = 200,
):
    flow = MagicMock()
    flow.request.pretty_host = host
    flow.request.path = path
    flow.request.method = method
    flow.response = MagicMock()
    flow.response.status_code = status_code
    flow.response.headers = headers if headers is not None else {"content-type": "text/html"}
    # emulate mitmproxy: .text is the decoded body; .content the bytes
    flow.response.text = body.decode("utf-8")
    flow.response.content = body
    return flow


# The web LLM UIs this feature must surface blocks in (all already in
# INTERCEPTED_DOMAINS). Google Search AI Mode (www.google.com) is intentionally
# NOT here — it needs google.com interception (routes all Google traffic), a
# deliberate scope decision tracked as a SEPARATE follow-up, asserted below.
TARGET_LLM_HOSTS = [
    "chatgpt.com",  # ChatGPT web
    "gemini.google.com",  # Gemini web
    "claude.ai",  # Anthropic Claude
    "chat.qwen.ai",  # Alibaba / Qwen chat
    "grok.com",  # xAI Grok
]


class TestInjectBlockWidget:
    def test_injects_into_llm_html_2xx(self):
        addon = DomestiqueAddon()
        flow = _html_flow()
        addon._maybe_inject_block_widget(flow)
        assert INJECTION_MARKER in flow.response.text

    @pytest.mark.parametrize("host", TARGET_LLM_HOSTS)
    def test_injects_for_each_target_llm_ui(self, host):
        """Every web LLM UI we ship block-feedback for is intercepted AND the
        injection path fires for its top-level HTML page."""
        addon = DomestiqueAddon()
        flow = _html_flow(host=host)
        addon._maybe_inject_block_widget(flow)
        assert INJECTION_MARKER in flow.response.text, f"{host} did not get the widget"

    def test_google_search_ai_mode_host_not_intercepted(self):
        """Google Search AI Mode runs on www.google.com, which is deliberately
        NOT intercepted (separate follow-up). Document that: no injection there."""
        addon = DomestiqueAddon()
        flow = _html_flow(host="www.google.com", path="/search")
        addon._maybe_inject_block_widget(flow)
        assert INJECTION_MARKER not in flow.response.text

    def test_skips_non_llm_host(self):
        addon = DomestiqueAddon()
        flow = _html_flow(host="example.com")
        addon._maybe_inject_block_widget(flow)
        assert INJECTION_MARKER not in flow.response.text

    def test_skips_json_api_response(self):
        addon = DomestiqueAddon()
        flow = _html_flow(
            path="/backend-api/conversation",
            headers={"content-type": "application/json"},
            body=b'{"ok": true}',
        )
        addon._maybe_inject_block_widget(flow)
        assert INJECTION_MARKER not in flow.response.text

    def test_skips_non_2xx(self):
        addon = DomestiqueAddon()
        flow = _html_flow(status_code=404)
        addon._maybe_inject_block_widget(flow)
        assert INJECTION_MARKER not in flow.response.text

    def test_is_idempotent(self):
        addon = DomestiqueAddon()
        flow = _html_flow()
        addon._maybe_inject_block_widget(flow)
        first = flow.response.text
        addon._maybe_inject_block_widget(flow)  # marker present now
        assert flow.response.text.count(INJECTION_MARKER) == 1
        assert flow.response.text == first

    def test_adds_csp_hash_when_policy_present(self):
        addon = DomestiqueAddon()
        flow = _html_flow(
            headers={"content-type": "text/html", "content-security-policy": "script-src 'self'"}
        )
        addon._maybe_inject_block_widget(flow)
        assert "sha256-" in flow.response.headers["content-security-policy"]

    def test_decode_failure_leaves_body_untouched_and_does_not_raise(self):
        addon = DomestiqueAddon()
        flow = _html_flow()
        # Force the injection path to raise when it reads the body.
        type(flow.response).text = property(
            lambda self: (_ for _ in ()).throw(UnicodeDecodeError("utf-8", b"", 0, 1, "boom"))
        )
        # Must not raise, and must not corrupt anything.
        addon._maybe_inject_block_widget(flow)


class TestInjectionIsFailSafe:
    def test_injection_error_does_not_propagate_and_leaves_body_untouched(self):
        """If the injection helper raises, the method must not propagate AND
        must leave the response body/headers exactly as they were (feedback is
        additive; a broken widget never mutates the response)."""
        addon = DomestiqueAddon()
        original_body = "<html><head></head><body>chat</body></html>"
        flow = _html_flow(body=original_body.encode("utf-8"))
        with patch(
            "domestique_app.services.inpage_feedback.inject_widget",
            side_effect=RuntimeError("boom"),
        ):
            addon._maybe_inject_block_widget(flow)  # must not raise
        # Body is untouched: no marker, identical to the original.
        assert INJECTION_MARKER not in flow.response.text
        assert flow.response.text == original_body
        assert "content-security-policy" not in {k.lower() for k in flow.response.headers}

    async def test_response_hook_still_runs_when_injection_raises(self):
        addon = DomestiqueAddon()
        flow = _html_flow()
        with patch(
            "domestique_app.services.inpage_feedback.inject_widget",
            side_effect=RuntimeError("boom"),
        ):
            # response() swallows the injection error and returns without raising.
            await addon.response(flow)
