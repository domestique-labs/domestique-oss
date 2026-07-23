"""Tests for in-page block feedback: the static widget asset and the
proxy-side injection/CSP helpers. No real browser or network involved.
"""

from __future__ import annotations

from importlib.resources import files

from domestique_app.services import inpage_feedback as fb


def _widget_source() -> str:
    return (files("domestique_app") / "assets" / "inpage_widget.js").read_text(encoding="utf-8")


class TestWidgetAsset:
    def test_asset_exists_and_nonempty(self):
        src = _widget_source()
        assert len(src) > 200

    def test_reads_only_firewall_block(self):
        src = _widget_source()
        assert "firewall_block" in src

    def test_uses_shadow_dom_for_isolation(self):
        assert "attachShadow" in _widget_source()

    def test_is_idempotent(self):
        # Guards against double-install when injected more than once.
        assert "__domestiqueWidgetInstalled" in _widget_source()

    def test_is_inert_no_eval(self):
        src = _widget_source()
        assert "eval(" not in src
        assert "new Function(" not in src

    def test_wraps_fetch_and_xhr(self):
        src = _widget_source()
        assert "fetch" in src
        assert "XMLHttpRequest" in src


class TestInjectWidget:
    def test_injects_after_head(self):
        html = "<html><head><title>x</title></head><body>hi</body></html>"
        out = fb.inject_widget(html)
        assert out is not None
        # script sits after the <head> open tag, before the page's own <title>
        head_idx = out.index("<head>")
        script_idx = out.index(fb.INJECTION_MARKER)
        title_idx = out.index("<title>")
        assert head_idx < script_idx < title_idx
        assert "firewall_block" in out  # the widget body is inlined

    def test_head_with_attributes_still_matches(self):
        html = '<html><head lang="en"><title>x</title></head><body></body></html>'
        out = fb.inject_widget(html)
        assert out is not None
        assert fb.INJECTION_MARKER in out

    def test_falls_back_to_before_body_close_when_no_head(self):
        html = "<html><body>hi</body></html>"
        out = fb.inject_widget(html)
        assert out is not None
        assert out.index(fb.INJECTION_MARKER) < out.index("</body>")

    def test_returns_none_when_no_injection_point(self):
        assert fb.inject_widget("just some text, no html tags") is None

    def test_idempotent_returns_none_when_already_injected(self):
        html = "<html><head></head><body></body></html>"
        once = fb.inject_widget(html)
        assert once is not None
        assert fb.inject_widget(once) is None  # marker present -> skip

    def test_hash_is_stable_base64_sha256(self):
        js = fb.load_widget_js()
        h1 = fb.compute_script_hash(js)
        h2 = fb.compute_script_hash(js)
        assert h1 == h2
        assert "sha256-" not in h1  # bare digest, prefix added by the CSP layer
        assert len(h1) == 44 and h1.endswith("=")  # base64 of a 32-byte digest
