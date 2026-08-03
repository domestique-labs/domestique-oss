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

    def test_header_element_is_not_mistaken_for_head(self):
        # A page with no <head> but a <header> must NOT inject into <header>;
        # it must fall back to before </body>.
        html = "<html><body><header>site</header><main>hi</main></body></html>"
        out = fb.inject_widget(html)
        assert out is not None
        marker_idx = out.index(fb.INJECTION_MARKER)
        assert marker_idx > out.index("</header>")  # after the header, not inside it
        assert marker_idx < out.index("</body>")  # via the body-close fallback

    def test_hash_is_stable_base64_sha256(self):
        js = fb.load_widget_js()
        h1 = fb.compute_script_hash(js)
        h2 = fb.compute_script_hash(js)
        assert h1 == h2
        assert "sha256-" not in h1  # bare digest, prefix added by the CSP layer
        assert len(h1) == 44 and h1.endswith("=")  # base64 of a 32-byte digest


class TestRelaxCsp:
    HASH = "abc123def456ghi789jkl012mno345pqr678stu901v="  # 44-char base64 stand-in

    def test_appends_hash_to_existing_script_src(self):
        policy = "default-src 'self'; script-src 'self' https://cdn.example.com"
        out = fb.relax_csp_for_injection(policy, self.HASH)
        assert f"'sha256-{self.HASH}'" in out
        # existing sources preserved
        assert "'self'" in out
        assert "https://cdn.example.com" in out
        # other directives untouched
        assert "default-src 'self'" in out

    def test_derives_script_src_from_default_src_when_absent(self):
        policy = "default-src 'self' https://x.example.com"
        out = fb.relax_csp_for_injection(policy, self.HASH)
        assert "script-src" in out
        assert f"'sha256-{self.HASH}'" in out
        assert "'self'" in out  # inherited from default-src
        # default-src is still present and unmodified
        assert "default-src 'self' https://x.example.com" in out

    def test_no_change_when_no_script_or_default_directive(self):
        policy = "img-src 'self'; style-src 'self'"
        out = fb.relax_csp_for_injection(policy, self.HASH)
        assert out == policy  # scripts weren't restricted; nothing to relax

    def test_blank_policy_returned_unchanged(self):
        assert fb.relax_csp_for_injection("", self.HASH) == ""

    def test_does_not_duplicate_hash_if_already_present(self):
        policy = f"script-src 'self' 'sha256-{self.HASH}'"
        out = fb.relax_csp_for_injection(policy, self.HASH)
        assert out.count(f"'sha256-{self.HASH}'") == 1

    def test_unsafe_inline_script_src_left_unchanged(self):
        # Adding a hash would disable 'unsafe-inline' and break the page's own
        # inline scripts; the widget already runs under 'unsafe-inline'.
        policy = "script-src 'self' 'unsafe-inline'"
        assert fb.relax_csp_for_injection(policy, self.HASH) == policy

    def test_unsafe_inline_default_src_left_unchanged(self):
        policy = "default-src 'self' 'unsafe-inline'"
        assert fb.relax_csp_for_injection(policy, self.HASH) == policy

    def test_nonce_present_still_gets_hash(self):
        # A nonce already disables 'unsafe-inline', and our inline widget has no
        # nonce, so it needs the hash to run.
        policy = "script-src 'self' 'nonce-abc123'"
        out = fb.relax_csp_for_injection(policy, self.HASH)
        assert f"'sha256-{self.HASH}'" in out

    def test_script_src_elem_gets_hash(self):
        # script-src-elem overrides script-src for element scripts; the widget
        # must be allowed there.
        policy = "script-src 'self'; script-src-elem 'self'"
        out = fb.relax_csp_for_injection(policy, self.HASH)
        # hash present on BOTH governing directives
        elem = [d for d in out.split(";") if "script-src-elem" in d][0]
        assert f"'sha256-{self.HASH}'" in elem

    def test_script_src_elem_only_gets_hash(self):
        policy = "script-src-elem 'self'"
        out = fb.relax_csp_for_injection(policy, self.HASH)
        assert "script-src-elem" in out
        assert f"'sha256-{self.HASH}'" in out
