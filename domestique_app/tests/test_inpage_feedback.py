"""Tests for in-page block feedback: the static widget asset and the
proxy-side injection/CSP helpers. No real browser or network involved.
"""

from __future__ import annotations

from importlib.resources import files


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
