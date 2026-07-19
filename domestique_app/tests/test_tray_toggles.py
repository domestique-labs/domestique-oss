"""Tests for the decoupled system-tray toggles.

The tray used to expose one all-or-nothing switch that stopped BOTH the
API proxy and the browser proxy. It now has two independent menu items;
each handler must invoke only its own callback, and the state setter must
track the two services separately.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pytest.importorskip("pystray")

from domestique_app.services.tray import SystemTray


def _make_tray():
    api = MagicMock()
    browser = MagicMock()
    quit_ = MagicMock()
    tray = SystemTray(on_toggle_api=api, on_toggle_browser=browser, on_quit=quit_)
    return tray, api, browser, quit_


class TestIndependentToggles:
    def test_api_toggle_only_fires_api_callback(self):
        tray, api, browser, _ = _make_tray()
        tray._handle_toggle_api(None, None)
        api.assert_called_once()
        browser.assert_not_called()

    def test_browser_toggle_only_fires_browser_callback(self):
        tray, api, browser, _ = _make_tray()
        tray._handle_toggle_browser(None, None)
        browser.assert_called_once()
        api.assert_not_called()

    def test_quit_fires_quit_callback(self):
        tray, api, browser, quit_ = _make_tray()
        tray._handle_quit(None, None)
        quit_.assert_called_once()
        api.assert_not_called()
        browser.assert_not_called()


class TestStateTracking:
    def test_set_states_tracks_services_separately(self):
        tray, *_ = _make_tray()
        tray.set_states(api_active=True, browser_active=False)
        assert tray._api_active is True
        assert tray._browser_active is False
        assert "API Proxy: on" in tray._tooltip()
        assert "Browser: off" in tray._tooltip()

    def test_set_active_back_compat_sets_both(self):
        tray, *_ = _make_tray()
        tray.set_active(True)
        assert tray._api_active is True
        assert tray._browser_active is True
