"""Tests for portable first-run auto-enable of browser interception (C6).

`_auto_start_proxies()` must:
  * enable + start browser interception exactly once, on a genuinely
    fresh config (browser_interception_configured is still False), so
    the "paste a secret -> see it blocked" browser demo works without
    any manual API calls;
  * never re-enable it once the flag has been explicitly configured
    (whether that landed on True or False) -- an explicit user "off"
    must stick across restarts.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app import main
from app.config.schema import AppConfig
from app.config.store import ConfigStore


class TestAutoStartProxiesBrowserInterceptionFirstRun:
    def setup_method(self):
        ConfigStore.reset()

    def _patched_store(self, tmp_path):
        return (
            patch("app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("app.config.store.APP_DATA_DIR", tmp_path),
        )

    def _fake_bp(self, *, is_running=False, is_setup=True):
        bp = MagicMock()
        bp.is_running = is_running
        bp.is_setup = is_setup
        bp.PROXY_PORT = 8080
        return bp

    def test_fresh_config_auto_enables_and_starts_browser_proxy(self, tmp_path):
        p1, p2 = self._patched_store(tmp_path)
        with p1, p2:
            ConfigStore.load()  # never-configured, fresh default AppConfig
            bp = self._fake_bp()
            with patch("app.server.api.get_proxy_service", return_value=MagicMock(is_running=False)), \
                 patch("app.server.api.get_browser_proxy_service", return_value=bp):
                main._auto_start_proxies()

            bp.start.assert_called_once()
            saved = ConfigStore.current()
            assert saved.browser_interception is True
            assert saved.browser_interception_configured is True

    def test_explicit_off_is_never_reenabled(self, tmp_path):
        p1, p2 = self._patched_store(tmp_path)
        with p1, p2:
            ConfigStore.load()
            # Simulate a user who explicitly turned it off (e.g. via
            # /api/browser-proxy/stop, which now also sets `configured`).
            config = ConfigStore.current()
            config.browser_interception = False
            config.browser_interception_configured = True
            ConfigStore.save(config)

            bp = self._fake_bp()
            with patch("app.server.api.get_proxy_service", return_value=MagicMock(is_running=False)), \
                 patch("app.server.api.get_browser_proxy_service", return_value=bp):
                main._auto_start_proxies()

            bp.start.assert_not_called()
            saved = ConfigStore.current()
            assert saved.browser_interception is False
            assert saved.browser_interception_configured is True

    def test_explicit_on_is_respected_and_started_without_reconfiguring(self, tmp_path):
        p1, p2 = self._patched_store(tmp_path)
        with p1, p2:
            ConfigStore.load()
            config = ConfigStore.current()
            config.browser_interception = True
            config.browser_interception_configured = True
            ConfigStore.save(config)

            bp = self._fake_bp()
            with patch("app.server.api.get_proxy_service", return_value=MagicMock(is_running=False)), \
                 patch("app.server.api.get_browser_proxy_service", return_value=bp):
                main._auto_start_proxies()

            bp.start.assert_called_once()

    def test_does_not_restart_already_running_browser_proxy(self, tmp_path):
        p1, p2 = self._patched_store(tmp_path)
        with p1, p2:
            ConfigStore.load()  # fresh -> will be auto-enabled
            bp = self._fake_bp(is_running=True)
            with patch("app.server.api.get_proxy_service", return_value=MagicMock(is_running=False)), \
                 patch("app.server.api.get_browser_proxy_service", return_value=bp):
                main._auto_start_proxies()

            bp.start.assert_not_called()

    def test_browser_proxy_start_failure_is_non_fatal(self, tmp_path):
        p1, p2 = self._patched_store(tmp_path)
        with p1, p2:
            ConfigStore.load()
            bp = self._fake_bp()
            bp.start.side_effect = RuntimeError("mitmdump exploded")
            with patch("app.server.api.get_proxy_service", return_value=MagicMock(is_running=False)), \
                 patch("app.server.api.get_browser_proxy_service", return_value=bp):
                main._auto_start_proxies()  # must not raise


class TestBrowserInterceptionConfiguredMigration:
    """AppConfig.from_dict()'s handling of pre-existing configs (schema.py)."""

    def test_missing_key_on_preexisting_config_is_treated_as_configured(self):
        """A config.json written before this field existed (any
        pre-fix install) must NOT be treated as a fresh install -- that
        would risk silently re-enabling browser interception for a user
        who had explicitly turned it off under the old code."""
        stale_data = {"browser_interception": False}
        config = AppConfig.from_dict(stale_data)
        assert config.browser_interception is False
        assert config.browser_interception_configured is True

    def test_missing_key_with_interception_already_on_stays_on_and_configured(self):
        stale_data = {"browser_interception": True}
        config = AppConfig.from_dict(stale_data)
        assert config.browser_interception is True
        assert config.browser_interception_configured is True

    def test_present_key_is_left_alone(self):
        data = {"browser_interception": True, "browser_interception_configured": False}
        config = AppConfig.from_dict(data)
        assert config.browser_interception_configured is False

    def test_brand_new_appconfig_defaults_unconfigured(self):
        """A truly fresh install (ConfigStore.load() with no config.json on
        disk) builds AppConfig() directly, bypassing from_dict() entirely --
        confirm the plain dataclass default is what first-run logic expects."""
        config = AppConfig()
        assert config.browser_interception_configured is False


class TestConfigStoreBrowserInterceptionSaveDict:
    def setup_method(self):
        ConfigStore.reset()

    def test_save_dict_marks_configured_when_browser_interception_present(self, tmp_path):
        with patch("app.config.store.CONFIG_PATH", tmp_path / "config.json"), \
             patch("app.config.store.APP_DATA_DIR", tmp_path):
            ConfigStore.load()
            result = ConfigStore.save_dict({"browser_interception": False})
            assert result.browser_interception is False
            assert result.browser_interception_configured is True

    def test_save_dict_leaves_configured_alone_when_key_absent(self, tmp_path):
        with patch("app.config.store.CONFIG_PATH", tmp_path / "config.json"), \
             patch("app.config.store.APP_DATA_DIR", tmp_path):
            ConfigStore.load()
            result = ConfigStore.save_dict({"proxy_port": 9001})
            assert result.browser_interception_configured is False
