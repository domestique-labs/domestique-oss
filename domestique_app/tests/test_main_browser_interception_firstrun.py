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

from domestique_app import main
from domestique_app.config.schema import AppConfig
from domestique_app.config.store import ConfigStore


class TestAutoStartProxiesBrowserInterceptionFirstRun:
    def setup_method(self):
        ConfigStore.reset()

    def _patched_store(self, tmp_path):
        return (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
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
            with (
                patch(
                    "domestique_app.server.api.get_proxy_service",
                    return_value=MagicMock(is_running=False),
                ),
                patch("domestique_app.server.api.get_browser_proxy_service", return_value=bp),
            ):
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
            with (
                patch(
                    "domestique_app.server.api.get_proxy_service",
                    return_value=MagicMock(is_running=False),
                ),
                patch("domestique_app.server.api.get_browser_proxy_service", return_value=bp),
            ):
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
            with (
                patch(
                    "domestique_app.server.api.get_proxy_service",
                    return_value=MagicMock(is_running=False),
                ),
                patch("domestique_app.server.api.get_browser_proxy_service", return_value=bp),
            ):
                main._auto_start_proxies()

            bp.start.assert_called_once()

    def test_does_not_restart_already_running_browser_proxy(self, tmp_path):
        p1, p2 = self._patched_store(tmp_path)
        with p1, p2:
            ConfigStore.load()  # fresh -> will be auto-enabled
            bp = self._fake_bp(is_running=True)
            with (
                patch(
                    "domestique_app.server.api.get_proxy_service",
                    return_value=MagicMock(is_running=False),
                ),
                patch("domestique_app.server.api.get_browser_proxy_service", return_value=bp),
            ):
                main._auto_start_proxies()

            bp.start.assert_not_called()

    def test_browser_proxy_start_failure_is_non_fatal(self, tmp_path):
        p1, p2 = self._patched_store(tmp_path)
        with p1, p2:
            ConfigStore.load()
            bp = self._fake_bp()
            bp.start.side_effect = RuntimeError("mitmdump exploded")
            with (
                patch(
                    "domestique_app.server.api.get_proxy_service",
                    return_value=MagicMock(is_running=False),
                ),
                patch("domestique_app.server.api.get_browser_proxy_service", return_value=bp),
            ):
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
    """save_dict()'s configured-flag heuristic (audit C6 review Important #1).

    The dashboard's saveConfigToBackend() POSTs the *entire* config object
    (round-tripped through the backend's own to_dict()), so
    `browser_interception` is present in the payload on literally every
    save -- including ones that only touch an unrelated field. Marking
    `configured` on mere key PRESENCE meant such an unrelated save could
    race ahead of portable's first-run auto-enable thread and permanently
    freeze `configured=True` with the stale `browser_interception=False`
    default, silently defeating the "auto-enable exactly once" guarantee.
    The fix requires the incoming value to actually DIFFER from what's
    stored (real intent), or an explicit `browser_interception_configured`
    override.
    """

    def setup_method(self):
        ConfigStore.reset()

    def test_unrelated_save_resending_same_value_does_not_mark_configured(self, tmp_path):
        """Bug scenario: fresh config (False/unconfigured); an unrelated
        save re-sends the current, unchanged `browser_interception` value
        (as the dashboard's full-object POST always does) -- this must NOT
        be treated as the user configuring interception."""
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.load()  # fresh: browser_interception=False, configured=False
            result = ConfigStore.save_dict(
                {
                    "browser_interception": False,  # unchanged -- just along for the ride
                    "proxy_port": 9001,  # the field the user actually meant to change
                }
            )
            assert result.proxy_port == 9001
            assert result.browser_interception is False
            assert result.browser_interception_configured is False

    def test_save_dict_marks_configured_on_value_change_false_to_true(self, tmp_path):
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.load()  # False, unconfigured
            result = ConfigStore.save_dict({"browser_interception": True})
            assert result.browser_interception is True
            assert result.browser_interception_configured is True

    def test_save_dict_marks_configured_on_value_change_true_to_false(self, tmp_path):
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.load()
            config = ConfigStore.current()
            config.browser_interception = True
            config.browser_interception_configured = True
            ConfigStore.save(config)

            result = ConfigStore.save_dict({"browser_interception": False})
            assert result.browser_interception is False
            assert result.browser_interception_configured is True

    def test_save_dict_honors_explicit_configured_flag_in_payload(self, tmp_path):
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.load()  # fresh: unconfigured
            result = ConfigStore.save_dict(
                {
                    "browser_interception": False,  # unchanged value
                    "browser_interception_configured": True,  # explicit intent
                }
            )
            assert result.browser_interception is False
            assert result.browser_interception_configured is True

    def test_save_dict_leaves_configured_alone_when_key_absent(self, tmp_path):
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.load()
            result = ConfigStore.save_dict({"proxy_port": 9001})
            assert result.browser_interception_configured is False


class TestBrowserInterceptionRaceRegression:
    """End-to-end regression covering the exact race the review flagged:
    an unrelated dashboard save landing between first-run bootstrap and
    the auto-enable thread must not suppress the one-time auto-enable,
    and an explicit user "off" must still persist across a reload."""

    def setup_method(self):
        ConfigStore.reset()

    def _patched_store(self, tmp_path):
        return (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        )

    def _fake_bp(self, *, is_running=False, is_setup=True):
        bp = MagicMock()
        bp.is_running = is_running
        bp.is_setup = is_setup
        bp.PROXY_PORT = 8080
        return bp

    def test_unrelated_save_before_firstrun_thread_does_not_block_autoenable(self, tmp_path):
        p1, p2 = self._patched_store(tmp_path)
        with p1, p2:
            ConfigStore.load()  # brand-new install: fresh, unconfigured

            # An unrelated dashboard save (e.g. toggling a detector) races
            # ahead of the auto-enable thread, resending the current,
            # untouched browser_interception=False as part of its
            # full-object POST.
            ConfigStore.save_dict(
                {
                    "detection_stack": {"gliner_pii": True},
                    "browser_interception": False,
                }
            )
            assert ConfigStore.current().browser_interception_configured is False

            bp = self._fake_bp()
            with (
                patch(
                    "domestique_app.server.api.get_proxy_service",
                    return_value=MagicMock(is_running=False),
                ),
                patch("domestique_app.server.api.get_browser_proxy_service", return_value=bp),
            ):
                main._auto_start_proxies()

            bp.start.assert_called_once()
            saved = ConfigStore.current()
            assert saved.browser_interception is True
            assert saved.browser_interception_configured is True

    def test_explicit_off_persists_across_reload_despite_unrelated_saves(self, tmp_path):
        p1, p2 = self._patched_store(tmp_path)
        with p1, p2:
            ConfigStore.load()
            # User explicitly turns interception off via the direct API.
            config = ConfigStore.current()
            config.browser_interception = False
            config.browser_interception_configured = True
            ConfigStore.save(config)

            # Followed by unrelated dashboard saves that keep resending
            # the same (now correctly "off") value.
            ConfigStore.save_dict({"proxy_port": 9002, "browser_interception": False})
            ConfigStore.save_dict({"llm_preset": "quality", "browser_interception": False})

            # Simulate app restart: reload from disk and re-run auto-start.
            ConfigStore.reset()
            ConfigStore.load()
            bp = self._fake_bp()
            with (
                patch(
                    "domestique_app.server.api.get_proxy_service",
                    return_value=MagicMock(is_running=False),
                ),
                patch("domestique_app.server.api.get_browser_proxy_service", return_value=bp),
            ):
                main._auto_start_proxies()

            bp.start.assert_not_called()
            saved = ConfigStore.current()
            assert saved.browser_interception is False
            assert saved.browser_interception_configured is True
