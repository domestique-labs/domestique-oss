"""Unit tests for the configuration module.

Tests cover:
- Schema serialization/deserialization
- Config store load/save/reset
- Graceful handling of corrupted files
- Thread-safety of the singleton store
"""

from __future__ import annotations

import threading
from unittest.mock import patch

from domestique_app.config.schema import AppConfig, DetectionStackConfig
from domestique_app.config.store import ConfigStore

# --- Schema Tests ----------------------------------------------------


class TestDetectionStackConfig:
    """Tests for DetectionStackConfig dataclass."""

    def test_defaults(self):
        stack = DetectionStackConfig()
        assert stack.regex is True
        assert stack.gliner_pii is False
        assert stack.qwen3_1_7b is True
        assert stack.gemma4_e2b is False
        assert stack.legacy_cpu is False

    def test_custom_values(self):
        stack = DetectionStackConfig(regex=False, gemma4_e2b=True)
        assert stack.regex is False
        assert stack.gemma4_e2b is True

    def test_legacy_cpu_flag(self):
        stack = DetectionStackConfig(qwen3_1_7b=False, gemma4_e2b=False, legacy_cpu=True)
        assert stack.legacy_cpu is True
        assert stack.qwen3_1_7b is False
        assert stack.gemma4_e2b is False


class TestAppConfig:
    """Tests for AppConfig dataclass."""

    def test_defaults(self):
        config = AppConfig()
        assert config.proxy_port == 8000
        assert config.proxy_enabled is False
        assert config.fail_mode == "closed"
        assert config.llm_preset == "balanced"
        assert isinstance(config.detection_stack, DetectionStackConfig)

    def test_to_dict_roundtrip(self):
        original = AppConfig(proxy_port=9000, fail_mode="open")
        data = original.to_dict()
        restored = AppConfig.from_dict(data)
        assert restored.proxy_port == 9000
        assert restored.fail_mode == "open"
        assert restored.detection_stack.regex is True

    def test_from_dict_missing_fields(self):
        """Gracefully handle partial configs (e.g., old versions)."""
        data = {"proxy_port": 7777}
        config = AppConfig.from_dict(data)
        assert config.proxy_port == 7777
        assert config.fail_mode == "closed"  # default
        assert config.detection_stack.regex is True  # default

    def test_from_dict_extra_fields_ignored(self):
        """Unknown fields don't crash deserialization."""
        data = {"proxy_port": 8000, "unknown_field": "ignored"}
        config = AppConfig.from_dict(data)
        assert config.proxy_port == 8000

    def test_from_dict_with_detection_stack(self):
        data = {
            "proxy_port": 8080,
            "detection_stack": {
                "regex": False,
                "gliner_pii": True,
                "qwen3_1_7b": False,
            },
        }
        config = AppConfig.from_dict(data)
        assert config.detection_stack.regex is False
        assert config.detection_stack.gliner_pii is True
        assert config.detection_stack.qwen3_1_7b is False
        # Unspecified fields get defaults
        assert config.detection_stack.gemma4_e2b is False

    def test_from_dict_with_legacy_cpu_preset(self):
        """legacy-cpu preset round-trips through llm_preset and detection_stack.legacy_cpu."""
        data = {
            "llm_preset": "legacy-cpu",
            "detection_stack": {
                "regex": True,
                "qwen3_1_7b": False,
                "gemma4_e2b": False,
                "legacy_cpu": True,
            },
        }
        config = AppConfig.from_dict(data)
        assert config.llm_preset == "legacy-cpu"
        assert config.detection_stack.legacy_cpu is True
        assert config.detection_stack.qwen3_1_7b is False
        assert config.detection_stack.gemma4_e2b is False

    def test_from_dict_migrates_stale_legacy_cpu_config(self):
        """Configs written by the OLD installer have llm_preset ==
        'legacy-cpu', detection_stack.qwen3_1_7b == True, and no
        `legacy_cpu` key at all (it didn't exist yet). Loading them must
        flip on legacy_cpu and turn off qwen3_1_7b so the app uses the
        llama3.2:1b CPU fallback the user actually installed, instead of
        silently defaulting legacy_cpu to False and trying to use the
        never-pulled qwen3:1.7b model.
        """
        stale_data = {
            "llm_preset": "legacy-cpu",
            "detection_stack": {
                "regex": True,
                "qwen3_1_7b": True,
                # no "legacy_cpu" key - predates the field entirely.
            },
        }
        config = AppConfig.from_dict(stale_data)
        assert config.llm_preset == "legacy-cpu"
        assert config.detection_stack.legacy_cpu is True
        assert config.detection_stack.qwen3_1_7b is False

    def test_from_dict_does_not_migrate_non_legacy_preset(self):
        """The migration must only touch legacy-cpu configs - other
        presets keep their qwen3_1_7b value untouched."""
        data = {
            "llm_preset": "balanced",
            "detection_stack": {"qwen3_1_7b": True},
        }
        config = AppConfig.from_dict(data)
        assert config.detection_stack.legacy_cpu is False
        assert config.detection_stack.qwen3_1_7b is True

    def test_from_dict_legacy_cpu_migration_is_idempotent(self):
        """A config that already has legacy_cpu=True (post-migration, or
        freshly installed via the new installer) is left alone."""
        data = {
            "llm_preset": "legacy-cpu",
            "detection_stack": {
                "qwen3_1_7b": False,
                "legacy_cpu": True,
            },
        }
        config = AppConfig.from_dict(data)
        assert config.detection_stack.legacy_cpu is True
        assert config.detection_stack.qwen3_1_7b is False


class TestDetectionStackConfiguredMigration:
    """AppConfig.from_dict()'s handling of `detection_stack_configured` for
    pre-existing configs (mirrors browser_interception_configured -- see
    app/tests/test_main_browser_interception_firstrun.py).

    Fix for the permanent-downgrade bug: a config.json written before this
    field existed must be treated as already configured, so the
    hardware-aware light profile (mitm_addon.py) never retroactively
    down-converts (or un-down-converts) a pre-existing install's detection
    stack; only a genuinely fresh install starts unconfigured.
    """

    def test_missing_key_on_preexisting_config_is_treated_as_configured(self):
        stale_data = {"detection_stack": {"regex": True, "qwen3_1_7b": True}}
        config = AppConfig.from_dict(stale_data)
        assert config.detection_stack_configured is True

    def test_present_key_is_left_alone(self):
        data = {
            "detection_stack": {"regex": True},
            "detection_stack_configured": False,
        }
        config = AppConfig.from_dict(data)
        assert config.detection_stack_configured is False

    def test_brand_new_appconfig_defaults_unconfigured(self):
        """A truly fresh install (ConfigStore.load() with no config.json on
        disk) builds AppConfig() directly, bypassing from_dict() entirely --
        confirm the plain dataclass default is what the light-profile
        default-downgrade logic expects."""
        config = AppConfig()
        assert config.detection_stack_configured is False


class TestConfigStoreDetectionStackSaveDict:
    """save_dict()'s configured-flag heuristic for detection_stack (Fix for
    the permanent-downgrade Important finding). Mirrors
    TestConfigStoreBrowserInterceptionSaveDict in
    test_main_browser_interception_firstrun.py: only a real value change (or
    an explicit `detection_stack_configured` override) marks the flag, since
    the dashboard's full-object POST includes `detection_stack` on every
    save regardless of whether the user touched it.
    """

    def setup_method(self):
        ConfigStore.reset()

    def test_unrelated_save_resending_same_stack_does_not_mark_configured(self, tmp_path):
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.load()  # fresh: unconfigured, qwen3_1_7b default True
            result = ConfigStore.save_dict(
                {
                    "detection_stack": {"regex": True, "qwen3_1_7b": True},  # unchanged
                    "proxy_port": 9001,  # the field actually being changed
                }
            )
            assert result.proxy_port == 9001
            assert result.detection_stack_configured is False

    def test_save_dict_marks_configured_on_stack_value_change(self, tmp_path):
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.load()  # fresh: gliner_pii defaults False
            result = ConfigStore.save_dict(
                {
                    "detection_stack": {"gliner_pii": True},
                }
            )
            assert result.detection_stack.gliner_pii is True
            assert result.detection_stack_configured is True

    def test_save_dict_marks_configured_when_qwen3_resaved_true_to_true_is_unrelated(
        self, tmp_path
    ):
        """A bare re-save of qwen3_1_7b: True (no actual change) must NOT
        mark configured on its own -- only an actual value change does."""
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.load()
            result = ConfigStore.save_dict(
                {
                    "detection_stack": {"qwen3_1_7b": True},
                }
            )
            assert result.detection_stack_configured is False

    def test_save_dict_marks_configured_when_qwen3_toggled_off_then_on(self, tmp_path):
        """The real-world re-enable path: a low-resource user whose qwen3
        was auto-downgraded explicitly flips it off then back on in the
        dashboard -- each actual value change marks configured."""
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.load()
            ConfigStore.save_dict({"detection_stack": {"qwen3_1_7b": False}})
            result = ConfigStore.save_dict({"detection_stack": {"qwen3_1_7b": True}})
            assert result.detection_stack.qwen3_1_7b is True
            assert result.detection_stack_configured is True

    def test_save_dict_honors_explicit_configured_flag_in_payload(self, tmp_path):
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.load()
            result = ConfigStore.save_dict(
                {
                    "detection_stack": {"qwen3_1_7b": True},  # unchanged value
                    "detection_stack_configured": True,  # explicit intent
                }
            )
            assert result.detection_stack_configured is True

    def test_save_dict_leaves_configured_alone_when_key_absent(self, tmp_path):
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.load()
            result = ConfigStore.save_dict({"proxy_port": 9001})
            assert result.detection_stack_configured is False


# --- Store Tests -----------------------------------------------------


class TestConfigStore:
    """Tests for ConfigStore persistence layer."""

    def setup_method(self):
        """Reset singleton state before each test."""
        ConfigStore.reset()

    def test_load_creates_default_if_missing(self, tmp_path):
        config_path = tmp_path / "config.json"
        with (
            patch("domestique_app.config.store.CONFIG_PATH", config_path),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            config = ConfigStore.load()
            assert config.proxy_port == 8000
            assert config_path.exists()

    def test_save_and_reload(self, tmp_path):
        config_path = tmp_path / "config.json"
        with (
            patch("domestique_app.config.store.CONFIG_PATH", config_path),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            config = AppConfig(proxy_port=1234)
            ConfigStore.save(config)

            ConfigStore.reset()
            loaded = ConfigStore.load()
            assert loaded.proxy_port == 1234

    def test_corrupted_file_resets_to_default(self, tmp_path):
        config_path = tmp_path / "config.json"
        config_path.write_text("not valid json {{{")
        with (
            patch("domestique_app.config.store.CONFIG_PATH", config_path),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            config = ConfigStore.load()
            assert config.proxy_port == 8000  # default

    def test_save_dict(self, tmp_path):
        config_path = tmp_path / "config.json"
        with (
            patch("domestique_app.config.store.CONFIG_PATH", config_path),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            result = ConfigStore.save_dict({"proxy_port": 5555})
            assert result.proxy_port == 5555
            assert ConfigStore.current().proxy_port == 5555

    def test_current_loads_lazily(self, tmp_path):
        config_path = tmp_path / "config.json"
        with (
            patch("domestique_app.config.store.CONFIG_PATH", config_path),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            config = ConfigStore.current()
            assert config is not None
            assert config.proxy_port == 8000

    def test_thread_safety(self, tmp_path):
        """Concurrent writes don't corrupt state."""
        config_path = tmp_path / "config.json"
        with (
            patch("domestique_app.config.store.CONFIG_PATH", config_path),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.load()
            errors = []

            def writer(port):
                try:
                    ConfigStore.save(AppConfig(proxy_port=port))
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=writer, args=(i,)) for i in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(errors) == 0
            # Final state is valid
            loaded = ConfigStore.current()
            assert 0 <= loaded.proxy_port < 20
