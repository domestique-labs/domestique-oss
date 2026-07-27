"""Tests for pipeline singleton behavior and shared config."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestPipelineConfig:
    """Tests for domestique_app.services.pipeline_config helpers."""

    def test_settings_from_config_balanced(self):
        from domestique_app.services.pipeline_config import settings_from_config

        cfg = {
            "detection_stack": {
                "regex": True, "gliner_pii": True,
                "qwen3_1_7b": True, "gemma4_e2b": False,
            },
        }
        s = settings_from_config(cfg)
        assert s.enable_secret_detection is True
        assert s.enable_pii_detection is False  # Presidio always off
        assert s.enable_gliner is True
        assert s.enable_local_llm is True
        assert s.local_llm_model == "qwen3:1.7b"

    def test_settings_from_config_quality(self):
        from domestique_app.services.pipeline_config import settings_from_config

        cfg = {
            "detection_stack": {
                "regex": True, "gliner_pii": False,
                "qwen3_1_7b": False, "gemma4_e2b": True,
            },
        }
        s = settings_from_config(cfg)
        assert s.enable_pii_detection is False
        assert s.enable_local_llm is True
        assert s.local_llm_model.startswith("gemma4:e2b")

    def test_settings_from_config_regex_only(self):
        from domestique_app.services.pipeline_config import settings_from_config

        cfg = {
            "detection_stack": {
                "regex": True, "gliner_pii": False,
                "qwen3_1_7b": False, "gemma4_e2b": False,
            },
        }
        s = settings_from_config(cfg)
        assert s.enable_secret_detection is True
        assert s.enable_pii_detection is False
        assert s.enable_local_llm is False

    def test_settings_from_config_legacy_cpu(self):
        """legacy-cpu must resolve to llama3.2:1b — the model the installer
        actually pulls for this preset (C4 regression guard)."""
        from domestique_app.services.pipeline_config import settings_from_config

        cfg = {
            "detection_stack": {
                "regex": True, "gliner_pii": False,
                "qwen3_1_7b": False, "gemma4_e2b": False,
                "legacy_cpu": True,
            },
        }
        s = settings_from_config(cfg)
        assert s.enable_local_llm is True
        assert s.local_llm_model == "llama3.2:1b"

    def test_settings_custom_prompt(self):
        from domestique_app.services.pipeline_config import settings_from_config

        cfg = {
            "detection_stack": {"regex": True},
            "classifier_prompt": "My custom prompt",
        }
        s = settings_from_config(cfg)
        assert s.local_llm_system_prompt == "My custom prompt"

    def test_settings_disabled_patterns(self):
        from domestique_app.services.pipeline_config import settings_from_config

        cfg = {
            "detection_stack": {"regex": True},
            "disabled_builtin_patterns": ["phone_number", "email_address"],
        }
        s = settings_from_config(cfg)
        assert "phone_number" in s.disabled_builtin_patterns
        assert "email_address" in s.disabled_builtin_patterns

    def test_config_hash_changes_on_stack_change(self):
        from domestique_app.services.pipeline_config import config_hash

        cfg1 = {"detection_stack": {"regex": True, "qwen3_1_7b": True}}
        cfg2 = {"detection_stack": {"regex": True, "qwen3_1_7b": False}}
        assert config_hash(cfg1) != config_hash(cfg2)

    def test_config_hash_changes_on_prompt_change(self):
        from domestique_app.services.pipeline_config import config_hash

        cfg1 = {"detection_stack": {"regex": True}, "classifier_prompt": "prompt A"}
        cfg2 = {"detection_stack": {"regex": True}, "classifier_prompt": "prompt B"}
        assert config_hash(cfg1) != config_hash(cfg2)

    def test_config_hash_stable_for_same_config(self):
        from domestique_app.services.pipeline_config import config_hash

        cfg = {"detection_stack": {"regex": True}, "classifier_prompt": "test"}
        assert config_hash(cfg) == config_hash(cfg)

    def test_config_hash_ignores_irrelevant_fields(self):
        from domestique_app.services.pipeline_config import config_hash

        cfg1 = {"detection_stack": {"regex": True}, "proxy_port": 8000}
        cfg2 = {"detection_stack": {"regex": True}, "proxy_port": 9999}
        assert config_hash(cfg1) == config_hash(cfg2)

    def test_settings_from_empty_config(self):
        from domestique_app.services.pipeline_config import settings_from_config

        s = settings_from_config({})
        # Defaults: regex only
        assert s.enable_secret_detection is True
        assert s.enable_local_llm is False


@pytest.mark.skip(
    reason="Stale: domestique_app.server.api._detector_cache was refactored away. "
    "Re-point these at the current pipeline-cache implementation before re-enabling."
)
class TestDetectorCacheSingleton:
    """Tests that scan + benchmark share the same pipeline."""

    def test_cache_returns_same_pipeline_on_repeated_calls(self):
        from domestique_app.server.api import _detector_cache

        _detector_cache.invalidate()
        p1, _ = _detector_cache.get()
        p2, _ = _detector_cache.get()
        assert p1 is p2  # same object, not rebuilt

    def test_cache_rebuilds_after_invalidate(self):
        from domestique_app.server.api import _detector_cache

        _detector_cache.invalidate()
        p1, _ = _detector_cache.get()
        _detector_cache.invalidate()
        p2, _ = _detector_cache.get()
        assert p1 is not p2  # new object after invalidate


class TestCrossPlatform:
    """Tests that core pipeline components work without macOS-specific deps."""

    def test_pipeline_config_importable(self):
        from domestique_app.services.pipeline_config import (
            settings_from_config,
            config_hash,
            load_config_dict,
            config_mtime_ns,
        )
        # All should be importable without platform-specific deps
        assert callable(settings_from_config)
        assert callable(config_hash)

    def test_settings_from_config_no_platform_deps(self):
        """settings_from_config should not import AppKit or other macOS deps."""
        from domestique_app.services.pipeline_config import settings_from_config
        s = settings_from_config({"detection_stack": {"regex": True}})
        assert s.enable_secret_detection is True

    def test_httpx_transport_bypass(self):
        """Verify httpx AsyncHTTPTransport is available (cross-platform)."""
        import httpx
        t = httpx.AsyncHTTPTransport()
        assert t is not None

    def test_thread_pool_executor(self):
        """ThreadPoolExecutor works on all platforms."""
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(1) as pool:
            result = pool.submit(lambda: 42).result(timeout=5)
        assert result == 42
