"""Tests for the browser interceptor's hardware-aware detection profile.

Context: on weak hardware (no usable GPU and/or low RAM), building the full
detector stack (GLiNER, local-LLM tier) can be very slow or OOM the addon
process. ``app/services/mitm_addon.py`` gates those heavy tiers behind a
hardware check reused from ``scripts/install.py`` (no new hardware-detection
code): on low-resource machines it auto-selects a light, regex-only profile
unless the user explicitly opted into a heavier detector.

Covered here:
- ``_detect_low_resource_hardware`` threshold logic (RAM / VRAM) and its
  fail-toward-capable behavior on detection errors.
- ``_light_profile_stack`` -- the pure stack-down-conversion logic,
  including the "explicit opt-in survives" rule.
- ``LLMGuardAddon._resolve_hardware_profile`` / ``_init_detector`` wiring:
  capable machines get the config-respecting stack unchanged; low-resource
  machines get the light stack; explicit heavy opt-ins are honored either
  way; the auto-light choice is logged (never silent).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.services.mitm_addon import (
    LLMGuardAddon,
    _detect_low_resource_hardware,
    _light_profile_stack,
)


@pytest.fixture(autouse=True)
def mock_ctx():
    with patch("app.services.mitm_addon.ctx") as mock:
        mock.log = MagicMock()
        yield mock


# --- _detect_low_resource_hardware ------------------------------------------


class TestDetectLowResourceHardware:
    def test_low_ram_and_no_gpu_is_low_resource(self):
        with patch("scripts.install.detect_total_ram_gb", return_value=4.0), \
             patch("scripts.install.detect_gpu", return_value=(None, 0.0)):
            assert _detect_low_resource_hardware() is True

    def test_no_gpu_alone_is_low_resource_even_with_plenty_of_ram(self):
        """A capable-RAM machine with no discrete GPU still gets the light
        profile -- in-process model loading on pure CPU is slow to bind
        even when it wouldn't OOM."""
        with patch("scripts.install.detect_total_ram_gb", return_value=32.0), \
             patch("scripts.install.detect_gpu", return_value=(None, 0.0)):
            assert _detect_low_resource_hardware() is True

    def test_low_ram_alone_is_low_resource_even_with_a_gpu(self):
        with patch("scripts.install.detect_total_ram_gb", return_value=4.0), \
             patch("scripts.install.detect_gpu", return_value=("Some GPU", 4.0)):
            assert _detect_low_resource_hardware() is True

    def test_capable_machine_is_not_low_resource(self):
        with patch("scripts.install.detect_total_ram_gb", return_value=32.0), \
             patch("scripts.install.detect_gpu", return_value=("NVIDIA RTX 4090", 24.0)):
            assert _detect_low_resource_hardware() is False

    def test_detection_failure_fails_toward_capable(self):
        """A detection glitch must never silently narrow security coverage
        -- fail toward the full/capable stack, not the light one."""
        with patch("scripts.install.detect_total_ram_gb", side_effect=RuntimeError("boom")):
            assert _detect_low_resource_hardware() is False


# --- _light_profile_stack -----------------------------------------------------


class TestLightProfileStack:
    def test_empty_stack_becomes_regex_only(self):
        light = _light_profile_stack({})
        assert light["regex"] is True
        assert light["gliner_pii"] is False
        assert light["openai_privacy_filter"] is False
        assert light["gemma4_e2b"] is False
        assert light["legacy_cpu"] is False

    def test_default_qwen3_true_is_not_treated_as_explicit(self):
        """qwen3_1_7b defaults True in the dataclass -- a bare True value
        (with nothing else set) is indistinguishable from a never-touched
        install, so the light profile turns it off."""
        light = _light_profile_stack({"regex": True, "qwen3_1_7b": True})
        assert light["qwen3_1_7b"] is False

    def test_explicit_gliner_opt_in_survives(self):
        light = _light_profile_stack({"regex": True, "gliner_pii": True})
        assert light["gliner_pii"] is True
        # Nothing else the user didn't ask for gets pulled along.
        assert light["qwen3_1_7b"] is False
        assert light["gemma4_e2b"] is False

    def test_explicit_legacy_cpu_opt_in_survives(self):
        light = _light_profile_stack({"regex": True, "legacy_cpu": True, "qwen3_1_7b": False})
        assert light["legacy_cpu"] is True

    def test_explicit_gemma_opt_in_survives(self):
        light = _light_profile_stack({"gemma4_e2b": True})
        assert light["gemma4_e2b"] is True

    def test_qwen3_explicitly_disabled_stays_disabled(self):
        light = _light_profile_stack({"qwen3_1_7b": False})
        assert light["qwen3_1_7b"] is False

    def test_regex_explicitly_disabled_is_respected(self):
        """Not really a 'heavy' tier, but the stack conversion must not
        silently flip regex back on if the user turned it off."""
        light = _light_profile_stack({"regex": False})
        assert light["regex"] is False


# --- LLMGuardAddon wiring ------------------------------------------------


def _patched_pipeline(settings_holder: list):
    """Return a create_detector_pipeline stand-in that records the Settings
    it was called with and returns a cheap fake pipeline."""

    def _create(settings=None):
        settings_holder.append(settings)
        pipeline = MagicMock()
        pipeline._detectors = []
        return pipeline

    return _create


class TestAddonHardwareProfileWiring:
    def test_capable_machine_respects_full_config(self):
        addon = LLMGuardAddon()
        addon._hardware_is_low_resource = lambda: False
        settings_seen: list = []

        with patch(
            "app.services.pipeline_config.load_config_dict",
            return_value={"detection_stack": {"regex": True, "qwen3_1_7b": True}},
        ), patch(
            "llmguard.detectors.registry.create_detector_pipeline",
            side_effect=_patched_pipeline(settings_seen),
        ):
            addon._init_detector()

        assert len(settings_seen) == 1
        assert settings_seen[0].enable_local_llm is True
        assert addon._light_profile_active is False

    def test_low_resource_machine_gets_light_stack_by_default(self):
        addon = LLMGuardAddon()
        addon._hardware_is_low_resource = lambda: True
        settings_seen: list = []

        with patch(
            "app.services.pipeline_config.load_config_dict",
            return_value={"detection_stack": {"regex": True, "qwen3_1_7b": True}},
        ), patch(
            "llmguard.detectors.registry.create_detector_pipeline",
            side_effect=_patched_pipeline(settings_seen),
        ):
            addon._init_detector()

        assert len(settings_seen) == 1
        assert settings_seen[0].enable_secret_detection is True
        assert settings_seen[0].enable_gliner is False
        assert settings_seen[0].enable_local_llm is False  # qwen3 default turned off
        assert addon._light_profile_active is True

    def test_low_resource_machine_honors_explicit_heavy_opt_in(self):
        addon = LLMGuardAddon()
        addon._hardware_is_low_resource = lambda: True
        settings_seen: list = []

        with patch(
            "app.services.pipeline_config.load_config_dict",
            return_value={"detection_stack": {"regex": True, "gliner_pii": True}},
        ), patch(
            "llmguard.detectors.registry.create_detector_pipeline",
            side_effect=_patched_pipeline(settings_seen),
        ):
            addon._init_detector()

        assert settings_seen[0].enable_gliner is True, (
            "explicit dashboard opt-in must be honored even on low-resource "
            "hardware -- the auto-light profile is a default, not a hard cap"
        )

    def test_low_resource_light_profile_is_logged_not_silent(self):
        addon = LLMGuardAddon()
        addon._hardware_is_low_resource = lambda: True

        with patch(
            "app.services.pipeline_config.load_config_dict",
            return_value={"detection_stack": {"regex": True, "qwen3_1_7b": True}},
        ), patch(
            "llmguard.detectors.registry.create_detector_pipeline",
            side_effect=_patched_pipeline([]),
        ):
            addon._init_detector()

        from app.services.mitm_addon import ctx as patched_ctx

        warn_messages = [call.args[0] for call in patched_ctx.log.warn.call_args_list]
        assert any("light profile" in msg for msg in warn_messages), (
            "auto-selecting the light profile must be logged clearly, not silent"
        )

    def test_capable_machine_logs_nothing_extra(self):
        addon = LLMGuardAddon()
        addon._hardware_is_low_resource = lambda: False

        with patch(
            "app.services.pipeline_config.load_config_dict",
            return_value={"detection_stack": {"regex": True, "qwen3_1_7b": True}},
        ), patch(
            "llmguard.detectors.registry.create_detector_pipeline",
            side_effect=_patched_pipeline([]),
        ):
            addon._init_detector()

        from app.services.mitm_addon import ctx as patched_ctx

        assert patched_ctx.log.warn.call_count == 0

    def test_hardware_resource_check_is_cached_per_process(self):
        addon = LLMGuardAddon()
        calls = []

        def _tracked():
            calls.append(1)
            return False

        with patch("app.services.mitm_addon._detect_low_resource_hardware", side_effect=_tracked):
            addon._hardware_is_low_resource()
            addon._hardware_is_low_resource()
            addon._hardware_is_low_resource()

        assert len(calls) == 1
