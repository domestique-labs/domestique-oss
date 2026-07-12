"""Tests for scripts/install.py's preset -> dashboard-config mapping.

Regression coverage for C4: the installer's `legacy-cpu` preset pulls
`llama3.2:1b` via Ollama, and must align the dashboard config
(~/.llmguard/config.json) to a `detection_stack` flag that runtime code
actually maps to `llama3.2:1b` — not the unrelated `qwen3_1_7b` flag,
which every runtime path hardcodes to `qwen3:1.7b`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import install


class TestPresetToStackKey:
    def test_all_presets_have_a_stack_key(self):
        for preset in install.LLM_PRESETS:
            assert preset in install.PRESET_TO_STACK_KEY, (
                f"preset '{preset}' has no PRESET_TO_STACK_KEY entry"
            )

    def test_legacy_cpu_maps_to_its_own_stack_key(self):
        """legacy-cpu must NOT be aliased onto qwen3_1_7b (C4) — that flag
        resolves to model 'qwen3:1.7b' everywhere at runtime, but legacy-cpu
        pulls 'llama3.2:1b'."""
        assert install.PRESET_TO_STACK_KEY["legacy-cpu"] == "legacy_cpu"
        assert install.PRESET_TO_STACK_KEY["legacy-cpu"] != "qwen3_1_7b"

    def test_stack_key_is_in_all_llm_stack_keys(self):
        for stack_key in install.PRESET_TO_STACK_KEY.values():
            assert stack_key in install.ALL_LLM_STACK_KEYS

    def test_legacy_cpu_model_is_llama(self):
        assert install.LLM_PRESETS["legacy-cpu"]["model"] == "llama3.2:1b"


class TestAlignDashboardConfig:
    @pytest.fixture(autouse=True)
    def _isolate_home(self, tmp_path, monkeypatch):
        """Point LLMGUARD_HOME at a temp dir so we don't touch the real
        ~/.llmguard/config.json."""
        monkeypatch.setattr(install, "LLMGUARD_HOME", tmp_path)
        self.cfg_path = tmp_path / "config.json"

    def test_legacy_cpu_sets_legacy_cpu_flag_only(self):
        changed, msg = install.align_dashboard_config("legacy-cpu")
        assert changed is True

        data = json.loads(self.cfg_path.read_text())
        stack = data["detection_stack"]
        assert stack["legacy_cpu"] is True
        assert stack["qwen3_1_7b"] is False
        assert stack["gemma4_e2b"] is False

    def test_legacy_cpu_preset_literal_is_written(self):
        """valid_literals must include 'legacy-cpu' so llm_preset isn't
        silently skipped (part of the C4 fix)."""
        install.align_dashboard_config("legacy-cpu")
        data = json.loads(self.cfg_path.read_text())
        assert data["llm_preset"] == "legacy-cpu"

    def test_minimal_still_sets_qwen3(self):
        """Existing presets must keep behaving exactly as before."""
        install.align_dashboard_config("minimal")
        data = json.loads(self.cfg_path.read_text())
        stack = data["detection_stack"]
        assert stack["qwen3_1_7b"] is True
        assert stack["gemma4_e2b"] is False
        assert stack.get("legacy_cpu", False) is False
        assert data["llm_preset"] == "minimal"

    def test_balanced_still_sets_gemma4(self):
        install.align_dashboard_config("balanced")
        data = json.loads(self.cfg_path.read_text())
        stack = data["detection_stack"]
        assert stack["gemma4_e2b"] is True
        assert stack["qwen3_1_7b"] is False
        assert data["llm_preset"] == "balanced"
