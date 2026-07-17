"""Shim parity: scripts/install.py must keep exposing the installer API.

scripts/install.py is now a thin alias of domestique.setup_wizard; every
attribute the old module had (and that tests/tooling monkeypatch) must
still resolve, and patching through the shim must patch the real
implementation.
"""

from __future__ import annotations

import domestique.setup_wizard as wizard
from scripts import install

_PUBLIC_API = [
    # constants
    "ROOT",
    "DOMESTIQUE_HOME",
    "PRESET_TO_STACK_KEY",
    "ALL_LLM_STACK_KEYS",
    "FEATURE_EXTRAS",
    "LLM_PRESETS",
    # detection
    "detect_total_ram_gb",
    "detect_gpu",
    "detect_gpu_free_vram_gb",
    "detect_ollama",
    "detect_existing_ollama_models",
    "recommend_preset",
    # prompts
    "prompt_yes_no",
    "prompt_choice",
    # execution
    "run",
    "install_extras",
    "download_spacy_model",
    "cache_huggingface_model",
    "pull_ollama_model",
    "align_dashboard_config",
    # main flow
    "parse_args",
    "parse_features_arg",
    "banner",
    "section",
    "report_environment",
    "pick_features",
    "pick_preset",
    "confirm_plan",
    "main",
    # private helpers patched by existing suites
    "_wait_for_command",
    "_auto_install_ollama",
    "_ensure_linux_venv",
    "_input",
    # modules the suites patch via patch.object(install.X, ...)
    "platform",
    "subprocess",
    "os",
    "sys",
    "Path",
]


def test_shim_is_the_wizard_module():
    """The alias means monkeypatching install.* patches the real module."""
    assert install is wizard


def test_all_legacy_attributes_resolve():
    missing = [name for name in _PUBLIC_API if not hasattr(install, name)]
    assert not missing, f"scripts.install lost attributes: {missing}"


def test_presets_and_stack_keys_unchanged():
    assert set(install.LLM_PRESETS) == {"minimal", "balanced", "quality", "legacy-cpu"}
    assert install.PRESET_TO_STACK_KEY["legacy-cpu"] == "legacy_cpu"
    assert install.ALL_LLM_STACK_KEYS == ("gemma4_e2b", "qwen3_1_7b", "legacy_cpu")
