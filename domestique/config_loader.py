"""Load ~/.domestique/config.json and map it to a domestique Settings.

This is the single source of truth for the detection-stack -> Settings
mapping. domestique_app/services/pipeline_config.py delegates here (domestique_app->domestique is
the allowed import direction), so the browser dashboard and the CLI demo
build identical Settings from the same config.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from domestique.config import Settings

DOMESTIQUE_HOME = Path.home() / ".domestique"


def load_config_dict() -> dict[str, Any]:
    """Read ~/.domestique/config.json; return {} if absent or invalid."""
    path = DOMESTIQUE_HOME / "config.json"
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return data
    except (OSError, ValueError):
        return {}


def settings_from_config(config: dict[str, Any] | None = None) -> Settings:
    """Build a Settings from a dashboard config dict (or the on-disk config)."""
    if config is None:
        config = load_config_dict()

    settings = Settings()
    stack = config.get("detection_stack", {})

    settings.enable_secret_detection = stack.get("regex", True)
    settings.enable_pii_detection = False  # Presidio off — GLiNER handles PII better
    settings.enable_gliner = stack.get("gliner_pii", False)
    settings.enable_semantic_detection = False  # Semantic heuristics add noise

    # GLiNER customization
    if config.get("gliner_labels"):
        settings.gliner_labels = config["gliner_labels"]
    if config.get("gliner_threshold") is not None:
        settings.gliner_threshold = config["gliner_threshold"]

    llm_on = (
        stack.get("gemma4_e2b", False)
        or stack.get("qwen3_1_7b", False)
        or stack.get("legacy_cpu", False)
    )
    settings.enable_local_llm = llm_on
    if stack.get("gemma4_e2b"):
        from domestique.detectors.local_llm import _resolve_gemma_model

        settings.local_llm_model = _resolve_gemma_model()
    elif stack.get("qwen3_1_7b"):
        settings.local_llm_model = "qwen3:1.7b"
    elif stack.get("legacy_cpu"):
        settings.local_llm_model = "llama3.2:1b"

    if config.get("classifier_prompt"):
        settings.local_llm_system_prompt = config["classifier_prompt"]

    preset = config.get("llm_preset")
    if preset in ("minimal", "balanced", "quality", "legacy-cpu"):
        settings.local_llm_preset = preset

    settings.disabled_builtin_patterns = config.get("disabled_builtin_patterns", [])
    settings.local_llm_timeout_s = max(settings.local_llm_timeout_s, 30.0)

    return settings
