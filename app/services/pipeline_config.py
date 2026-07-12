"""Shared helpers for building detector Settings from the dashboard config.

Used by both the API server process (_DetectorCache) and the mitmdump
addon process to ensure identical pipeline construction semantics.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

_CONFIG_PATH = Path.home() / ".llmguard" / "config.json"


def load_config_dict() -> dict[str, Any]:
    """Read ~/.llmguard/config.json and return as dict."""
    try:
        if _CONFIG_PATH.exists():
            return json.loads(_CONFIG_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def config_hash(config: dict) -> str:
    """Deterministic hash of detector-relevant config fields."""
    relevant = {
        "detection_stack": config.get("detection_stack", {}),
        "classifier_prompt": config.get("classifier_prompt", ""),
        "disabled_builtin_patterns": config.get("disabled_builtin_patterns", []),
        "confidence_threshold": config.get("confidence_threshold", 0.7),
        "gliner_labels": config.get("gliner_labels", []),
        "gliner_threshold": config.get("gliner_threshold", 0.5),
    }
    return hashlib.md5(json.dumps(relevant, sort_keys=True).encode()).hexdigest()


def settings_from_config(config: dict | None = None):
    """Build a llmguard.config.Settings from dashboard config dict.

    Applies detection_stack toggles, classifier_prompt, disabled patterns,
    and LLM model selection. Returns a Settings instance ready for
    create_detector_pipeline().
    """
    from llmguard.config import Settings

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
        from llmguard.detectors.local_llm import _resolve_gemma_model
        settings.local_llm_model = _resolve_gemma_model()
    elif stack.get("qwen3_1_7b"):
        settings.local_llm_model = "qwen3:1.7b"
    elif stack.get("legacy_cpu"):
        settings.local_llm_model = "llama3.2:1b"

    if config.get("classifier_prompt"):
        settings.local_llm_system_prompt = config["classifier_prompt"]

    settings.disabled_builtin_patterns = config.get("disabled_builtin_patterns", [])
    settings.local_llm_timeout_s = max(settings.local_llm_timeout_s, 30.0)

    return settings


def config_mtime_ns() -> int:
    """Return mtime_ns of the config file, or 0 if missing."""
    try:
        return _CONFIG_PATH.stat().st_mtime_ns
    except OSError:
        return 0
