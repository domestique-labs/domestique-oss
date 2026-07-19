"""Shared helpers for building detector Settings from the dashboard config.

Used by both the API server process (_DetectorCache) and the mitmdump
addon process to ensure identical pipeline construction semantics.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from domestique.config import Settings

_CONFIG_PATH = Path.home() / ".domestique" / "config.json"


def load_config_dict() -> dict[str, Any]:
    """Read ~/.domestique/config.json and return as dict."""
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
    # md5 used purely as a config-change cache key (fast, non-security digest).
    return hashlib.md5(json.dumps(relevant, sort_keys=True).encode()).hexdigest()  # noqa: S324


def settings_from_config(config: dict | None = None) -> Settings:
    """Build a domestique.config.Settings from dashboard config dict.

    Delegates to domestique.config_loader (single source of truth for the
    detection_stack -> Settings mapping; app->domestique is the allowed
    import direction). Kept here for backward-compatible imports from domestique_app
    code, and so this module's own load_config_dict() remains the default
    source when no config dict is passed in.
    """
    from domestique.config_loader import settings_from_config as _core

    if config is None:
        config = load_config_dict()
    return _core(config)


def config_mtime_ns() -> int:
    """Return mtime_ns of the config file, or 0 if missing."""
    try:
        return _CONFIG_PATH.stat().st_mtime_ns
    except OSError:
        return 0
