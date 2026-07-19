"""Configuration persistence layer.

Handles loading from disk, saving to disk, and providing a singleton
accessor for the current configuration state. Thread-safe.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from domestique_app.config.schema import AppConfig

# Canonical storage location
APP_DATA_DIR = Path.home() / ".domestique"
CONFIG_PATH = APP_DATA_DIR / "config.json"


class ConfigStore:
    """Thread-safe configuration store backed by a JSON file.

    Usage:
        config = ConfigStore.load()
        config.proxy_port = 9000
        ConfigStore.save(config)

        # Or read the current in-memory state:
        current = ConfigStore.current()
    """

    _lock = threading.Lock()
    _current: AppConfig | None = None

    @classmethod
    def load(cls) -> AppConfig:
        """Load configuration from disk, creating defaults if absent.

        Returns:
            The loaded (or newly created) AppConfig instance.
        """
        with cls._lock:
            APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

            if CONFIG_PATH.exists():
                try:
                    with open(CONFIG_PATH) as f:
                        data = json.load(f)
                    cls._current = AppConfig.from_dict(data)
                except (json.JSONDecodeError, TypeError, ValueError):
                    # Corrupted config - reset to defaults
                    cls._current = AppConfig()
                    cls._write(cls._current)
            else:
                cls._current = AppConfig()
                cls._write(cls._current)

            return cls._current

    @classmethod
    def save(cls, config: AppConfig) -> None:
        """Persist configuration to disk.

        Args:
            config: The configuration to save.
        """
        with cls._lock:
            cls._current = config
            cls._write(config)

    @classmethod
    def save_dict(cls, data: dict) -> AppConfig:
        """Save from a raw dictionary (used by API endpoints).

        Merges the provided fields into the existing config, preserving
        any fields not included in the update.

        Args:
            data: Raw JSON-parsed dictionary (partial update).

        Returns:
            The validated AppConfig instance.
        """
        # Start from current config to preserve unmentioned fields
        current = cls.current()
        current_dict = current.to_dict()

        # Merge: update only the fields that were provided
        for key, value in data.items():
            if key == "detection_stack" and isinstance(value, dict):
                current_dict.setdefault("detection_stack", {}).update(value)
            else:
                current_dict[key] = value

        # Mark `browser_interception` as user-configured only when the
        # caller's intent is unambiguous -- see
        # AppConfig.browser_interception_configured (audit C6). The
        # dashboard's /api/config save always POSTs the *entire* config
        # object (it round-trips the backend's own to_dict()), so
        # `browser_interception` is present on literally every save, even
        # ones that only touch an unrelated field (a detector toggle, a
        # preset change, a custom pattern edit). Treating mere key
        # PRESENCE as "the user configured this" meant an unrelated save
        # racing ahead of portable's first-run auto-enable thread could
        # permanently freeze `browser_interception_configured=True` with
        # the stale default `browser_interception=False` baked in --
        # silently defeating the "auto-enable exactly once" guarantee
        # without the user ever having chosen to disable interception.
        #
        # Instead, only flip `configured` when there's real evidence of
        # intent:
        #   1. the incoming value actually differs from what's currently
        #      stored (the user/API genuinely changed it), or
        #   2. the payload explicitly sets `browser_interception_configured`
        #      itself (an internal caller stating its intent directly).
        # A same-value resend from an unrelated save satisfies neither and
        # leaves `configured` untouched.
        if "browser_interception" in data and bool(data["browser_interception"]) != bool(
            current.browser_interception
        ):
            current_dict["browser_interception_configured"] = True
        if "browser_interception_configured" in data:
            current_dict["browser_interception_configured"] = bool(
                data["browser_interception_configured"]
            )

        # Same reasoning as browser_interception_configured just above,
        # applied to detection_stack -- see
        # AppConfig.detection_stack_configured. The dashboard's full-object
        # POST includes `detection_stack` on every save (e.g. an unrelated
        # proxy_port change round-trips the whole config), so mere key
        # presence proves nothing about intent; only a field that actually
        # differs from what's currently stored is real signal that the user
        # touched the detection stack. Once set, low-resource hardware's
        # light profile (mitm_addon.py::_light_profile_stack) trusts the
        # on-disk stack as-is instead of down-converting a default-valued
        # heavy tier -- this is what gives a low-resource user a real,
        # supported way to keep (or re-enable) a heavy detector like
        # `qwen3_1_7b`.
        if "detection_stack" in data and isinstance(data["detection_stack"], dict):
            current_stack = current.to_dict().get("detection_stack", {})
            for key, value in data["detection_stack"].items():
                if key not in current_stack or bool(value) != bool(current_stack[key]):
                    current_dict["detection_stack_configured"] = True
                    break
        if "detection_stack_configured" in data:
            current_dict["detection_stack_configured"] = bool(data["detection_stack_configured"])

        config = AppConfig.from_dict(current_dict)
        cls.save(config)
        return config

    @classmethod
    def current(cls) -> AppConfig:
        """Get the current in-memory configuration.

        Loads from disk if not yet initialized.
        """
        if cls._current is None:
            return cls.load()
        return cls._current

    @classmethod
    def _write(cls, config: AppConfig) -> None:
        """Write config to disk (must be called with lock held)."""
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(config.to_dict(), f, indent=2)

    @classmethod
    def reset(cls) -> None:
        """Reset to defaults (useful for testing)."""
        with cls._lock:
            cls._current = None
