"""Configuration persistence layer.

Handles loading from disk, saving to disk, and providing a singleton
accessor for the current configuration state. Thread-safe.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from app.config.schema import AppConfig

# Canonical storage location
APP_DATA_DIR = Path.home() / ".llmguard"
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
