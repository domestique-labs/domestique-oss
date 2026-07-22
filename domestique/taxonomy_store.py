"""Persisted registry of LLM-coined taxonomy terms.

Canonical terms live in code (``taxonomy.CANONICAL``); this stores only the
open-vocabulary terms the LLM invents, so they survive restarts and keep a
stable token prefix. Fail-safe: any path/IO error degrades to in-memory only.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import structlog

from domestique.taxonomy import CANONICAL, MAX_PREFIX_LEN, _derive_prefix, normalize_category

logger = structlog.get_logger()

_CANONICAL_PREFIXES = set(CANONICAL.values())


def _default_path() -> Path | None:
    try:
        return Path.home() / ".domestique" / "taxonomy.json"
    except Exception:
        return None


class TaxonomyStore:
    """Thread-safe store of coined term -> token prefix, persisted to JSON."""

    def __init__(self, path: Path | None) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._terms: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._terms = {str(k): str(v) for k, v in data.items()}
        except Exception:
            logger.warning("taxonomy_store_load_failed", path=str(self._path))

    def _persist_locked(self) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self._terms, indent=2, sort_keys=True), encoding="utf-8")
            tmp.replace(self._path)
        except Exception:
            logger.warning("taxonomy_store_persist_failed", path=str(self._path))

    def prefix_of(self, term: str) -> str | None:
        with self._lock:
            return self._terms.get(term)

    def terms(self) -> dict[str, str]:
        with self._lock:
            return dict(self._terms)

    def register(self, raw: str) -> str:
        """Return the prefix for ``raw``; coin + persist it if new and non-canonical."""
        term = normalize_category(raw)
        if term in CANONICAL:
            return CANONICAL[term]
        with self._lock:
            existing = self._terms.get(term)
            if existing is not None:
                return existing
            prefix = self._unique_prefix_locked(_derive_prefix(term))
            self._terms[term] = prefix
            self._persist_locked()
            return prefix

    def _unique_prefix_locked(self, base: str) -> str:
        taken = _CANONICAL_PREFIXES | set(self._terms.values())
        if base not in taken:
            return base
        for n in range(2, 1000):
            suffix = f"_{n}"
            candidate = base[: MAX_PREFIX_LEN - len(suffix)].rstrip("_") + suffix
            if candidate not in taken:
                return candidate
        return base  # pathological; accept collision over infinite loop


_DEFAULT: TaxonomyStore | None = None
_DEFAULT_LOCK = threading.Lock()


def default_store() -> TaxonomyStore:
    """Process-global store, initialized from ``~/.domestique/taxonomy.json`` once."""
    global _DEFAULT
    if _DEFAULT is None:
        with _DEFAULT_LOCK:
            if _DEFAULT is None:
                _DEFAULT = TaxonomyStore(path=_default_path())
    return _DEFAULT
