"""Startup detector-availability probe.

Answers "is each *configured* detection tier actually usable right now?" so the
wedge can (a) warn loudly when a tier is enabled but its optional dependency is
missing (fail-loud-but-open, the default) and (b) refuse to start under
``--strict`` when protection would be incomplete (fail-closed).

The cheap probe (``deep=False``) only checks that the tier's package is
importable — enough to catch the common "extra not installed" case without
paying model-load cost. ``deep=True`` (used by ``--strict``) additionally
verifies the tier can construct/load, catching "installed but model uncached".
"""

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from domestique.config import Settings

# GLiNER model id — kept in sync with domestique/detectors/registry.py.
_GLINER_MODEL_ID = "knowledgator/gliner-pii-base-v1.0"


@dataclass(frozen=True)
class TierStatus:
    """Availability of one optional detection tier."""

    key: str
    label: str
    configured: bool
    available: bool
    install_hint: str
    detail: str = ""


# key, label, settings attribute, import module, install hint
_TIERS: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "pii",
        "PII detection (Presidio) — names, SSNs, addresses",
        "enable_pii_detection",
        "presidio_analyzer",
        "pipx inject domestique 'domestique[pii]'",
    ),
    (
        "gliner",
        "PII/NER detection (GLiNER) — names, addresses, DOBs",
        "enable_gliner",
        "gliner",
        "pipx inject domestique 'domestique[ner]'",
    ),
    (
        "semantic",
        "Semantic detection",
        "enable_semantic_detection",
        "sentence_transformers",
        "pipx inject domestique 'domestique[semantic]'",
    ),
)


def _module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def detector_status(settings: Settings, *, deep: bool = False) -> list[TierStatus]:
    """Return the availability of every optional detection tier."""
    statuses: list[TierStatus] = []
    for key, label, attr, module, hint in _TIERS:
        configured = bool(getattr(settings, attr, False))
        if not configured:
            statuses.append(TierStatus(key, label, False, False, hint))
            continue
        available = _module_available(module)
        detail = "" if available else "optional dependency not installed"
        if available and deep:
            available, detail = _deep_probe(key)
        statuses.append(TierStatus(key, label, True, available, hint, detail))
    return statuses


def unavailable_configured(statuses: list[TierStatus]) -> list[TierStatus]:
    """The tiers that are configured/enabled but not currently usable."""
    return [s for s in statuses if s.configured and not s.available]


def _deep_probe(key: str) -> tuple[bool, str]:  # pragma: no cover - needs heavy deps
    """Verify a tier can actually load. Returns ``(available, detail)``."""
    try:
        if key == "pii":
            from presidio_analyzer import AnalyzerEngine

            AnalyzerEngine()
        elif key == "gliner":
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            from gliner import GLiNER

            GLiNER.from_pretrained(_GLINER_MODEL_ID)
        # semantic: import-availability is a sufficient check for now.
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return True, ""
