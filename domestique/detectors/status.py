"""Startup detector-availability probe.

Answers "is each *configured* detection tier actually usable right now?" so the
wedge can (a) warn loudly when a tier is enabled but its optional dependency is
missing (fail-loud-but-open, the default) and (b) refuse to start under
``--strict`` when protection would be incomplete (fail-closed).

The cheap probe (``deep=False``) only checks that the tier's package is
importable — enough to catch the common "extra not installed" case without
paying model-load cost. ``deep=True`` (used by ``--strict``) additionally
verifies the tier can construct/load, catching "installed but model uncached".

The local-LLM tier is the exception: it has no importable module, so the cheap
probe is a short, proxy-bypassing HTTP call to the configured Ollama daemon.
It runs only when the tier is explicitly enabled (off by default). The response
read is bounded by ``_PROBE_TIMEOUT_S`` as a wall-clock deadline and by
``_MAX_TAGS_BYTES`` in size; every failure degrades to "unavailable".

One caveat that the deadline does not cover: hostname resolution happens before
the socket timeout applies, so a ``local_llm_url`` pointing at a name served by
an unresponsive resolver can still block for the OS resolver timeout. The
default ``localhost`` is unaffected.
"""

from __future__ import annotations

import importlib.util
import json
import os
import time
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from domestique.config import Settings

# GLiNER model id — kept in sync with domestique/detectors/registry.py.
_GLINER_MODEL_ID = "knowledgator/gliner-pii-base-v1.0"

#: Upper bound on the Ollama reachability probe. This runs on ``domestique
#: demo``'s happy path, so it must never be the reason the demo feels slow: a
#: refused connection on loopback returns in ~3 ms, and a black-holed host is
#: capped here rather than at ``local_llm_timeout_s`` (30 s).
_PROBE_TIMEOUT_S = 1.0


@dataclass(frozen=True)
class TierStatus:
    """Availability of one optional detection tier."""

    key: str
    label: str
    configured: bool
    available: bool
    install_hint: str
    detail: str = ""


# key, label, settings attribute, import module ("" = probed, not imported),
# install hint
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
    (
        # No importable module: the second-pass classifier talks to a local
        # Ollama daemon over HTTP, so availability is a daemon probe.
        "local_llm",
        "Local LLM second pass (Ollama)",
        "enable_local_llm",
        "",
        "domestique setup",
    ),
)


def _module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _ollama_tags(base_url: str, timeout: float) -> set[str] | None:
    """Model names the Ollama daemon reports, or ``None`` if unreachable.

    Lifted from ``setup_wizard.detect_existing_ollama_models`` with its two
    defects fixed: the base URL comes from settings rather than a hardcoded
    ``localhost:11434``, and the system proxy is bypassed. Without the bypass an
    active wedge/mitmproxy answers this request itself, so the probe reports on
    the proxy instead of the daemon — i.e. it lies.
    """
    if not base_url.startswith(("http://", "https://")):
        return None
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(  # noqa: S310  # scheme checked above
            f"{base_url.rstrip('/')}/api/tags"
        )
        deadline = time.monotonic() + timeout
        with opener.open(req, timeout=timeout) as resp:
            # `timeout` is a per-socket-operation deadline, not an end-to-end
            # one: every byte received resets it, so a server that accepts and
            # then trickles the body blocks for as long as it keeps dripping.
            # Measured 15s against a 1s timeout, on the `domestique demo` path.
            # Cap the read and enforce our own wall-clock deadline. Also bounds
            # size: a wrong service on :11434 could otherwise return gigabytes.
            data = json.loads(_read_bounded(resp, deadline))
        return {str(m.get("name", "")) for m in data.get("models", [])}
    except Exception:
        return None


#: Ollama's /api/tags is a short model list; anything larger is not it.
_MAX_TAGS_BYTES = 1 << 20


def _read_bounded(resp: Any, deadline: float) -> bytes:
    """Read at most ``_MAX_TAGS_BYTES``, giving up once ``deadline`` passes."""
    chunks: list[bytes] = []
    total = 0
    while total < _MAX_TAGS_BYTES:
        if time.monotonic() >= deadline:
            raise TimeoutError("ollama probe exceeded its deadline")
        chunk = resp.read(min(65536, _MAX_TAGS_BYTES - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _model_present(model: str, names: set[str]) -> bool:
    """Whether *model* is among the daemon's ``names``.

    Ollama stores an untagged pull under the ``:latest`` tag, so a config that
    says ``qwen3`` is satisfied by ``qwen3:latest``.
    """
    if model in names:
        return True
    return ":" not in model and f"{model}:latest" in names


def _local_llm_available(settings: Settings) -> tuple[bool, str]:
    """``(available, detail)`` for the local-LLM tier. Never raises.

    Two distinct failures, reported distinctly: the daemon is not reachable,
    or it is reachable but has not pulled the configured model.
    """
    base = str(getattr(settings, "local_llm_url", "") or "")
    model = str(getattr(settings, "local_llm_model", "") or "")
    if not base:
        return False, "local_llm_url is not set"
    try:
        names = _ollama_tags(base, _PROBE_TIMEOUT_S)
    except Exception:  # a probe must never break the demo's happy path
        names = None
    if names is None:
        return False, f"Ollama not reachable at {base}"
    if not _model_present(model, names):
        return False, f"Ollama is running but model '{model}' is not pulled"
    return True, ""


def detector_status(settings: Settings, *, deep: bool = False) -> list[TierStatus]:
    """Return the availability of every optional detection tier."""
    statuses: list[TierStatus] = []
    for key, label, attr, module, hint in _TIERS:
        configured = bool(getattr(settings, attr, False))
        if not configured:
            statuses.append(TierStatus(key, label, False, False, hint))
            continue
        if not module:
            available, detail = _local_llm_available(settings)
        else:
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
