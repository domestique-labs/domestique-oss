"""Mitmproxy addon for LLM request inspection.

This addon is loaded by mitmproxy to inspect HTTPS traffic flowing through
the transparent proxy. It:

1. Identifies requests to LLM API endpoints
2. Extracts the user's message content from the request body
3. Runs it through the firewall's detection pipeline
4. Blocks, redacts, or queues for approval before forwarding

The addon is designed to be loaded via:
    mitmdump --set confdir=~/.domestique/ca -s app/services/mitm_addon.py

Architecture:
    Browser -> System Proxy -> mitmproxy (port 8080) -> this addon -> upstream LLM
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import sys
import threading
import time

# Direct HTTP opener that bypasses any system proxy settings.
# This is critical because the mitmdump process runs inside the proxy chain -
# if urlopen respects system proxy, it would route localhost API calls back
# through mitmproxy, creating a deadlock.
import urllib.request as _urllib_req
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.error import URLError
from urllib.request import Request

from mitmproxy import ctx, http
from mitmproxy.net import encoding as mitm_encoding

if TYPE_CHECKING:
    from mitmproxy.addonmanager import Loader

_direct_opener = _urllib_req.build_opener(_urllib_req.ProxyHandler({}))
_direct_urlopen = _direct_opener.open

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger("domestique.mitm")


# --- Hardware-aware detection profile ---------------------------------------
#
# Weak hardware (no usable GPU and/or low RAM) must never be asked to build
# the heavy in-process tiers (GLiNER, semantic embeddings, local-LLM warmup)
# synchronously at startup -- that's exactly what makes cold binds slow and
# risks OOM on the addon process. Below that threshold we fall back to a
# light, regex-only profile (SecretDetector is pure regex: <1ms, zero model
# load) unless the user explicitly opted into a heavier tier.

_LOW_RAM_THRESHOLD_GB = 8.0
_MIN_USABLE_VRAM_GB = 2.0

# Mirrors app.config.schema.DetectionStackConfig's own field defaults. Used
# to distinguish "the user explicitly turned this on" from "this is just the
# dataclass default that got serialized to config.json" -- the same
# ambiguity already documented on AppConfig.browser_interception_configured
# (to_dict() always serializes every field, so key *presence* in config.json
# proves nothing about intent; only a value that *differs* from the safe
# default is real signal).
_STACK_SAFE_DEFAULTS = {
    "regex": True,
    "gliner_pii": False,
    "gemma4_e2b": False,
    "qwen3_1_7b": True,
    "legacy_cpu": False,
}


def _detect_low_resource_hardware() -> bool:
    """True if this machine is weak enough to warrant the light profile.

    Reuses the existing stdlib/ctypes RAM probe and nvidia-smi/Apple-Silicon
    VRAM probe from ``scripts/install.py`` instead of re-implementing
    hardware detection. Fails toward "capable" (False) on any detection
    error -- a detection glitch must never silently narrow security
    coverage; the light profile is an intentional, logged trade-off, not
    something that should kick in by accident.
    """
    try:
        from scripts.install import detect_gpu, detect_total_ram_gb

        ram_gb = detect_total_ram_gb()
        _gpu_name, vram_gb = detect_gpu()
    except Exception:
        return False

    low_ram = ram_gb > 0 and ram_gb < _LOW_RAM_THRESHOLD_GB
    no_gpu = vram_gb < _MIN_USABLE_VRAM_GB
    return bool(low_ram or no_gpu)


def _light_profile_stack(stack: dict, stack_configured: bool = False) -> dict:
    """Down-convert a raw ``detection_stack`` dict to regex-only, preserving
    any field the user explicitly opted into (value True, differing from
    that field's safe default -- see ``_STACK_SAFE_DEFAULTS``).

    ``qwen3_1_7b`` defaults True in the dataclass, so a bare True value there
    is normally indistinguishable from having never touched the dashboard --
    on low-resource hardware it is switched off along with the other heavy
    tiers unless the user separately enabled a different heavy detector.

    ``stack_configured`` (mirrors ``AppConfig.detection_stack_configured``)
    breaks that ambiguity: once the user has explicitly changed the
    detection stack at least once, the entire on-disk stack is honored as-is
    -- including a default-valued ``qwen3_1_7b: True`` -- instead of being
    down-converted. Without this, a low-resource user had NO supported way
    to keep (or re-enable) the shipped-default heavy detector: re-toggling
    it in the dashboard just writes ``True`` again, identical to the
    never-configured default.
    """
    if stack_configured:
        return {
            key: bool(stack.get(key, default)) for key, default in _STACK_SAFE_DEFAULTS.items()
        }

    light = {"regex": bool(stack.get("regex", _STACK_SAFE_DEFAULTS["regex"]))}
    for key, default in _STACK_SAFE_DEFAULTS.items():
        if key == "regex":
            continue
        value = stack.get(key, default)
        light[key] = bool(value is True and default is False)
    return light


class _InspectResult:
    """Result from running the detection pipeline on a text."""

    def __init__(
        self, findings: list, should_block: bool = False, redacted_text: str | None = None
    ) -> None:
        self.findings = findings
        self.should_block = should_block
        self.redacted_text = redacted_text


class _Finding:
    """A single finding from the detection pipeline."""

    def __init__(self, category: str, confidence: float, description: str) -> None:
        self.category = category
        self.confidence = confidence
        self.description = description


class _DetectorPipeline:
    """Wraps a list of detectors into a unified pipeline with an inspect() method."""

    def __init__(self, detectors: list[Any]) -> None:
        self._detectors = detectors

    async def inspect(self, text: str) -> _InspectResult:
        all_findings = []
        for det in self._detectors:
            try:
                detections = await det.scan(text)
                for d in detections:
                    all_findings.append(
                        _Finding(
                            category=d.category,
                            confidence=d.confidence,
                            description=f"{d.detector}: {d.category} ({d.confidence:.0%})",
                        )
                    )
            except Exception:  # noqa: S110
                pass

        should_block = any(f.confidence >= 0.7 for f in all_findings)
        return _InspectResult(
            findings=all_findings,
            should_block=should_block,
        )


class DomestiqueAddon:
    """Mitmproxy addon that inspects LLM API requests for sensitive data.

    Only processes requests to known LLM endpoints. All other traffic
    passes through untouched with zero overhead.
    """

    MAX_LOG_ENTRIES = 500  # Keep last N entries in the request log

    # Bounded hold for the request path while the background-built detector
    # pipeline is not yet ready (see load() / _wait_for_detector_ready()).
    DETECTOR_READY_WAIT_S = 20.0

    # Minimum interval between automatic re-init attempts after a
    # background pipeline-construction failure (see
    # _maybe_retry_detector_init()). Bounds how often a storm of blocked
    # requests can hammer a still-broken dependency (e.g. a locked policy
    # file or an Ollama outage) -- a detected config change bypasses this
    # backoff and retries immediately regardless.
    DETECTOR_RETRY_BACKOFF_S = 5.0

    # Path fragments that identify a genuine conversation/completion
    # endpoint -- one that carries user-authored prompt content (outbound)
    # or assistant-authored reply content (inbound). Shared by the
    # request-side prompt-DLP filter and the response-side leak-scan
    # filter (see ``_is_conversation_path``) so both directions apply the
    # identical scope. Internal endpoints (sentinel, telemetry,
    # autocompletions, connectors, static assets) are noise and cause
    # false positives / false "inspected" counts with none of the DLP
    # value.
    _CONVERSATION_PATH_FRAGMENTS = (
        # ChatGPT web
        "/conversation",  # /backend-api/f/conversation
        "/backend-anon/",  # guest conversations
        # OpenAI API
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/responses",  # 2025 Responses API
        # Anthropic
        "/v1/messages",
        "/v1/complete",  # legacy
        "/completion",  # Claude web: /api/.../completion
        "/append_message",  # Claude web
        # Google Gemini
        "/batchexecute",  # Gemini web (BardChatUi)
        "/StreamGenerate",  # Gemini web streaming
        ":generateContent",  # Gemini API
        ":streamGenerateContent",  # Gemini API streaming
        # Microsoft Copilot
        "/c/api/chat",
        "/c/api/conversations",
        "/c/api/messages",
        "/turing/conversation",
        # Cohere
        "/v2/chat",
        "/v1/chat",
        # Generic (covers most OpenAI-compatible APIs: Groq, xAI,
        # DeepSeek, Together, Fireworks, Cursor, etc.)
        "/chat/completions",
        "/generate",
        "/predictions",  # Replicate
        # HuggingFace
        "/models/",  # api-inference: /models/{model}
        # Cursor / Windsurf (gRPC-web)
        "/aiserver.v1.",  # Cursor: /aiserver.v1.ChatService/
    )
    _SKIP_PATH_SUBSTRINGS = (
        "/sentinel/",
        "/autocompletions",
        "/connectors/",
        "/telemetry",
        "/rgstr",
        "/library",
        "/cdn-cgi/",
        "/ces/",
        "/cdn/",
        "/_next/",
        "/assets/",
        "/static/",
        "/favicon",
        "/init",
    )

    def __init__(self) -> None:
        self._detector = None
        self._data_dir = Path.home() / ".domestique"
        self._stats = {
            "inspected": 0,
            "blocked": 0,
            "redacted": 0,
            "allowed": 0,
            # Response-side leak alerts (async, non-blocking scan -- see
            # responseheaders()/response()). Counted separately from the
            # request-side counters above because a response alert can
            # never block/redact; it only surfaces a leak after the bytes
            # already reached the browser.
            "response_alerts": 0,
            # A teed response body whose Content-Encoding could not be
            # decoded (unknown encoding, or corrupt/truncated compressed
            # bytes) -- the background scan could NOT inspect it for a
            # leak. Tracked separately from response_alerts so "0 alerts"
            # can't be misread as "everything was scanned and clean" when
            # some responses were actually un-scannable. See
            # _report_unscannable_response().
            "response_scan_errors": 0,
        }
        self._stats_file = self._data_dir / "browser_stats.json"
        self._log_file = self._data_dir / "request_log.jsonl"
        self._config_file = self._data_dir / "config.json"
        self._api_base = "http://127.0.0.1:9876"
        self._data_dir.mkdir(parents=True, exist_ok=True)
        # Ready by default: tests/tools that construct DomestiqueAddon() and
        # assign self._detector directly (bypassing load()) get immediate,
        # non-blocking behavior. load() clears this while the pipeline is
        # being built on a background thread.
        self._detector_ready = threading.Event()
        self._detector_ready.set()
        self._detector_init_error: Exception | None = None
        self._light_profile_active = False
        # Self-heal state for _maybe_retry_detector_init(): guards against
        # more than one concurrent background retry attempt, and gates how
        # often an automatic retry is attempted absent a config change.
        self._detector_retry_lock = threading.Lock()
        self._last_detector_retry_ts = 0.0
        # Strong references to fire-and-forget background response-scan
        # tasks (asyncio.create_task(...) in response()). Per the asyncio
        # docs, a Task with no other referent can be garbage-collected
        # before it completes, silently dropping the scan -- this set
        # keeps each task alive until it finishes, then self-evicts via
        # the done callback. See response() / _scan_response_bytes_async().
        self._background_tasks: set[asyncio.Task] = set()

    def _persist_stats(self) -> None:
        """Write stats to a shared file for the dashboard to read.

        Includes ``light_profile_active`` (see ``_init_detector`` /
        ``_resolve_hardware_profile``) alongside the request counters so an
        auto-selected regex-only downgrade is visible to the dashboard/API
        (``/api/browser-proxy``), not just logged to ``browser_proxy.log``
        -- an ordinary user has no other way to discover that detection was
        silently narrowed on their machine.
        """
        try:
            payload = dict(self._stats)
            payload["light_profile_active"] = self._light_profile_active
            self._stats_file.write_text(json.dumps(payload))
        except OSError:
            pass

    def _log_request(self, entry: dict) -> None:
        """Append a request entry to the JSON lines log file."""
        try:
            with open(self._log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
            # Truncate if too large (keep last N entries)
            self._trim_log()
        except OSError:
            pass

    def _trim_log(self) -> None:
        """Keep only the last MAX_LOG_ENTRIES in the log file."""
        try:
            lines = self._log_file.read_text().strip().split("\n")
            if len(lines) > self.MAX_LOG_ENTRIES:
                self._log_file.write_text("\n".join(lines[-self.MAX_LOG_ENTRIES :]) + "\n")
        except OSError:
            pass

    def _load_config(self) -> dict:
        """Load config from disk. Returns dict (empty on failure)."""
        try:
            if self._config_file.exists():
                return json.loads(self._config_file.read_text())
        except (json.JSONDecodeError, OSError):
            pass
        return {}

    def _trace_request(
        self,
        flow: http.HTTPFlow,
        *,
        action: str,
        reason: str = "",
        reasons: list[str] | None = None,
        content: str | None = None,
        redacted_content: str | None = None,
        latency_ms: float | None = None,
        raw_body_preview: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Write the raw prompt decision trace for browser-intercepted traffic."""
        reasons = reasons or []
        trace_action = "allowed" if action == "allow" else action
        event = {
            "request_id": getattr(flow, "id", ""),
            "source": "browser_proxy",
            "direction": "outbound",
            "action": trace_action,
            "reason": reason or ", ".join(reasons),
            "reasons": reasons,
            "host": flow.request.pretty_host,
            "method": flow.request.method,
            "path": flow.request.path,
            "model": self._extract_model(flow),
            "content_length": len(flow.request.content or b""),
            "detections": [{"detector": "browser_proxy", "category": item} for item in reasons],
        }
        if latency_ms is not None:
            event["latency_ms"] = round(latency_ms, 1)
        if content is not None:
            event["prompt"] = content
            event["prompt_fields"] = [
                {
                    "field_path": "request.body",
                    "text": content,
                    "length": len(content),
                }
            ]
        if redacted_content is not None:
            event["redacted_prompt"] = redacted_content
            event["redacted_prompt_fields"] = [
                {
                    "field_path": "request.body",
                    "text": redacted_content,
                    "length": len(redacted_content),
                }
            ]
        if raw_body_preview:
            event["raw_body_preview"] = raw_body_preview
        if extra:
            event.update(extra)
        from domestique.debug_trace import append_debug_trace

        append_debug_trace(event)

    def _extract_model(self, flow: http.HTTPFlow) -> str:
        """Best-effort model extraction from JSON request bodies."""
        try:
            body = json.loads(flow.request.content or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            return ""
        if isinstance(body, dict):
            model = body.get("model") or body.get("model_id")
            return str(model) if model else ""
        return ""

    def load(self, loader: Loader) -> None:
        """Called when the addon is loaded.

        mitmproxy does not accept connections on the proxy port until this
        method returns, so building the detection pipeline (which can
        instantiate torch/transformers/GLiNER) must NEVER happen
        synchronously here -- doing so gates the port bind on however long
        model construction takes, which on a cold cache or weak hardware can
        blow past the readiness-timeout safety net and get the whole proxy
        killed. Build it on a background thread instead; the request path
        (``_wait_for_detector_ready`` / ``_inspect``) holds briefly for
        intercepted LLM traffic until the pipeline is ready, and fails
        closed if it never becomes ready.
        """
        ctx.log.info("Domestique addon loaded - inspecting LLM API traffic")
        self._detector_ready.clear()
        self._detector_init_error = None
        threading.Thread(
            target=self._build_detector_pipeline_background,
            daemon=True,
            name="detector-pipeline-init",
        ).start()
        self._warmup_llm()

    def _build_detector_pipeline_background(self) -> None:
        """Build the detector pipeline off the mitmproxy event loop.

        Runs on the thread started from ``load()``. On success, sets
        ``_detector_ready`` and then warms the detectors (GLiNER lazy-load
        etc) so the first real request doesn't pay that cost. On failure,
        records the exception in ``_detector_init_error`` and still sets
        ``_detector_ready`` so waiters stop blocking -- ``_detector`` stays
        ``None``, and the request path treats "ready but no detector" as
        fail-closed (block), never fail-open.
        """
        try:
            self._init_detector()
        except Exception as e:
            self._detector_init_error = e
            ctx.log.error(
                f"Detector pipeline failed to build: {e} - "
                "failing closed on intercepted requests until resolved"
            )
            self._detector_ready.set()
            return

        ctx.log.info("Detection pipeline ready")
        self._detector_ready.set()

        # Pre-warm all detectors (GLiNER lazy load etc) now that the
        # pipeline exists, still off the mitmproxy event loop.
        if self._detector:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(
                    self._detector.inspect("warmup email test@example.com SSN 123-45-6789")
                )
                ctx.log.info("All detectors warmed up")
            except Exception as e:
                ctx.log.warn(f"Detector warmup: {e}")
            finally:
                loop.close()

    async def _wait_for_detector_ready(self, timeout: float | None = None) -> bool:
        """Bounded wait for the background-built pipeline to become ready.

        Returns True once the pipeline is ready to use. Returns False if the
        wait expires, or if the pipeline is "ready" (init finished) but
        construction actually failed (``self._detector`` is None) -- both are
        fail-closed conditions for the caller.

        Waits via ``run_in_executor`` so the bounded hold never blocks
        mitmproxy's event loop -- other flows keep flowing concurrently.
        """
        if timeout is None:
            timeout = self.DETECTOR_READY_WAIT_S
        if not self._detector_ready.is_set():
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._detector_ready.wait, timeout)
        return self._detector_ready.is_set() and self._detector is not None

    def _init_detector(self) -> None:
        """Build detection pipeline from config. Called once at startup (in
        the background -- see ``load()``) and again whenever the on-disk
        config changes (hot-reload path in ``_inspect()``).

        Uses the shared pipeline_config helper for consistent Settings
        construction between API and mitm processes. On low-resource
        hardware (no usable GPU and/or low RAM), gates the heavy in-process
        tiers (GLiNER, local LLM) down to a light, regex-only profile so the
        pipeline builds near-instantly and never OOMs -- see
        ``_resolve_hardware_profile``. The user's explicit choices are never
        silently overridden; an auto-selected light profile is logged.
        """
        import os

        os.environ.setdefault("HF_HUB_OFFLINE", "1")

        from domestique.detectors.registry import create_detector_pipeline
        from domestique_app.services.pipeline_config import (
            config_hash,
            load_config_dict,
            settings_from_config,
        )

        raw_config = load_config_dict()
        effective_config, profile_note = self._resolve_hardware_profile(raw_config)

        settings = settings_from_config(effective_config)
        self._detector = create_detector_pipeline(settings)
        # Hash the RAW config, not the hardware-adjusted one: _inspect()'s
        # hot-reload check always hashes a fresh load_config_dict(), so
        # comparing against a hash of the adjusted config would spuriously
        # detect a "change" (and rebuild) on every single request.
        self._config_hash = config_hash(raw_config)

        names = [d.name for d in self._detector._detectors]
        ctx.log.info(f"Detection pipeline: {', '.join(names)}")
        self._light_profile_active = profile_note is not None
        if profile_note:
            ctx.log.warn(profile_note)
        # Surface the (possibly just-changed) light-profile state to
        # browser_stats.json immediately -- don't wait for the first
        # inspected request to write it, so the dashboard can show it right
        # after startup / a hot-reload rebuild.
        self._persist_stats()

    def _hardware_is_low_resource(self) -> bool:
        """Cache the hardware-resource determination for this process's
        lifetime -- hardware doesn't change at runtime, and GPU probing can
        shell out to nvidia-smi, so there's no need to repeat that work on
        every config hot-reload."""
        if not hasattr(self, "_low_resource_cache"):
            self._low_resource_cache = _detect_low_resource_hardware()
        return self._low_resource_cache

    def _resolve_hardware_profile(self, config: dict) -> tuple[dict, str | None]:
        """Return ``(effective_config, profile_note)``.

        On capable hardware, returns *config* unchanged (full/config-
        respecting stack) and ``profile_note`` is ``None``.

        On low-resource hardware, returns a copy of *config* with
        ``detection_stack`` down-converted to regex-only (see
        ``_light_profile_stack``) plus a human-readable note to log -- unless
        the resulting stack is identical to what was already configured (a
        user who already runs regex-only sees no note), in which case
        ``profile_note`` is ``None`` too.

        If ``detection_stack_configured`` is set on *config* (the user has
        explicitly changed the detection stack via the dashboard/API at
        least once -- see ``AppConfig.detection_stack_configured``), the
        on-disk stack is honored as-is instead of being down-converted --
        this is what lets a low-resource user keep or re-enable a
        default-valued heavy detector like ``qwen3_1_7b``.
        """
        if not self._hardware_is_low_resource():
            return config, None

        stack = dict(config.get("detection_stack", {}))
        stack_configured = bool(config.get("detection_stack_configured", False))
        light_stack = _light_profile_stack(stack, stack_configured)
        if light_stack == stack:
            return config, None

        effective = dict(config)
        effective["detection_stack"] = light_stack
        note = (
            "interceptor running light profile: regex-only - low-resource "
            "machine detected (no usable GPU and/or low RAM); enable heavier "
            "detection tiers (GLiNER / local LLM) in the dashboard if desired"
        )
        return effective, note

    def _warmup_llm(self) -> None:
        """Pre-load Ollama model so first request doesn't block."""
        import threading

        config = self._load_config()
        stack = config.get("detection_stack", {})
        model = None
        if stack.get("gemma4_e2b", False):
            from domestique.detectors.local_llm import _resolve_gemma_model

            model = _resolve_gemma_model()
        elif stack.get("qwen3_1_7b", True):
            model = "qwen3:1.7b"
        elif stack.get("legacy_cpu", False):
            model = "llama3.2:1b"
        if not model:
            return

        def _warmup() -> None:
            try:
                import json as _json
                import urllib.request as _req

                opener = _req.build_opener(_req.ProxyHandler({}))
                data = _json.dumps(
                    {
                        "model": model,
                        "messages": [{"role": "user", "content": "warmup"}],
                        "stream": False,
                        "options": {"num_predict": 1, "num_ctx": 8192},
                    }
                ).encode()
                req = _req.Request(
                    "http://localhost:11434/api/chat",
                    data=data,
                    headers={"Content-Type": "application/json"},
                )
                opener.open(req, timeout=120)
                ctx.log.info(f"LLM warmup complete: {model}")
            except Exception as e:
                ctx.log.warn(f"LLM warmup failed: {e}")

        threading.Thread(target=_warmup, daemon=True, name="llm-warmup").start()
        ctx.log.info(f"LLM warmup started in background: {model}")

    async def request(self, flow: http.HTTPFlow) -> None:
        """Inspect outgoing requests to LLM APIs.

        Called by mitmproxy for every request. We only process requests
        to known LLM endpoints; everything else passes through.
        """
        host = flow.request.pretty_host
        if not self._is_llm_endpoint(host):
            return

        # Log ALL requests to LLM domains (helps debug why some aren't counted)
        method = flow.request.method
        path = flow.request.path

        # Only inspect POST requests with bodies (not page loads / GETs)
        if method != "POST" or not flow.request.content:
            self._log_request(
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "host": host,
                    "method": method,
                    "path": path[:100],
                    "action": "pass",
                    "reason": f"no body ({method})",
                }
            )
            self._trace_request(
                flow,
                action="pass",
                reason=f"no body ({method})",
            )
            return

        # Skip non-conversation paths. Only inspect endpoints that carry
        # user-authored content (chat messages, completions). Internal
        # endpoints (sentinel, telemetry, autocompletions, connectors,
        # static assets) are noise and cause false positives. (See
        # ``_is_conversation_path`` -- shared with the response-side scan
        # filter in ``responseheaders()``/``response()``.)
        if not self._is_conversation_path(path):
            self._log_request(
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "host": host,
                    "method": method,
                    "path": path[:100],
                    "action": "pass",
                    "reason": "non-conversation path",
                }
            )
            return

        # Extract user content from the request body
        content = self._extract_content(flow)
        if not content:
            # Log raw body snippet for conversation endpoints to help debug extraction
            raw_snippet = ""
            if "conversation" in path:
                with contextlib.suppress(Exception):
                    raw_snippet = flow.request.content.decode("utf-8", errors="replace")[:500]
            self._log_request(
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "host": host,
                    "method": method,
                    "path": path[:100],
                    "action": "pass",
                    "reason": "no extractable content",
                    "body_size": len(flow.request.content),
                    "raw_snippet": raw_snippet if raw_snippet else None,
                }
            )
            self._trace_request(
                flow,
                action="pass",
                reason="no extractable content",
                raw_body_preview=raw_snippet if raw_snippet else None,
                extra={"body_size": len(flow.request.content)},
            )
            return

        self._stats["inspected"] += 1

        # Run detection (measure latency)
        start_time = time.time()
        result = await self._inspect(content)
        latency_ms = (time.time() - start_time) * 1000
        content_preview = content[:200] + ("..." if len(content) > 200 else "")

        # Emit structured audit event
        self._emit_audit_event(
            action=result["action"],
            host=host,
            method=method,
            path=path,
            reasons=result.get("reasons", []),
            latency_ms=latency_ms,
            content_length=len(flow.request.content),
            content_preview=content_preview,
        )

        if result["action"] == "block":
            reasons = result.get("reasons", [])
            approval_decision = None

            # Check if approval mode is enabled
            if self._is_approval_mode():
                decision = await asyncio.to_thread(
                    lambda: self._request_approval(
                        host=host,
                        path=path,
                        findings=reasons,
                        content_preview=content_preview,
                    )
                )
                approval_decision = decision
                if decision == "approved":
                    # User approved - let request through
                    self._stats["allowed"] += 1
                    self._persist_stats()
                    self._log_request(
                        {
                            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                            "host": host,
                            "method": method,
                            "path": path[:100],
                            "action": "approved",
                            "reasons": reasons,
                            "prompt": content,
                            "content_preview": content_preview,
                        }
                    )
                    self._trace_request(
                        flow,
                        action="approved",
                        reasons=reasons,
                        content=content,
                        latency_ms=latency_ms,
                        extra={"approval_decision": "approved"},
                    )
                    ctx.log.info(f"APPROVED by user: request to {host} ({reasons})")
                    return

            # Denied, expired, or immediate block
            self._stats["blocked"] += 1
            self._persist_stats()
            self._log_request(
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "host": host,
                    "method": method,
                    "path": path[:100],
                    "action": "blocked",
                    "reasons": reasons,
                    "prompt": content,
                    "content_preview": content_preview,
                }
            )
            self._trace_request(
                flow,
                action="blocked",
                reasons=reasons,
                content=content,
                latency_ms=latency_ms,
                extra=({"approval_decision": approval_decision} if approval_decision else None),
            )
            flow.response = http.Response.make(
                403,
                json.dumps(
                    {
                        "error": {
                            "message": "Request blocked by Domestique: sensitive data detected",
                            "type": "firewall_block",
                            "details": reasons,
                        }
                    }
                ).encode(),
                {"Content-Type": "application/json"},
            )
            ctx.log.warn(f"BLOCKED request to {host}: {reasons}")
            try:
                from domestique_app.services.notifications import notify_block

                notify_block(host)
            except Exception:
                logger.debug("Desktop notification failed", exc_info=True)

        elif result["action"] == "redact":
            self._stats["redacted"] += 1
            self._persist_stats()
            self._log_request(
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "host": host,
                    "method": method,
                    "path": path[:100],
                    "action": "redacted",
                    "reasons": result.get("reasons", []),
                    "redacted_count": result.get("redacted_count", 0),
                    "prompt": content,
                    "redacted_prompt": result["redacted_content"],
                    "content_preview": content_preview,
                }
            )
            self._trace_request(
                flow,
                action="redacted",
                reasons=result.get("reasons", []),
                content=content,
                redacted_content=result["redacted_content"],
                latency_ms=latency_ms,
                extra={"redacted_count": result.get("redacted_count", 0)},
            )
            self._redact_request(flow, result["redacted_content"])
            ctx.log.info(f"REDACTED request to {host}: {result.get('redacted_count', 0)} spans")

        else:
            self._stats["allowed"] += 1
            self._persist_stats()
            self._log_request(
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "host": host,
                    "method": method,
                    "path": path[:100],
                    "action": "allowed",
                    "prompt": content,
                    "content_preview": content_preview,
                }
            )
            self._trace_request(
                flow,
                action="allowed",
                content=content,
                latency_ms=latency_ms,
            )

    def _is_llm_endpoint(self, host: str) -> bool:
        """Check if a host is a known LLM API endpoint."""
        from domestique_app.services.interceptor import INTERCEPTED_DOMAINS

        return any(host.endswith(d) or host == d for d in INTERCEPTED_DOMAINS)

    def _is_conversation_path(self, path: str) -> bool:
        """True if *path* is a genuine LLM conversation/completion
        endpoint (see ``_CONVERSATION_PATH_FRAGMENTS`` /
        ``_SKIP_PATH_SUBSTRINGS``).

        Shared by ``request()`` (outbound prompt DLP) and
        ``responseheaders()`` / the ``response()`` fallback path (inbound
        response-leak scanning) so both directions apply the identical
        scope. Internal endpoints on an LLM host -- telemetry, sentinel,
        autocompletions, connectors, polling, static assets -- are
        excluded: scanning/logging them is pure noise (dozens of extra
        "inspected" entries per real user interaction) with none of the
        DLP value.
        """
        if any(s in path for s in self._SKIP_PATH_SUBSTRINGS):
            return False
        return any(f in path for f in self._CONVERSATION_PATH_FRAGMENTS)

    def _emit_audit_event(
        self,
        *,
        action: str,
        host: str,
        method: str,
        path: str,
        reasons: list[str],
        latency_ms: float,
        content_length: int,
        content_preview: str,
    ) -> None:
        """Emit a structured audit event to the audit store."""
        try:
            from domestique_app.services.audit import (
                AuditAction,
                create_audit_event,
                get_audit_store,
            )

            action_enum = {
                "block": AuditAction.BLOCK,
                "redact": AuditAction.REDACT,
                "allow": AuditAction.ALLOW,
            }.get(action, AuditAction.ALLOW)

            event = create_audit_event(
                action=action_enum,
                destination=host,
                method=method,
                path=path[:200],
                detectors=reasons,
                categories=reasons,
                latency_ms=latency_ms,
                content_length=content_length,
                content_preview=content_preview[:200],
                proxy_mode="browser",
            )
            get_audit_store().record(event)
        except Exception:  # noqa: S110
            pass  # Never let audit failure affect request path

    # --- Approval flow -----------------------------------------------

    def _is_approval_mode(self) -> bool:
        """Check if approval mode is enabled in config."""
        try:
            if self._config_file.exists():
                config = json.loads(self._config_file.read_text())
                return bool(config.get("approval_mode", False))
        except (json.JSONDecodeError, OSError):
            pass
        return False

    def _redact_for_preview(self, text: str) -> str:
        """Redact sensitive values in a preview string.

        Replaces detected PII with masked versions so the approval
        queue never stores raw sensitive data.
        """
        # SSN: 123-45-6789 -> ***-**-6789
        text = re.sub(
            r"\b(\d{3})-(\d{2})-(\d{4})\b",
            r"***-**-\3",
            text,
        )
        # Email: user@domain.com -> u***@domain.com
        text = re.sub(
            r"\b([A-Za-z0-9])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b",
            r"\1***@\2",
            text,
        )
        # API keys: sk-abc...xyz -> sk-***
        text = re.sub(
            r"\b(sk-|pk_live_|sk_live_|AKIA|ASIA)[a-zA-Z0-9_-]{6,}\b",
            r"\1***",
            text,
        )
        # Credit card: 4111 1111 1111 1111 -> **** **** **** 1111
        text = re.sub(
            r"\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?)(\d{4})\b",
            r"**** **** **** \2",
            text,
        )
        return text

    def _request_approval(
        self,
        *,
        host: str,
        path: str,
        findings: list[str],
        content_preview: str,
    ) -> str:
        """Submit a request for user approval and poll for the decision.

        Blocks the current request thread until the user approves/denies
        or the timeout expires. Other mitmproxy requests continue in
        parallel threads.

        Returns:
            'approved', 'denied', or 'expired'
        """
        # Redact PII from the preview before sending to the API
        redacted_preview = self._redact_for_preview(content_preview)

        # Read timeout from config
        timeout = 30
        try:
            if self._config_file.exists():
                config = json.loads(self._config_file.read_text())
                timeout = int(config.get("approval_timeout_seconds", 30))
        except (json.JSONDecodeError, OSError, ValueError):
            pass

        # Submit to the API server
        try:
            payload = json.dumps(
                {
                    "host": host,
                    "path": path[:100],
                    "findings": findings,
                    "content_preview": redacted_preview,
                }
            ).encode()
            req = Request(  # noqa: S310
                f"{self._api_base}/api/approvals",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            resp = _direct_urlopen(req, timeout=5)
            result = json.loads(resp.read())
            approval_id = result.get("id")
            if not approval_id:
                ctx.log.error("Approval submit returned no ID - blocking")
                return "denied"
        except (URLError, OSError, json.JSONDecodeError) as e:
            ctx.log.error(f"Failed to submit approval: {e} - blocking")
            return "denied"

        # Poll for the decision
        ctx.log.info(
            f"Awaiting approval {approval_id} for {host} (timeout={timeout}s, findings={findings})"
        )
        deadline = time.time() + timeout
        poll_interval = 0.5

        while time.time() < deadline:
            time.sleep(poll_interval)
            try:
                req = Request(  # noqa: S310
                    f"{self._api_base}/api/approvals/{approval_id}",
                    method="GET",
                )
                resp = _direct_urlopen(req, timeout=3)
                data = json.loads(resp.read())
                status = data.get("status", "pending")

                if status == "approved":
                    ctx.log.info(f"Approval {approval_id}: APPROVED by user")
                    return "approved"
                elif status in ("denied", "expired"):
                    ctx.log.info(f"Approval {approval_id}: {status}")
                    return status
                # Still pending - continue polling
            except (URLError, OSError, json.JSONDecodeError):
                pass  # Transient error - keep polling

        ctx.log.info(f"Approval {approval_id}: EXPIRED (timeout)")
        return "expired"

    def _extract_content(self, flow: http.HTTPFlow) -> str | None:
        """Extract the user's message content from the request body.

        Handles JSON and non-JSON (URL-encoded, protobuf-like) bodies.
        Also extracts text from base64-encoded images and file attachments.
        """
        if not flow.request.content:
            return None

        raw = flow.request.content
        content_type = flow.request.headers.get("content-type", "")

        # Handle multipart file uploads
        if "multipart/form-data" in content_type:
            return self._extract_multipart_content(flow)

        # Try JSON parsing first
        body = None
        with contextlib.suppress(json.JSONDecodeError, UnicodeDecodeError):
            body = json.loads(raw)

        if body and isinstance(body, dict):
            # Try OpenAI-compatible format (most common)
            content = _extract_openai_content(body)
            if content:
                # Also scan any embedded images/files in the message
                file_text = self._extract_files_from_json(body)
                if file_text:
                    content = content + "\n" + file_text
                return content

            # Try Anthropic format
            content = _extract_anthropic_content(body)
            if content:
                file_text = self._extract_files_from_json(body)
                if file_text:
                    content = content + "\n" + file_text
                return content

            # Try Google format
            content = _extract_google_content(body)
            if content:
                file_text = self._extract_files_from_json(body)
                if file_text:
                    content = content + "\n" + file_text
                return content

            # Fallback: deep search
            content = _extract_generic_content(body)
            if content:
                file_text = self._extract_files_from_json(body)
                if file_text:
                    content = content + "\n" + file_text
                return content

            # Even if no text content, check for files
            return self._extract_files_from_json(body)

        # Non-JSON body (URL-encoded forms, Gemini batchexecute, etc.)
        # Scan raw text for sensitive patterns directly
        if len(raw) > 10:
            try:
                text = raw.decode("utf-8", errors="replace")
                # Only return if body is substantial (not tiny pings)
                if len(text) > 50:
                    return text
            except Exception:  # noqa: S110
                pass

        return None

    def _extract_files_from_json(self, body: dict) -> str | None:
        """Extract text from base64-encoded images/files in JSON payloads.

        Handles:
        - OpenAI vision: messages[].content[].image_url.url (data:image/...;base64,...)
        - Anthropic: messages[].content[].source.data (base64)
        - Generic: any "data" or "file" field containing base64
        """
        from domestique_app.services.file_scanner import scan_base64

        extracted_parts = []

        # Search for base64 image data in the JSON tree
        base64_items = _find_base64_data(body)

        for item in base64_items:
            result = scan_base64(item["data"], filename=item.get("filename", ""))
            if result.extracted_text:
                extracted_parts.append(result.extracted_text)

        return "\n".join(extracted_parts) if extracted_parts else None

    def _extract_multipart_content(self, flow: http.HTTPFlow) -> str | None:
        """Extract text from multipart/form-data file uploads."""
        from domestique_app.services.file_scanner import scan_file

        content_type = flow.request.headers.get("content-type", "")
        if "boundary=" not in content_type:
            return None

        boundary = content_type.split("boundary=")[1].strip().strip('"')
        parts = flow.request.content.split(f"--{boundary}".encode())

        extracted_parts = []
        for part in parts:
            if not part or part == b"--\r\n":
                continue

            # Split headers from body
            if b"\r\n\r\n" in part:
                header_section, body = part.split(b"\r\n\r\n", 1)
            elif b"\n\n" in part:
                header_section, body = part.split(b"\n\n", 1)
            else:
                continue

            headers_str = header_section.decode("utf-8", errors="replace")

            # Get filename if present
            filename = ""
            if 'filename="' in headers_str:
                filename = headers_str.split('filename="')[1].split('"')[0]

            # Skip tiny parts
            if len(body) < 10:
                continue

            # Scan the file content
            result = scan_file(body.rstrip(b"\r\n"), filename=filename)
            if result.extracted_text:
                extracted_parts.append(result.extracted_text)

        return "\n".join(extracted_parts) if extracted_parts else None

    def _config_changed_since_last_check(self) -> bool:
        """True once per actual on-disk config change (mtime-gated hash
        compare, avoids a JSON parse on the common no-change hot path).

        Shared by the hot-reload check below (ready path) and
        ``_maybe_retry_detector_init`` (not-ready path) so that fixing a
        broken policy file and re-saving config rebuilds the pipeline either
        way -- whether or not the previous background build already failed.
        """
        from domestique_app.services.pipeline_config import (
            config_hash,
            config_mtime_ns,
            load_config_dict,
        )

        mtime = config_mtime_ns()
        if mtime == getattr(self, "_config_mtime", 0):
            return False
        self._config_mtime = mtime
        return config_hash(load_config_dict()) != getattr(self, "_config_hash", "")

    def _maybe_retry_detector_init(self) -> None:
        """Self-heal after a transient detector-construction failure.

        Called from ``_inspect()``'s not-ready branch whenever
        ``self._detector_init_error`` is set (a previous background build
        failed). Without this, ``_wait_for_detector_ready()`` would never
        return True again -- it requires ``self._detector is not None`` --
        and nothing else ever re-triggered ``_init_detector()`` once
        ``_detector_ready`` was set on failure, so a TRANSIENT problem
        (locked/missing policy file, an Ollama blip while resolving a model,
        a disk hiccup) would block 100% of LLM traffic PERMANENTLY until a
        full mitmdump restart.

        Retries in the background (never on the request coroutine --
        rebuilding can be slow) and at most once per
        ``DETECTOR_RETRY_BACKOFF_S`` seconds unless the on-disk config has
        actually changed, so a storm of blocked requests doesn't hammer a
        still-broken dependency. At most one retry runs at a time (guarded
        by ``_detector_retry_lock``).

        Fail-closed holds throughout: this never sets ``self._detector``
        itself and never touches ``_detector_ready`` (already set) -- the
        CURRENT request that triggered this call has already decided to
        fail closed (see the caller) regardless of how this retry turns
        out. Only a LATER request can benefit, once (if) the retry lands.
        """
        try:
            config_changed = self._config_changed_since_last_check()
        except Exception:
            config_changed = False

        now = time.time()
        if (
            not config_changed
            and (now - self._last_detector_retry_ts) < self.DETECTOR_RETRY_BACKOFF_S
        ):
            return
        if not self._detector_retry_lock.acquire(blocking=False):
            return  # a retry attempt is already in flight
        self._last_detector_retry_ts = now
        threading.Thread(
            target=self._retry_detector_init_background,
            daemon=True,
            name="detector-pipeline-retry",
        ).start()

    def _retry_detector_init_background(self) -> None:
        """Background retry of ``_init_detector()`` after a prior failure.

        Runs on the thread started by ``_maybe_retry_detector_init``. On
        success, clears ``self._detector_init_error`` so subsequent requests
        resume normal inspection. On (repeat) failure, records the new
        exception and logs it -- traffic keeps failing closed exactly as
        before, no different from the original failure.
        """
        try:
            try:
                self._init_detector()
            except Exception as e:
                self._detector_init_error = e
                ctx.log.error(f"Detector pipeline retry failed: {e} - still failing closed")
                return
            self._detector_init_error = None
            ctx.log.info("Detector pipeline recovered after previous failure - inspection resumed")
        finally:
            self._detector_retry_lock.release()

    async def _inspect(self, content: str) -> dict:
        """Run content through the detection pipeline.

        Uses mtime check for config changes (avoids JSON parse on hot path).
        Pipeline is rebuilt only when config actually changes.

        Note: detector scan methods (GLiNER, regex) do CPU-bound work inside
        async scan(). For a single-user desktop proxy this is fine. For
        multi-user deployments, wrap in asyncio.to_thread() to
        avoid blocking mitmproxy's event loop on slow detectors.

        Startup race: the pipeline is now built on a background thread (see
        ``load()``), so a request can arrive before it's ready. We hold
        briefly (bounded, see ``DETECTOR_READY_WAIT_S``) for it to finish.
        If it never becomes ready in time -- or construction raised -- this
        fails CLOSED (blocks) rather than letting sensitive data through
        uninspected. A construction failure also triggers a background
        self-heal retry (see ``_maybe_retry_detector_init``) so the lockout
        isn't permanent -- but THIS request still fails closed regardless of
        how that retry turns out.
        """
        try:
            ready = await self._wait_for_detector_ready()
            if not ready:
                if self._detector_init_error is not None:
                    ctx.log.error(
                        "Detection pipeline unavailable "
                        f"({self._detector_init_error}) - failing closed"
                    )
                    self._maybe_retry_detector_init()
                else:
                    ctx.log.error(
                        "Detection pipeline not ready after "
                        f"{self.DETECTOR_READY_WAIT_S}s - failing closed"
                    )
                return {"action": "block", "reasons": ["detectors_unavailable"]}

            if self._config_changed_since_last_check():
                ctx.log.info("Config changed, rebuilding pipeline")
                self._init_detector()

            result = await self._detector.inspect(content)

        except Exception as e:
            ctx.log.error(f"Detection error: {e}")
            return {"action": "block", "reasons": [f"detection_error:{e}"]}

        extra_reasons = self._augment_with_app_services(content)

        if result.should_block or extra_reasons:
            return {
                "action": "block",
                "reasons": [f.description for f in result.findings] + extra_reasons,
            }
        if result.findings and result.redacted_text is not None:
            return {
                "action": "redact",
                "reasons": [f.description for f in result.findings],
                "redacted_content": result.redacted_text,
                "redacted_count": len(result.findings),
            }
        return {"action": "allow"}

    def _augment_with_app_services(self, content: str) -> list[str]:
        """Run app-level detectors that are not part of the core pipeline.

        Currently: prompt-injection and proprietary-code detection. These
        live under ``app/services/`` because they are desktop-app concerns,
        not core firewall detectors. Failures here are logged but do not
        block the request - the core pipeline is already authoritative.
        """
        extra: list[str] = []
        try:
            from domestique_app.services.injection import InjectionDetector, Severity

            inj = InjectionDetector(min_severity=Severity.HIGH).scan(content)
            if inj.is_injection:
                extra.append(f"prompt_injection:{inj.highest_severity.value}")
        except Exception as e:
            ctx.log.debug(f"Injection detector unavailable: {e}")

        try:
            from domestique_app.services.code_detection import CodeDetector

            code = CodeDetector().scan(content)
            if code.is_sensitive:
                extra.extend(f"code:{cat}" for cat in code.categories)
        except Exception as e:
            ctx.log.debug(f"Code detector unavailable: {e}")

        return extra

    def _redact_request(self, flow: http.HTTPFlow, redacted_content: str) -> None:
        """Replace the request body with redacted content."""
        try:
            body = json.loads(flow.request.content)
            # Replace message content in the most common format
            if "messages" in body:
                for msg in reversed(body["messages"]):
                    if msg.get("role") == "user":
                        if isinstance(msg.get("content"), str):
                            msg["content"] = redacted_content
                        break
            flow.request.content = json.dumps(body).encode()
        except (json.JSONDecodeError, KeyError):
            pass

    # --- Response Scanning (Bidirectional DLP, async / non-blocking) -

    async def responseheaders(self, flow: http.HTTPFlow) -> None:
        """Decide whether to stream this response straight through to the
        browser while teeing a copy off for background scanning.

        This fires once response headers arrive, before any body bytes do.
        Setting ``flow.response.stream`` to a callable here is what keeps
        ChatGPT-style token streaming intact: mitmproxy forwards each body
        chunk to the browser AS IT ARRIVES from upstream (the callable's
        return value), instead of buffering the entire response before
        ``response()`` runs -- the old, blocking behavior. The callable
        also appends each chunk to an in-memory buffer so ``response()``
        can hand a COPY of the full body to a background scan once
        streaming completes, without ever delaying delivery.

        Only touches known LLM-host, conversation-path, JSON/SSE API
        responses -- everything else (static assets, other hosts,
        telemetry/polling on an LLM host -- see ``_is_conversation_path``,
        the same filter ``request()`` uses) is left at mitmproxy's default
        (non-streamed) handling, unchanged from before this change. This
        also means non-conversation responses are never logged as
        "inspected", cutting the noise a single chat interaction used to
        generate from background polling/telemetry calls.
        """
        host = flow.request.pretty_host
        if not self._is_llm_endpoint(host):
            return
        if flow.response is None:
            return
        if not self._is_conversation_path(flow.request.path):
            return

        # Skip static assets — only tee API responses (JSON / SSE)
        content_type = flow.response.headers.get("content-type", "")
        is_api_response = "application/json" in content_type or "text/event-stream" in content_type
        if not is_api_response:
            return

        buf = bytearray()
        flow.metadata["domestique_streamed"] = True
        flow.metadata["domestique_response_buf"] = buf
        # The teed bytes are captured off the wire, BEFORE mitmproxy's
        # normal auto-decompression (which only happens when something
        # reads flow.response.content/.text -- never touched on this
        # streamed path, by design). Content-Encoding is known now, at
        # header time, so stash it for the background scan to decode with
        # (see _scan_response_bytes_async / _decode_response_body).
        flow.metadata["domestique_response_encoding"] = flow.response.headers.get(
            "content-encoding", ""
        )

        def _tee(chunk: bytes) -> bytes:
            # Called synchronously by mitmproxy for every body chunk as it
            # arrives from upstream (and once more with b"" at end of
            # body). Must stay cheap and must never block -- the return
            # value is forwarded to the browser immediately.
            if chunk:
                buf.extend(chunk)
            return chunk

        flow.response.stream = _tee

    async def response(self, flow: http.HTTPFlow) -> None:
        """Handle a completed response.

        Two paths:

        1. Streamed (the normal case for real traffic -- see
           ``responseheaders()``): the body already reached the browser
           chunk-by-chunk, untouched. ``flow.response.content`` is
           unavailable (mitmproxy never buffered it, by design). Kick off
           a background scan of the teed COPY and return immediately --
           this hook must never block, because for a streamed response
           there is nothing left it could usefully delay.

        2. Fallback / non-streamed: a response ``responseheaders()``
           chose not to tee (e.g. non-LLM host, or content-type wasn't
           known to be scannable at header time), or a caller that builds
           a flow with content already attached directly (some tests do
           this). Scans synchronously against ``flow.response.content``,
           same as the original alert-mode behavior.
        """
        host = flow.request.pretty_host
        if not self._is_llm_endpoint(host):
            return

        metadata = getattr(flow, "metadata", None)
        if isinstance(metadata, dict) and metadata.get("domestique_streamed") is True:
            buf = metadata.get("domestique_response_buf")
            if buf:
                data = bytes(buf)
                content_type = (
                    flow.response.headers.get("content-type", "") if flow.response else ""
                )
                content_encoding = metadata.get("domestique_response_encoding", "")
                # Fire-and-forget: never await the scan here. The bytes
                # are already gone to the browser, so there is nothing
                # for this hook to block on. The task is kept alive via
                # self._background_tasks (added, then evicted by the done
                # callback) -- an unreferenced asyncio.Task can otherwise
                # be garbage-collected mid-run, silently dropping the
                # scan.
                t = asyncio.create_task(
                    self._scan_response_bytes_async(
                        host=host,
                        path=flow.request.path,
                        content_type=content_type,
                        content_encoding=content_encoding,
                        data=data,
                    )
                )
                self._background_tasks.add(t)
                t.add_done_callback(self._background_tasks.discard)
            return

        if not self._is_conversation_path(flow.request.path):
            return
        if not flow.response or not flow.response.content:
            return
        if len(flow.response.content) < 20:
            return

        # Skip static assets — only scan API responses (JSON / SSE)
        content_type = flow.response.headers.get("content-type", "")
        is_api_response = "application/json" in content_type or "text/event-stream" in content_type
        if not is_api_response:
            return

        # Extract text from response
        response_text = self._extract_response_content(flow)
        if not response_text:
            return

        # Run detection on response content
        result = await self._inspect(response_text)

        if result["action"] in ("block", "redact"):
            reasons = result.get("reasons", [])
            preview = response_text[:200]
            self._report_response_leak(
                host=host,
                path=flow.request.path,
                reasons=reasons,
                preview=preview,
                content_length=len(flow.response.content),
            )

            # Add warning header (doesn't block - alert mode). Only
            # possible on this fallback path: headers haven't reached
            # the client yet, unlike the streamed path above.
            flow.response.headers["X-Domestique-Alert"] = (
                f"Sensitive data detected in response: {','.join(reasons)}"
            )

    async def _scan_response_bytes_async(
        self,
        *,
        host: str,
        path: str,
        content_type: str,
        data: bytes,
        content_encoding: str = "",
    ) -> None:
        """Background scan of a teed response copy.

        Runs as a fire-and-forget ``asyncio.create_task`` kicked off from
        ``response()``. By the time this executes, the real response
        bytes have already reached the browser via the streaming tee
        installed in ``responseheaders()``. A detected leak can only be
        logged/alerted (dashboard stats, debug/request log, audit trail)
        -- it can never block or modify a response that was already
        delivered. This is "detect + surface, don't block" for the
        response direction; the request/prompt DLP path is unaffected and
        still blocks synchronously before forwarding (see ``request()``).

        ``data`` is the RAW wire bytes teed off ``flow.response.stream``
        -- still Content-Encoding'd (gzip/br/zstd/deflate) if the upstream
        sent it that way, because the streaming tee runs before
        mitmproxy's normal auto-decompression would ever kick in (that
        only happens on ``.content``/``.text`` access, which this path
        never does, by design -- see ``responseheaders()``). Decode it
        the same way mitmproxy's own ``Message.content`` would before
        attempting to parse JSON/SSE, or a compressed conversation
        response silently scans as garbage bytes and no leak is ever
        detected -- see ``_decode_response_body``.

        Any failure here is swallowed (logged at debug level only) -- a
        background scan must never surface as an error on the proxied
        flow, which has already completed from the browser's perspective.
        A body that fails to decode is the one exception to "swallow and
        move on": that must be recorded as un-scannable (not silently
        treated as "scanned, clean"), see ``_report_unscannable_response``.
        """
        try:
            if not data:
                return
            try:
                decoded = self._decode_response_body(data, content_encoding)
            except ValueError as exc:
                self._report_unscannable_response(
                    host=host,
                    path=path,
                    content_encoding=content_encoding,
                    error=str(exc),
                )
                return

            if len(decoded) < 20:
                return
            response_text = self._extract_text_from_body(content_type, decoded)
            if not response_text:
                return

            result = await self._inspect(response_text)
            if result["action"] in ("block", "redact"):
                reasons = result.get("reasons", [])
                preview = response_text[:200]
                self._report_response_leak(
                    host=host,
                    path=path,
                    reasons=reasons,
                    preview=preview,
                    content_length=len(decoded),
                )
        except Exception:
            logger.debug("Background response scan failed", exc_info=True)

    def _decode_response_body(self, raw: bytes, content_encoding: str) -> bytes:
        """Decode a raw (possibly Content-Encoding'd) response body the
        same way mitmproxy's own ``Message.content``/``get_content()``
        would (see ``mitmproxy/http.py``), using mitmproxy's own
        ``mitmproxy.net.encoding.decode`` helper -- so the background scan
        of a teed streamed copy sees the identical decompressed bytes the
        pre-streaming code got for free from ``flow.response.content``.

        No/identity/unrecognized-but-blank encoding -> bytes returned
        unchanged (nothing to decode). A real, non-identity encoding that
        fails to decode (corrupt/truncated body, or a server advertising
        an encoding it didn't actually use) raises ``ValueError`` -- the
        caller must treat that as "could not be scanned," never as
        "scanned, nothing found."
        """
        encoding = (content_encoding or "").strip().lower()
        if not encoding or encoding == "identity":
            return raw
        decoded = mitm_encoding.decode(raw, encoding)
        if isinstance(decoded, str):
            # A server may illegally specify a byte->str codec name (e.g.
            # "utf-8") in Content-Encoding -- mitmproxy's own get_content()
            # treats this as invalid too.
            raise ValueError(f"Invalid Content-Encoding: {encoding!r}")
        return decoded

    def _report_unscannable_response(
        self,
        *,
        host: str,
        path: str,
        content_encoding: str,
        error: str,
    ) -> None:
        """A teed response body could not be decoded, so the background
        scan never got to inspect it for a leak -- do NOT let this pass
        silently (that would be indistinguishable from "scanned, clean").
        Records a dedicated stats counter (kept separate from
        ``response_alerts`` -- see ``__init__``), a request-log entry, and
        a proxy-log warning, mirroring how a detected leak is surfaced via
        ``_report_response_leak`` so both are equally visible to the
        dashboard/debug log/audit trail.
        """
        self._stats["response_scan_errors"] = self._stats.get("response_scan_errors", 0) + 1
        self._persist_stats()
        self._log_request(
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "host": host,
                "method": "RESPONSE",
                "path": path[:100],
                "action": "response_undecodable",
                "reasons": [f"content-encoding={content_encoding!r}: {error}"],
                "direction": "inbound",
            }
        )
        ctx.log.warn(
            f"RESPONSE UNSCANNABLE from {host}: could not decode "
            f"Content-Encoding={content_encoding!r} ({error}) -- this "
            f"response body was NOT scanned for a data leak"
        )

    def _report_response_leak(
        self,
        *,
        host: str,
        path: str,
        reasons: list[str],
        preview: str,
        content_length: int,
    ) -> None:
        """Record a detected response-side leak: stats counter, request
        log entry, audit event, and a proxy-log warning. Shared by the
        synchronous fallback scan and the async background scan
        (``response()`` / ``_scan_response_bytes_async()``) so both
        surface leaks identically to the dashboard and debug log.
        """
        self._stats["response_alerts"] += 1
        self._persist_stats()
        self._log_request(
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "host": host,
                "method": "RESPONSE",
                "path": path[:100],
                "action": "response_alert",
                "reasons": reasons,
                "content_preview": preview,
                "direction": "inbound",
            }
        )
        self._emit_audit_event(
            action="response_alert",
            host=host,
            method="RESPONSE",
            path=path,
            reasons=reasons,
            latency_ms=0,
            content_length=content_length,
            content_preview=preview,
        )
        ctx.log.warn(f"RESPONSE ALERT from {host}: sensitive data in response - {reasons}")

    def _extract_response_content(self, flow: http.HTTPFlow) -> str | None:
        """Extract text content from an LLM response body attached to a
        flow (the non-streamed / fallback path -- ``flow.response.content``
        is available). Delegates to ``_extract_text_from_body`` so the
        streamed async-scan path (which only has raw bytes, no flow) uses
        the identical extraction logic.
        """
        if not flow.response or not flow.response.content:
            return None
        content_type = flow.response.headers.get("content-type", "")
        return self._extract_text_from_body(content_type, flow.response.content)

    def _extract_text_from_body(self, content_type: str, raw: bytes) -> str | None:
        """Extract text content from a raw response body + content-type.

        Handles streaming (SSE) and JSON response formats. Shared by the
        flow-based fallback path (``_extract_response_content``) and the
        background async-scan path (``_scan_response_bytes_async``, which
        only has a teed byte copy, not a live flow).
        """
        # Handle Server-Sent Events (streaming responses)
        if "text/event-stream" in content_type:
            return self._extract_sse_content(raw)

        # Handle JSON responses
        try:
            body = json.loads(raw)
            if isinstance(body, dict):
                return self._extract_response_text(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # Fallback: raw text if substantial
        try:
            text = raw.decode("utf-8", errors="replace")
            return text if len(text) > 50 else None
        except Exception:
            return None

    def _extract_sse_content(self, raw: bytes) -> str | None:
        """Extract text from SSE (Server-Sent Events) stream.

        Parses data: lines from SSE format, extracts content deltas.
        """
        texts = []
        try:
            for line in raw.decode("utf-8", errors="replace").split("\n"):
                if not line.startswith("data: "):
                    continue
                data = line[6:]
                if data == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                    # OpenAI streaming format
                    choices = chunk.get("choices", [])
                    for choice in choices:
                        delta = choice.get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            texts.append(content)
                    # Anthropic streaming format
                    if chunk.get("type") == "content_block_delta":
                        delta = chunk.get("delta", {})
                        if delta.get("type") == "text_delta":
                            texts.append(delta.get("text", ""))
                except json.JSONDecodeError:
                    pass
        except Exception:  # noqa: S110
            pass

        return "".join(texts) if texts else None

    def _extract_response_text(self, body: dict) -> str | None:
        """Extract assistant message text from a JSON response body."""
        texts = []

        # OpenAI format: {choices: [{message: {content: "..."}}]}
        for choice in body.get("choices", []):
            msg = choice.get("message", {})
            content = msg.get("content", "")
            if isinstance(content, str) and content:
                texts.append(content)

        # Anthropic format: {content: [{type: "text", text: "..."}]}
        for block in body.get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                texts.append(block.get("text", ""))

        # Google format: {candidates: [{content: {parts: [{text: "..."}]}}]}
        for candidate in body.get("candidates", []):
            content = candidate.get("content", {})
            for part in content.get("parts", []):
                if "text" in part:
                    texts.append(part["text"])

        # Generic: {response: "..."} or {output: "..."}
        for key in ("response", "output", "result", "text", "completion"):
            if key in body and isinstance(body[key], str):
                texts.append(body[key])

        return "\n".join(texts) if texts else None


# --- Content extractors ----------------------------------------------


def _extract_openai_content(body: dict) -> str | None:
    """Extract from OpenAI/ChatGPT format: {messages: [{role, content}]}.

    Handles both API format (content is string/array) and web app format
    (content is {"content_type": "text", "parts": [...]}).
    """
    messages = body.get("messages", [])
    if not messages:
        return None
    # Get the last user message
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                return content
            # Handle multimodal content (array of parts)
            if isinstance(content, list):
                text_parts = [
                    p.get("text", "")
                    for p in content
                    if isinstance(p, dict) and p.get("type") == "text"
                ]
                # Also handle plain string parts
                text_parts += [p for p in content if isinstance(p, str)]
                return "\n".join(text_parts) if text_parts else None
            # Handle ChatGPT web format: {"content_type": "text", "parts": [...]}
            if isinstance(content, dict):
                parts = content.get("parts", [])
                texts = [p for p in parts if isinstance(p, str)]
                return "\n".join(texts) if texts else None
    return None


def _extract_anthropic_content(body: dict) -> str | None:
    """Extract from Anthropic format: {messages: [{role, content}]} + system."""
    parts = []
    if "system" in body:
        parts.append(str(body["system"]))
    messages = body.get("messages", [])
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if block.get("type") == "text":
                        parts.append(block.get("text", ""))
            break
    return "\n".join(parts) if parts else None


def _extract_google_content(body: dict) -> str | None:
    """Extract from Google/Gemini format: {contents: [{parts: [{text}]}]}."""
    contents = body.get("contents", [])
    if not contents:
        return None
    # Last content entry
    last = contents[-1]
    parts = last.get("parts", [])
    texts = [p.get("text", "") for p in parts if "text" in p]
    return "\n".join(texts) if texts else None


def _extract_generic_content(body: dict) -> str | None:
    """Fallback: deep-search for user message text in any nested structure.

    ChatGPT web app (2026) uses deeply nested formats that don't match
    standard API schemas. This recursively finds all substantial text.
    """
    # Try common top-level fields first
    for key in ("prompt", "input", "query", "text", "content"):
        if key in body and isinstance(body[key], str) and len(body[key]) > 5:
            return body[key]

    # Deep recursive extraction of all text content
    texts = []
    _extract_texts_recursive(body, texts, depth=0)
    # Filter out short strings (UUIDs, timestamps, IDs)
    meaningful = [t for t in texts if len(t) > 20 and not _is_metadata(t)]
    return "\n".join(meaningful) if meaningful else None


def _extract_texts_recursive(obj: object, texts: list, depth: int = 0) -> None:
    """Recursively find all text strings in a nested structure."""
    if depth > 10:
        return
    if isinstance(obj, str):
        if len(obj) > 5:
            texts.append(obj)
    elif isinstance(obj, dict):
        for _key, val in obj.items():
            _extract_texts_recursive(val, texts, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _extract_texts_recursive(item, texts, depth + 1)


def _is_metadata(text: str) -> bool:
    """Check if a string looks like metadata rather than user content."""
    import re as _re

    # UUID pattern
    if _re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", text):
        return True
    # ISO timestamp
    if _re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", text):
        return True
    # Timezone names
    return bool(text.count("/") == 1 and all(c.isalpha() or c in "/_" for c in text))


def _find_base64_data(obj: object, depth: int = 0) -> list[dict]:
    """Recursively find base64-encoded file data in a JSON structure.

    Looks for patterns used by major LLM APIs:
    - OpenAI vision: {"type": "image_url", "image_url": {"url": "data:image/...;base64,..."}}
    - Anthropic: {"type": "image", "source": {"type": "base64", "data": "..."}}
    - Generic: any string that looks like base64 data (>100 chars, valid charset)

    Returns:
        List of dicts: [{"data": "base64string", "filename": "optional.png"}]
    """
    if depth > 8:
        return []

    results = []

    if isinstance(obj, dict):
        # OpenAI vision format
        if obj.get("type") == "image_url":
            url = obj.get("image_url", {}).get("url", "")
            if url.startswith("data:") and ";base64," in url:
                results.append({"data": url, "filename": "image.png"})
                return results

        # Anthropic image format
        if obj.get("type") == "image" and "source" in obj:
            source = obj["source"]
            if isinstance(source, dict) and source.get("type") == "base64":
                media_type = source.get("media_type", "image/png")
                ext = media_type.split("/")[-1] if "/" in media_type else "bin"
                results.append(
                    {
                        "data": source.get("data", ""),
                        "filename": f"image.{ext}",
                    }
                )
                return results

        # Generic: look for file_data, image_data, attachment fields
        for key in ("file_data", "image_data", "attachment", "file_content"):
            if key in obj and isinstance(obj[key], str) and len(obj[key]) > 100:  # noqa: SIM102
                if _looks_like_base64(obj[key]):
                    results.append({"data": obj[key], "filename": obj.get("filename", "")})

        # Recurse
        for val in obj.values():
            results.extend(_find_base64_data(val, depth + 1))

    elif isinstance(obj, list):
        for item in obj:
            results.extend(_find_base64_data(item, depth + 1))

    return results


def _looks_like_base64(text: str) -> bool:
    """Quick heuristic: does this string look like base64-encoded binary?"""
    if len(text) < 100:
        return False
    # Check first 100 chars for valid base64 charset
    sample = text[:100].replace("\n", "").replace("\r", "")
    import re as _re

    return bool(_re.match(r"^[A-Za-z0-9+/=]+$", sample))


# mitmproxy addon entry point
addons = [DomestiqueAddon()]
