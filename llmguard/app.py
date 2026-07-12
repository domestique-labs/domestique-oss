"""LLM Firewall - FastAPI application factory.

The app is constructed via ``create_app()`` for testability. In production
uvicorn imports this module and calls the factory.

Request flow:
  1. Extract text fields from the JSON body.
  2. Run all detectors in parallel (asyncio.gather).
  3. Evaluate findings against policy rules.
  4. Block / redact / forward depending on the verdict.

Latency budget:
  - Text extraction:   ~0.01 ms
  - Secret scanning:   ~0.1 ms  (compiled regex, single pass)
  - PII scanning:      ~5 ms    (spaCy NER, skipped if regex finds nothing)
  - Policy evaluation: ~0.01 ms
  - Upstream forward:  ~200-5000 ms (LLM provider RTT - not our overhead)
  Total firewall overhead target: < 10 ms p99
"""

from __future__ import annotations

import asyncio
import copy
import time
from contextlib import asynccontextmanager, suppress
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from llmguard.audit import AuditLogger
from llmguard.config import Settings
from llmguard.debug_trace import (
    append_debug_trace,
    detection_fields,
    join_prompts,
    prompt_fields,
)
from llmguard.detectors.registry import build_detectors
from llmguard.models import Action, Detection
from llmguard.policy import PolicyEngine
from llmguard.transport import LLMProxy

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from llmguard.detectors import Detector

logger = structlog.get_logger()


# --- Application Factory ----------------------------------------------------


def create_app(settings: Settings | None = None) -> FastAPI:
    """Construct and wire the FastAPI application."""
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
        logger.info("firewall_starting", fail_mode=settings.fail_mode)
        yield
        _app.state.audit.close()
        logger.info("firewall_stopped")

    app = FastAPI(
        title="LLM Firewall",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Wire dependencies into app state for handler access.
    app.state.settings = settings
    app.state.detectors = build_detectors(settings)
    app.state.policy = PolicyEngine.from_yaml(settings.policy_path)
    app.state.proxy = LLMProxy(settings)
    app.state.audit = AuditLogger(settings.audit_log_path)

    _register_routes(app)
    return app


# --- Route Handlers ---------------------------------------------------------


def _register_routes(app: FastAPI) -> None:
    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "healthy"}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        return await _handle_request(request, endpoint="/v1/chat/completions")

    @app.post("/v1/completions")
    async def completions(request: Request) -> JSONResponse:
        return await _handle_request(request, endpoint="/v1/completions")

    @app.post("/v1/embeddings")
    async def embeddings(request: Request) -> JSONResponse:
        return await _handle_request(request, endpoint="/v1/embeddings")

    @app.post("/chat/completions")
    async def chat_completions_alt(request: Request) -> JSONResponse:
        """Anthropic-style path (no /v1 prefix)."""
        return await _handle_request(request, endpoint="/chat/completions")


async def _handle_request(request: Request, *, endpoint: str) -> JSONResponse:
    """Unified request pipeline: parse -> detect -> decide -> act."""
    t0 = time.perf_counter()
    request_id = str(uuid4())
    settings: Settings = request.app.state.settings
    detectors: list[Detector] = request.app.state.detectors
    policy: PolicyEngine = request.app.state.policy
    proxy: LLMProxy = request.app.state.proxy
    audit: AuditLogger = request.app.state.audit

    # 1. Parse body
    try:
        body: dict[str, Any] = await request.json()
    except Exception:
        raw_body = ""
        with suppress(Exception):
            raw_body = (await request.body()).decode("utf-8", errors="replace")
        append_debug_trace(
            {
                "request_id": request_id,
                "source": "api_proxy",
                "direction": "outbound",
                "action": "invalid_json",
                "reason": "invalid JSON body",
                "endpoint": endpoint,
                "method": request.method,
                "raw_body": raw_body,
            }
        )
        return JSONResponse(
            status_code=400,
            content={"error": {"message": "Invalid JSON", "type": "invalid_request"}},
        )

    user_id = _user_from_headers(request)
    model = body.get("model", "unknown")

    # 2. Extract text fields
    texts = _extract_texts(body, endpoint)
    if not texts:
        latency_ms = (time.perf_counter() - t0) * 1000
        append_debug_trace(
            {
                "request_id": request_id,
                "source": "api_proxy",
                "direction": "outbound",
                "action": "pass",
                "reason": "no scannable prompt content",
                "endpoint": endpoint,
                "method": request.method,
                "model": model,
                "user_id": user_id,
                "latency_ms": round(latency_ms, 1),
                "request_json": body,
            }
        )
        # No scannable content - forward immediately (zero overhead).
        return await _forward_and_respond(proxy, body, settings)

    # 3. Run all detectors in parallel across all text fields.
    all_detections = await _run_detectors(detectors, texts)

    # 4. Evaluate policy
    action, reason = policy.explain(all_detections)
    latency_ms = (time.perf_counter() - t0) * 1000

    # 5. Audit
    audit.record(
        action=action,
        user_id=user_id,
        model=model,
        endpoint=endpoint,
        detections=all_detections,
        latency_ms=latency_ms,
        metadata={"request_id": request_id},
    )

    # 6. Act
    if action is Action.BLOCK:
        _trace_policy_decision(
            request_id=request_id,
            request=request,
            endpoint=endpoint,
            action=action,
            reason=reason,
            model=model,
            user_id=user_id,
            texts=texts,
            detections=all_detections,
            latency_ms=latency_ms,
        )
        logger.warning(
            "request_blocked",
            user=user_id,
            reason=reason,
            findings=len(all_detections),
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": f"Request blocked by LLM Firewall: {reason}",
                    "type": "firewall_block",
                }
            },
        )

    if action is Action.REDACT:
        body = _apply_redactions(body, endpoint, texts, all_detections)
        _trace_policy_decision(
            request_id=request_id,
            request=request,
            endpoint=endpoint,
            action=action,
            reason=reason,
            model=model,
            user_id=user_id,
            texts=texts,
            detections=all_detections,
            latency_ms=latency_ms,
            redacted_texts=_extract_texts(body, endpoint),
        )
    else:
        _trace_policy_decision(
            request_id=request_id,
            request=request,
            endpoint=endpoint,
            action=action,
            reason=reason,
            model=model,
            user_id=user_id,
            texts=texts,
            detections=all_detections,
            latency_ms=latency_ms,
        )

    return await _forward_and_respond(proxy, body, settings)


# --- Helpers -----------------------------------------------------------------


def _trace_policy_decision(
    *,
    request_id: str,
    request: Request,
    endpoint: str,
    action: Action,
    reason: str,
    model: Any,
    user_id: str,
    texts: list[tuple[str, str]],
    detections: list[Detection],
    latency_ms: float,
    redacted_texts: list[tuple[str, str]] | None = None,
) -> None:
    """Write the raw prompt decision trace for a proxied API request."""
    event: dict[str, Any] = {
        "request_id": request_id,
        "source": "api_proxy",
        "direction": "outbound",
        "action": "allowed" if action is Action.ALLOW else action.value,
        "reason": reason,
        "endpoint": endpoint,
        "method": request.method,
        "model": model,
        "user_id": user_id,
        "prompt": join_prompts(texts),
        "prompt_fields": prompt_fields(texts),
        "detections": detection_fields(detections),
        "findings": len(detections),
        "latency_ms": round(latency_ms, 1),
    }
    if redacted_texts is not None:
        event["redacted_prompt"] = join_prompts(redacted_texts)
        event["redacted_prompt_fields"] = prompt_fields(redacted_texts)
    append_debug_trace(event)


async def _run_detectors(
    detectors: list[Detector], texts: list[tuple[str, str]]
) -> list[Detection]:
    """Run all detectors on all text fields concurrently.

    Creates one coroutine per (detector, text) pair and awaits them together.
    For N detectors and M text fields this is O(1) wall-clock time (parallel).
    """
    tasks = []
    field_paths = []

    for field_path, text in texts:
        for detector in detectors:
            tasks.append(detector.scan(text))
            field_paths.append(field_path)

    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_detections: list[Detection] = []
    for i, result in enumerate(results):
        if isinstance(result, BaseException):
            logger.error("detector_error", error=str(result))
            continue
        for det in result:
            det.field_path = field_paths[i]
            all_detections.append(det)

    return all_detections


def _extract_texts(body: dict[str, Any], endpoint: str) -> list[tuple[str, str]]:
    """Extract (field_path, text) pairs from the request body.

    Only user-provided content is scanned; system prompts are optionally skipped
    since they are controlled by the application developer, not the end-user.
    """
    texts: list[tuple[str, str]] = []

    if endpoint in ("/v1/chat/completions", "/chat/completions"):
        for i, msg in enumerate(body.get("messages", [])):
            content = msg.get("content", "")
            if isinstance(content, str) and content:
                texts.append((f"messages.{i}.content", content))
            elif isinstance(content, list):
                for j, part in enumerate(content):
                    if isinstance(part, dict) and part.get("type") == "text":
                        texts.append((f"messages.{i}.content.{j}.text", part.get("text", "")))

    elif endpoint == "/v1/completions":
        prompt = body.get("prompt", "")
        if isinstance(prompt, str) and prompt:
            texts.append(("prompt", prompt))
        elif isinstance(prompt, list):
            for i, p in enumerate(prompt):
                if isinstance(p, str):
                    texts.append((f"prompt.{i}", p))

    elif endpoint == "/v1/embeddings":
        inp = body.get("input", "")
        if isinstance(inp, str) and inp:
            texts.append(("input", inp))
        elif isinstance(inp, list):
            for i, t in enumerate(inp):
                if isinstance(t, str):
                    texts.append((f"input.{i}", t))

    return texts


def _apply_redactions(
    body: dict[str, Any],
    endpoint: str,
    texts: list[tuple[str, str]],
    detections: list[Detection],
) -> dict[str, Any]:
    """Return a deep copy of the body with detected spans replaced by placeholders."""
    body = copy.deepcopy(body)

    for field_path, original in texts:
        field_dets = sorted(
            (d for d in detections if d.field_path == field_path),
            key=lambda d: d.span.start,
            reverse=True,
        )
        if not field_dets:
            continue

        redacted = original
        for det in field_dets:
            placeholder = f"[{det.category.upper()}_REDACTED]"
            redacted = redacted[: det.span.start] + placeholder + redacted[det.span.end :]

        _set_by_path(body, field_path, redacted)

    return body


def _set_by_path(obj: Any, path: str, value: str) -> None:
    """Set a value in a nested dict/list using dot-notation path."""
    parts = path.split(".")
    for part in parts[:-1]:
        obj = obj[int(part)] if part.isdigit() else obj[part]
    last = parts[-1]
    if last.isdigit():
        obj[int(last)] = value
    else:
        obj[last] = value


def _user_from_headers(request: Request) -> str:
    """Extract a user identifier from the Authorization header."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer ") and len(auth) > 15:
        return f"bearer:{auth[7:15]}…"
    return "anonymous"


async def _forward_and_respond(
    proxy: LLMProxy, body: dict[str, Any], settings: Settings
) -> JSONResponse:
    """Forward to upstream and handle errors according to fail-mode."""
    try:
        response = await proxy.forward(body)
        return JSONResponse(content=response)
    except Exception as exc:
        logger.error("upstream_error", error=str(exc))
        if settings.fail_mode == "closed":
            return JSONResponse(
                status_code=502,
                content={
                    "error": {
                        "message": "Upstream unavailable (fail-closed mode)",
                        "type": "upstream_error",
                    }
                },
            )
        raise


# --- Entry Point -------------------------------------------------------------

app = create_app()
