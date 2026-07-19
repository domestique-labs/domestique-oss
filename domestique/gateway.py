"""Domestique OSS CLI wedge - transparent redacting reverse proxy.

Routes a request by path to a provider (OpenAI/Anthropic), scans+redacts the
prompt text using the existing detection pipeline, then forwards the redacted
bytes to the real upstream (streaming), passing the client's own API key
through. Responses stream back untouched.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx
import structlog
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from domestique.config import Settings
from domestique.detectors.registry import DetectorPipeline, build_detectors
from domestique.extract import extract_texts
from domestique.models import Action
from domestique.policy import PolicyEngine
from domestique.redact import apply_field_redactions

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

logger = structlog.get_logger()

# path -> (provider, extraction kind)
ROUTES: dict[str, tuple[str, str]] = {
    "/v1/chat/completions": ("openai", "openai_chat"),
    "/v1/completions": ("openai", "openai_completions"),
    "/v1/embeddings": ("openai", "openai_embeddings"),
    "/v1/messages": ("anthropic", "anthropic_messages"),
}

_DEFAULT_UPSTREAMS = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
}
_UPSTREAM_ENV = {
    "openai": "DOMESTIQUE_OPENAI_UPSTREAM",
    "anthropic": "DOMESTIQUE_ANTHROPIC_UPSTREAM",
}

_CLI_POLICY = Path(__file__).resolve().parent / "policy" / "cli-rules.yaml"

# hop-by-hop headers that must not be forwarded (RFC 7230 6.1) + host/length.
_STRIP_REQUEST_HEADERS = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
}
# We relay the upstream body verbatim via aiter_raw() (still compressed), so
# content-encoding MUST be preserved for the client to decode it. Only the
# framing headers change (StreamingResponse re-frames the transfer).
_STRIP_RESPONSE_HEADERS = {
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
}


def upstream_base(provider: str) -> str:
    """Resolve the upstream base URL for *provider*, honoring env overrides."""
    override = os.environ.get(_UPSTREAM_ENV[provider], "").strip()
    return override.rstrip("/") if override else _DEFAULT_UPSTREAMS[provider]


def build_cli_pipeline(settings: Settings | None = None) -> DetectorPipeline:
    """Build the detection pipeline with the redact-first CLI policy."""
    settings = settings or Settings()
    return DetectorPipeline(
        detectors=build_detectors(settings),
        policy=PolicyEngine.from_yaml(_CLI_POLICY),
    )


async def _scan_and_redact(
    pipeline: DetectorPipeline, body: dict[str, Any], kind: str
) -> tuple[Action, str, dict[str, Any], list[str]]:
    """Return ``(action, reason, possibly-redacted body, driving categories)``.

    The category list feeds the live ticker and the metadata-only audit log; it
    never contains any prompt text.
    """
    texts = extract_texts(body, kind)
    redactions: list[tuple[str, str]] = []
    categories: set[str] = set()
    for field_path, text in texts:
        result = await pipeline.inspect(text)
        if result.action is Action.BLOCK:
            blocked = sorted({f.category for f in result.findings})
            return Action.BLOCK, result.reason, body, blocked
        if result.action is Action.REDACT and result.redacted_text is not None:
            redactions.append((field_path, result.redacted_text))
            categories.update(f.category for f in result.findings)
    if redactions:
        redacted_body = apply_field_redactions(body, redactions)
        return Action.REDACT, "redacted", redacted_body, sorted(categories)
    return Action.ALLOW, "", body, []


def _upstream_host(provider: str) -> str:
    """Human-readable upstream host (e.g. ``api.anthropic.com``) for feedback."""
    return urlparse(upstream_base(provider)).netloc or provider


def _emit_decision(app: FastAPI, action: Action, categories: list[str], host: str) -> None:
    """Record the decision to the audit log and fire the live-feedback callback."""
    audit = getattr(app.state, "audit", None)
    if audit is not None:
        audit.record_event(action=action, categories=categories, endpoint=host)
    callback = getattr(app.state, "on_decision", None)
    if callback is not None:
        try:
            callback(action, categories, host)
        except Exception:  # never let a display callback break the proxy
            logger.debug("on_decision_callback_error")


def _block_response(provider: str, reason: str) -> JSONResponse:
    if provider == "anthropic":
        return JSONResponse(
            status_code=403,
            content={
                "type": "error",
                "error": {
                    "type": "firewall_block",
                    "message": f"Blocked by Domestique: {reason}",
                },
            },
        )
    return JSONResponse(
        status_code=403,
        content={
            "error": {
                "message": f"Blocked by Domestique: {reason}",
                "type": "firewall_block",
            }
        },
    )


def _forward_headers(request: Request, provider: str, settings: Settings) -> dict[str, str]:
    headers = {k: v for k, v in request.headers.items() if k.lower() not in _STRIP_REQUEST_HEADERS}
    present = {k.lower() for k in headers}
    # Fall back to a server-side env key only if the client sent none.
    if provider == "openai" and "authorization" not in present and settings.openai_api_key:
        headers["Authorization"] = f"Bearer {settings.openai_api_key}"
    if provider == "anthropic" and "x-api-key" not in present and settings.anthropic_api_key:
        headers["x-api-key"] = settings.anthropic_api_key
    return headers


def _relay(upstream_resp: httpx.Response) -> StreamingResponse:
    """Stream an upstream httpx response back to the client, unmodified."""

    async def body_iter() -> AsyncIterator[bytes]:
        try:
            async for chunk in upstream_resp.aiter_raw():
                yield chunk
        finally:
            await upstream_resp.aclose()

    out_headers = {
        k: v for k, v in upstream_resp.headers.items() if k.lower() not in _STRIP_RESPONSE_HEADERS
    }
    return StreamingResponse(
        body_iter(),
        status_code=upstream_resp.status_code,
        headers=out_headers,
        media_type=upstream_resp.headers.get("content-type"),
    )


async def _passthrough(request: Request, provider: str, path: str, raw: bytes) -> Response:
    """Forward a request upstream untouched (no scanning)."""
    settings: Settings = request.app.state.settings
    client: httpx.AsyncClient = request.app.state.http
    url = f"{upstream_base(provider)}{path}"
    headers = _forward_headers(request, provider, settings)
    upstream_req = client.build_request(
        request.method,
        url,
        content=raw or None,
        headers=headers,
        params=request.url.query or None,
    )
    upstream_resp = await client.send(upstream_req, stream=True)
    return _relay(upstream_resp)


async def _proxy(request: Request, path: str) -> Response:
    """Scan+redact then forward a routed provider request."""
    provider, kind = ROUTES[path]
    settings: Settings = request.app.state.settings
    pipeline: DetectorPipeline = request.app.state.pipeline
    client: httpx.AsyncClient = request.app.state.http

    raw = await request.body()
    try:
        parsed: Any = json.loads(raw)
    except Exception:
        # Not JSON we understand - forward untouched (fail-safe transparency).
        return await _passthrough(request, provider, path, raw)
    if not isinstance(parsed, dict):
        return await _passthrough(request, provider, path, raw)

    action, reason, out_body, categories = await _scan_and_redact(pipeline, parsed, kind)
    host = _upstream_host(provider)
    if action is Action.BLOCK:
        # The clean ticker (_emit_decision) + metadata audit log are the block's
        # user-facing signals; no separate raw structlog line (it read as noise
        # and made --quiet look broken).
        _emit_decision(request.app, Action.BLOCK, categories, host)
        return _block_response(provider, reason)
    if action is Action.REDACT:
        _emit_decision(request.app, Action.REDACT, categories, host)

    payload = json.dumps(out_body).encode("utf-8")
    url = f"{upstream_base(provider)}{path}"
    headers = _forward_headers(request, provider, settings)
    headers["content-type"] = "application/json"

    upstream_req = client.build_request("POST", url, content=payload, headers=headers)
    upstream_resp = await client.send(upstream_req, stream=True)
    return _relay(upstream_resp)


def create_gateway(
    settings: Settings | None = None,
    *,
    pipeline: DetectorPipeline | None = None,
    on_decision: Callable[[Action, list[str], str], None] | None = None,
    audit_path: str | Path | None = None,
    enable_audit: bool = True,
) -> FastAPI:
    """Construct the transparent redacting reverse-proxy app.

    ``on_decision`` is invoked (action, categories, host) on each redact/block
    for live terminal feedback. Redact/block decisions are also appended to a
    metadata-only audit log (``enable_audit``) for ``domestique report``.
    """
    resolved = settings or Settings()
    built_pipeline = pipeline or build_cli_pipeline(resolved)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.http = httpx.AsyncClient(timeout=resolved.upstream_timeout_s)
        app.state.audit = None
        if enable_audit:
            try:
                from domestique.audit import AuditLogger
                from domestique.report import default_audit_path

                path = audit_path or default_audit_path()
                app.state.audit = AuditLogger(str(path))
            except Exception:  # audit must never block the proxy from starting
                logger.warning("audit_init_failed")
        try:
            yield
        finally:
            await app.state.http.aclose()
            if app.state.audit is not None:
                app.state.audit.close()

    app = FastAPI(title="Domestique Proxy", version="0.1.0", lifespan=lifespan)
    app.state.settings = resolved
    app.state.pipeline = built_pipeline
    app.state.on_decision = on_decision

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "healthy"}

    def _make_handler(route_path: str) -> Callable[[Request], Awaitable[Response]]:
        async def handler(request: Request) -> Response:
            return await _proxy(request, route_path)

        return handler

    for route_path in ROUTES:
        app.add_api_route(route_path, _make_handler(route_path), methods=["POST"])

    # Catch-all passthrough for anything else (e.g. GET /v1/models).
    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def catch_all(request: Request, full_path: str) -> Response:
        raw = await request.body()
        return await _passthrough(request, "openai", f"/{full_path}", raw)

    return app
