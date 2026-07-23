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
from domestique.vault.stream import StreamDetokenizer

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable
    from collections.abc import Set as AbstractSet

    from domestique.vault.service import TokenService

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


def build_cli_pipeline(
    settings: Settings | None = None,
    token_service: TokenService | None = None,
) -> DetectorPipeline:
    """Build the detection pipeline with the redact-first CLI policy.

    With a ``token_service`` the pipeline mints reversible numbered tokens
    (``[SSN_1]``) instead of flat ``[..._REDACTED]`` placeholders.
    """
    settings = settings or Settings()
    return DetectorPipeline(
        detectors=build_detectors(settings),
        policy=PolicyEngine.from_yaml(_CLI_POLICY),
        token_service=token_service,
    )


async def _scan_and_redact(
    pipeline: DetectorPipeline, body: dict[str, Any], kind: str
) -> tuple[Action, str, dict[str, Any], list[str], set[str]]:
    """Return ``(action, reason, redacted body, driving categories, minted tokens)``.

    ``categories`` feeds the live ticker and the metadata-only audit log; it
    never contains any prompt text. ``minted`` is exactly the tokens present in
    the outbound (redacted) request — response detokenization is scoped to it so
    a reply can only ever reveal secrets this request itself redacted, never a
    token minted for another conversation sharing the process-wide store.
    """
    texts = extract_texts(body, kind)
    redactions: list[tuple[str, str]] = []
    categories: set[str] = set()
    minted: set[str] = set()
    for field_path, text in texts:
        result = await pipeline.inspect(text)
        if result.action is Action.BLOCK:
            blocked = sorted({f.category for f in result.findings})
            return Action.BLOCK, result.reason, body, blocked, set()
        if result.action is Action.REDACT and result.redacted_text is not None:
            redactions.append((field_path, result.redacted_text))
            categories.update(f.category for f in result.findings)
            # Precisely the tokens this redaction minted — NOT every
            # token-shaped substring in the body, so a literal ``[SSN_1]``
            # the user typed can never widen the response's reversal scope.
            minted.update(result.minted_tokens)
    if redactions:
        redacted_body = apply_field_redactions(body, redactions)
        return Action.REDACT, "redacted", redacted_body, sorted(categories), minted
    return Action.ALLOW, "", body, [], set()


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


def _relay(
    upstream_resp: httpx.Response,
    token_service: TokenService | None = None,
    allowed: AbstractSet[str] | None = None,
) -> Response:
    """Stream an upstream response back to the client.

    Without a ``token_service`` (or for non-text payloads) bytes are relayed
    verbatim. With one, redaction tokens in the response are rewritten back
    to their original values — buffered for JSON bodies, incrementally (with
    bounded holdback) for SSE streams. ``allowed`` scopes which tokens may be
    reversed to the ones this request minted (see ``_scan_and_redact``).
    """
    content_type = upstream_resp.headers.get("content-type", "")
    out_headers = {
        k: v for k, v in upstream_resp.headers.items() if k.lower() not in _STRIP_RESPONSE_HEADERS
    }

    if token_service is not None and "text/event-stream" in content_type:
        out_headers.pop("content-length", None)
        return StreamingResponse(
            _detok_sse_iter(upstream_resp, token_service, allowed),
            status_code=upstream_resp.status_code,
            headers=out_headers,
            media_type=content_type,
        )

    if token_service is not None and "application/json" in content_type:
        out_headers.pop("content-length", None)

        async def json_iter() -> AsyncIterator[bytes]:
            try:
                body = await upstream_resp.aread()
            finally:
                await upstream_resp.aclose()
            yield _detok_json_bytes(body, token_service, allowed)

        return StreamingResponse(
            json_iter(),
            status_code=upstream_resp.status_code,
            headers=out_headers,
            media_type=content_type,
        )

    async def body_iter() -> AsyncIterator[bytes]:
        try:
            async for chunk in upstream_resp.aiter_raw():
                yield chunk
        finally:
            await upstream_resp.aclose()

    return StreamingResponse(
        body_iter(),
        status_code=upstream_resp.status_code,
        headers=out_headers,
        media_type=upstream_resp.headers.get("content-type"),
    )


#: JSON keys whose string values carry assistant-visible text.
_TEXT_KEYS = ("content", "text", "output_text", "delta")


def _detok_json_bytes(
    body: bytes, service: TokenService, allowed: AbstractSet[str] | None = None
) -> bytes:
    """Detokenize every string value in a buffered JSON body."""
    try:
        obj = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return body

    unknown: list[str] = []

    def walk(node: Any) -> Any:
        if isinstance(node, str):
            out, unk = service.detokenize_text(node, allowed)
            unknown.extend(unk)
            return out
        if isinstance(node, list):
            return [walk(item) for item in node]
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        return node

    result = walk(obj)
    if unknown:
        logger.info("unknown_tokens_in_response", tokens=sorted(set(unknown)))
    return json.dumps(result).encode("utf-8")


def _rewrite_sse_event(
    obj: Any,
    channels: dict[str, StreamDetokenizer],
    service: TokenService,
    *,
    allowed: AbstractSet[str] | None = None,
    flush_into: str = "",
) -> Any:
    """Feed assistant-text fields of one SSE event through per-key channels.

    ``flush_into`` (used for the synthesized final event) replaces the first
    text field with the given remainder instead of feeding it.
    """
    injected = {"done": False}

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for key, value in node.items():
                if key in _TEXT_KEYS and isinstance(value, str):
                    if flush_into:
                        out[key] = "" if injected["done"] else flush_into
                        injected["done"] = True
                    else:
                        channel = channels.setdefault(key, StreamDetokenizer(service, allowed))
                        out[key] = channel.feed(value)
                else:
                    out[key] = walk(value)
            return out
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return walk(obj)


async def _detok_sse_iter(
    upstream_resp: httpx.Response,
    service: TokenService,
    allowed: AbstractSet[str] | None = None,
) -> AsyncIterator[bytes]:
    """Rewrite an SSE stream line-by-line, holding back partial tokens.

    Non-``data:`` lines and non-JSON payloads pass through verbatim. Any
    text still held back at end-of-stream is emitted in a synthesized event
    cloned from the last text-bearing event, before the terminator.
    """
    channels: dict[str, StreamDetokenizer] = {}
    template: str | None = None
    buf = b""

    def flush_remainder() -> bytes:
        remainder = "".join(ch.flush() for ch in channels.values())
        unknown = sorted({t for ch in channels.values() for t in ch.unknown_tokens})
        if unknown:
            logger.info("unknown_tokens_in_response", tokens=unknown)
        if not remainder or template is None:
            return b""
        synthetic = _rewrite_sse_event(
            json.loads(template), channels, service, allowed=allowed, flush_into=remainder
        )
        return b"data: " + json.dumps(synthetic).encode("utf-8") + b"\n\n"

    def process_line(line: bytes) -> bytes:
        nonlocal template
        stripped = line.strip()
        if not stripped.startswith(b"data:"):
            return line + b"\n"
        payload = stripped[5:].strip()
        if payload == b"[DONE]":
            return flush_remainder() + line + b"\n"
        try:
            obj = json.loads(payload)
        except ValueError:
            return line + b"\n"
        template = payload.decode("utf-8", errors="replace")
        rewritten = _rewrite_sse_event(obj, channels, service, allowed=allowed)
        return b"data: " + json.dumps(rewritten).encode("utf-8") + b"\n"

    try:
        async for chunk in upstream_resp.aiter_raw():
            buf += chunk
            out = b""
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                out += process_line(line.rstrip(b"\r"))
            if out:
                yield out
        tail = b""
        if buf:
            tail += process_line(buf.rstrip(b"\r"))
        tail += flush_remainder()
        if tail:
            yield tail
    finally:
        await upstream_resp.aclose()


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

    action, reason, out_body, categories, allowed_tokens = await _scan_and_redact(
        pipeline, parsed, kind
    )
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

    # Only responses to redacted requests can contain our tokens; everything
    # else relays verbatim (zero-cost fast path). When tokens are in play we
    # need the response uncompressed to rewrite it.
    token_service: TokenService | None = getattr(request.app.state, "token_service", None)
    tokens_active = action is Action.REDACT and token_service is not None
    if tokens_active:
        headers["accept-encoding"] = "identity"

    upstream_req = client.build_request("POST", url, content=payload, headers=headers)
    upstream_resp = await client.send(upstream_req, stream=True)
    return _relay(
        upstream_resp,
        token_service if tokens_active else None,
        allowed_tokens if tokens_active else None,
    )


def create_gateway(
    settings: Settings | None = None,
    *,
    pipeline: DetectorPipeline | None = None,
    on_decision: Callable[[Action, list[str], str], None] | None = None,
    audit_path: str | Path | None = None,
    enable_audit: bool = True,
    token_service: TokenService | None = None,
) -> FastAPI:
    """Construct the transparent redacting reverse-proxy app.

    ``on_decision`` is invoked (action, categories, host) on each redact/block
    for live terminal feedback. Redact/block decisions are also appended to a
    metadata-only audit log (``enable_audit``) for ``domestique report``.

    A ``TokenService`` (session-only by default) makes redaction reversible:
    numbered tokens go out, and responses are rewritten back inline. Callers
    that want the persistent pinned vault (the CLI does) pass a service
    wired to one.
    """
    resolved = settings or Settings()
    if pipeline is None:
        if token_service is None:
            from domestique.vault.service import TokenService as _TokenService
            from domestique.vault.session import SessionStore

            token_service = _TokenService(SessionStore(), None)
        built_pipeline = build_cli_pipeline(resolved, token_service=token_service)
    else:
        built_pipeline = pipeline
        # getattr, not direct access: test doubles / future pipeline shapes may
        # not have a _token_service at all, which should behave exactly like
        # token_service=None (verbatim relay) rather than raising.
        pipeline_token_service = getattr(built_pipeline, "_token_service", None)
        if token_service is None:
            # Derive it from the pipeline instead of leaving app.state.token_service
            # None: otherwise tokens get minted going out but responses are never
            # detokenized coming back (fails safe -- verbatim relay -- but silently
            # breaks reversibility). Mirror image of the mistake build_cli_pipeline's
            # caller in cli.py already guards against by passing token_service to both.
            token_service = pipeline_token_service
        elif token_service is not pipeline_token_service:
            raise ValueError(
                "create_gateway() received a pipeline and a token_service that "
                "don't match -- pass the same TokenService to both, or only one."
            )

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
    app.state.token_service = token_service

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
