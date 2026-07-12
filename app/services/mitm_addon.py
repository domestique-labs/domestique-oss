"""Mitmproxy addon for LLM request inspection.

This addon is loaded by mitmproxy to inspect HTTPS traffic flowing through
the transparent proxy. It:

1. Identifies requests to LLM API endpoints
2. Extracts the user's message content from the request body
3. Runs it through the firewall's detection pipeline
4. Blocks, redacts, or queues for approval before forwarding

The addon is designed to be loaded via:
    mitmdump --set confdir=~/.llmguard/ca -s app/services/mitm_addon.py

Architecture:
    Browser -> System Proxy -> mitmproxy (port 8080) -> this addon -> upstream LLM
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional
from urllib.request import Request
from urllib.error import URLError

from mitmproxy import http, ctx

# Direct HTTP opener that bypasses any system proxy settings.
# This is critical because the mitmdump process runs inside the proxy chain -
# if urlopen respects system proxy, it would route localhost API calls back
# through mitmproxy, creating a deadlock.
import urllib.request as _urllib_req
_direct_opener = _urllib_req.build_opener(_urllib_req.ProxyHandler({}))
_direct_urlopen = _direct_opener.open

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger("llmguard.mitm")


class _InspectResult:
    """Result from running the detection pipeline on a text."""

    def __init__(self, findings: list, should_block: bool = False, redacted_text: str | None = None):
        self.findings = findings
        self.should_block = should_block
        self.redacted_text = redacted_text


class _Finding:
    """A single finding from the detection pipeline."""

    def __init__(self, category: str, confidence: float, description: str):
        self.category = category
        self.confidence = confidence
        self.description = description


class _DetectorPipeline:
    """Wraps a list of detectors into a unified pipeline with an inspect() method."""

    def __init__(self, detectors):
        self._detectors = detectors

    async def inspect(self, text: str) -> _InspectResult:
        all_findings = []
        for det in self._detectors:
            try:
                detections = await det.scan(text)
                for d in detections:
                    all_findings.append(_Finding(
                        category=d.category,
                        confidence=d.confidence,
                        description=f"{d.detector}: {d.category} ({d.confidence:.0%})",
                    ))
            except Exception:
                pass

        should_block = any(f.confidence >= 0.7 for f in all_findings)
        return _InspectResult(
            findings=all_findings,
            should_block=should_block,
        )


class LLMGuardAddon:
    """Mitmproxy addon that inspects LLM API requests for sensitive data.

    Only processes requests to known LLM endpoints. All other traffic
    passes through untouched with zero overhead.
    """

    MAX_LOG_ENTRIES = 500  # Keep last N entries in the request log

    def __init__(self):
        self._detector = None
        self._data_dir = Path.home() / ".llmguard"
        self._stats = {"inspected": 0, "blocked": 0, "redacted": 0, "allowed": 0}
        self._stats_file = self._data_dir / "browser_stats.json"
        self._log_file = self._data_dir / "request_log.jsonl"
        self._config_file = self._data_dir / "config.json"
        self._api_base = "http://127.0.0.1:9876"
        self._data_dir.mkdir(parents=True, exist_ok=True)

    def _persist_stats(self):
        """Write stats to a shared file for the dashboard to read."""
        try:
            self._stats_file.write_text(json.dumps(self._stats))
        except OSError:
            pass

    def _log_request(self, entry: dict):
        """Append a request entry to the JSON lines log file."""
        try:
            with open(self._log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
            # Truncate if too large (keep last N entries)
            self._trim_log()
        except OSError:
            pass

    def _trim_log(self):
        """Keep only the last MAX_LOG_ENTRIES in the log file."""
        try:
            lines = self._log_file.read_text().strip().split("\n")
            if len(lines) > self.MAX_LOG_ENTRIES:
                self._log_file.write_text(
                    "\n".join(lines[-self.MAX_LOG_ENTRIES:]) + "\n"
                )
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
            "detections": [
                {"detector": "browser_proxy", "category": item}
                for item in reasons
            ],
        }
        if latency_ms is not None:
            event["latency_ms"] = round(latency_ms, 1)
        if content is not None:
            event["prompt"] = content
            event["prompt_fields"] = [{
                "field_path": "request.body",
                "text": content,
                "length": len(content),
            }]
        if redacted_content is not None:
            event["redacted_prompt"] = redacted_content
            event["redacted_prompt_fields"] = [{
                "field_path": "request.body",
                "text": redacted_content,
                "length": len(redacted_content),
            }]
        if raw_body_preview:
            event["raw_body_preview"] = raw_body_preview
        if extra:
            event.update(extra)
        from llmguard.debug_trace import append_debug_trace
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

    def load(self, loader):
        """Called when the addon is loaded."""
        ctx.log.info("LLMGuard addon loaded - inspecting LLM API traffic")
        self._init_detector()
        self._warmup_llm()
        # Pre-warm all detectors (GLiNER lazy load etc) in background
        if self._detector:
            import threading
            def _warmup_detectors():
                import asyncio
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
            threading.Thread(target=_warmup_detectors, daemon=True, name="detector-warmup").start()

    def _init_detector(self):
        """Build detection pipeline from config. Called once at startup.

        Uses the shared pipeline_config helper for consistent Settings
        construction between API and mitm processes.
        """
        import os
        os.environ.setdefault("HF_HUB_OFFLINE", "1")

        from app.services.pipeline_config import settings_from_config, config_hash, load_config_dict
        from llmguard.detectors.registry import create_detector_pipeline

        config = load_config_dict()
        settings = settings_from_config(config)
        self._detector = create_detector_pipeline(settings)
        self._config_hash = config_hash(config)

        names = [d.name for d in self._detector._detectors]
        ctx.log.info(f"Detection pipeline: {', '.join(names)}")

    def _warmup_llm(self):
        """Pre-load Ollama model so first request doesn't block."""
        import threading
        config = self._load_config()
        stack = config.get("detection_stack", {})
        model = None
        if stack.get("gemma4_e2b", False):
            from llmguard.detectors.local_llm import _resolve_gemma_model
            model = _resolve_gemma_model()
        elif stack.get("qwen3_1_7b", True):
            model = "qwen3:1.7b"
        elif stack.get("legacy_cpu", False):
            model = "llama3.2:1b"
        if not model:
            return

        def _warmup():
            try:
                import urllib.request as _req
                import json as _json
                opener = _req.build_opener(_req.ProxyHandler({}))
                data = _json.dumps({
                    "model": model,
                    "messages": [{"role": "user", "content": "warmup"}],
                    "stream": False,
                    "options": {"num_predict": 1, "num_ctx": 8192},
                }).encode()
                req = _req.Request("http://localhost:11434/api/chat", data=data,
                                   headers={"Content-Type": "application/json"})
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
            self._log_request({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "host": host,
                "method": method,
                "path": path[:100],
                "action": "pass",
                "reason": f"no body ({method})",
            })
            self._trace_request(
                flow,
                action="pass",
                reason=f"no body ({method})",
            )
            return

        # Skip non-conversation paths. Only inspect endpoints that carry
        # user-authored content (chat messages, completions). Internal
        # endpoints (sentinel, telemetry, autocompletions, connectors,
        # static assets) are noise and cause false positives.
        _CONVERSATION_PATH_FRAGMENTS = (
            # ChatGPT web
            "/conversation",          # /backend-api/f/conversation
            "/backend-anon/",         # guest conversations
            # OpenAI API
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/responses",          # 2025 Responses API
            # Anthropic
            "/v1/messages",
            "/v1/complete",           # legacy
            "/completion",            # Claude web: /api/.../completion
            "/append_message",        # Claude web
            # Google Gemini
            "/batchexecute",          # Gemini web (BardChatUi)
            "/StreamGenerate",        # Gemini web streaming
            ":generateContent",       # Gemini API
            ":streamGenerateContent", # Gemini API streaming
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
            "/predictions",           # Replicate
            # HuggingFace
            "/models/",               # api-inference: /models/{model}
            # Cursor / Windsurf (gRPC-web)
            "/aiserver.v1.",          # Cursor: /aiserver.v1.ChatService/
        )
        _SKIP_PATH_SUBSTRINGS = (
            "/sentinel/", "/autocompletions", "/connectors/",
            "/telemetry", "/rgstr", "/library",
            "/cdn-cgi/", "/ces/", "/cdn/", "/_next/",
            "/assets/", "/static/", "/favicon",
            "/init",
        )
        if any(s in path for s in _SKIP_PATH_SUBSTRINGS):
            self._log_request({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "host": host,
                "method": method,
                "path": path[:100],
                "action": "pass",
                "reason": "non-conversation path",
            })
            return
        if not any(f in path for f in _CONVERSATION_PATH_FRAGMENTS):
            self._log_request({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "host": host,
                "method": method,
                "path": path[:100],
                "action": "pass",
                "reason": "non-conversation path",
            })
            return

        # Extract user content from the request body
        content = self._extract_content(flow)
        if not content:
            # Log raw body snippet for conversation endpoints to help debug extraction
            raw_snippet = ""
            if "conversation" in path:
                try:
                    raw_snippet = flow.request.content.decode("utf-8", errors="replace")[:500]
                except Exception:
                    pass
            self._log_request({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "host": host,
                "method": method,
                "path": path[:100],
                "action": "pass",
                "reason": "no extractable content",
                "body_size": len(flow.request.content),
                "raw_snippet": raw_snippet if raw_snippet else None,
            })
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
                    self._log_request({
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "host": host,
                        "method": method,
                        "path": path[:100],
                        "action": "approved",
                        "reasons": reasons,
                        "prompt": content,
                        "content_preview": content_preview,
                    })
                    self._trace_request(
                        flow,
                        action="approved",
                        reasons=reasons,
                        content=content,
                        latency_ms=latency_ms,
                        extra={"approval_decision": "approved"},
                    )
                    ctx.log.info(
                        f"APPROVED by user: request to {host} ({reasons})"
                    )
                    return

            # Denied, expired, or immediate block
            self._stats["blocked"] += 1
            self._persist_stats()
            self._log_request({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "host": host,
                "method": method,
                "path": path[:100],
                "action": "blocked",
                "reasons": reasons,
                "prompt": content,
                "content_preview": content_preview,
            })
            self._trace_request(
                flow,
                action="blocked",
                reasons=reasons,
                content=content,
                latency_ms=latency_ms,
                extra=(
                    {"approval_decision": approval_decision}
                    if approval_decision else None
                ),
            )
            flow.response = http.Response.make(
                403,
                json.dumps({
                    "error": {
                        "message": "Request blocked by LLMGuard: sensitive data detected",
                        "type": "firewall_block",
                        "details": reasons,
                    }
                }).encode(),
                {"Content-Type": "application/json"},
            )
            ctx.log.warn(f"BLOCKED request to {host}: {reasons}")

        elif result["action"] == "redact":
            self._stats["redacted"] += 1
            self._persist_stats()
            self._log_request({
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
            })
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
            self._log_request({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "host": host,
                "method": method,
                "path": path[:100],
                "action": "allowed",
                "prompt": content,
                "content_preview": content_preview,
            })
            self._trace_request(
                flow,
                action="allowed",
                content=content,
                latency_ms=latency_ms,
            )

    def _is_llm_endpoint(self, host: str) -> bool:
        """Check if a host is a known LLM API endpoint."""
        from app.services.interceptor import INTERCEPTED_DOMAINS
        return any(host.endswith(d) or host == d for d in INTERCEPTED_DOMAINS)

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
            from app.services.audit import (
                get_audit_store,
                create_audit_event,
                AuditAction,
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
        except Exception:
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
            payload = json.dumps({
                "host": host,
                "path": path[:100],
                "findings": findings,
                "content_preview": redacted_preview,
            }).encode()
            req = Request(
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
            f"Awaiting approval {approval_id} for {host} "
            f"(timeout={timeout}s, findings={findings})"
        )
        deadline = time.time() + timeout
        poll_interval = 0.5

        while time.time() < deadline:
            time.sleep(poll_interval)
            try:
                req = Request(
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

    def _extract_content(self, flow: http.HTTPFlow) -> Optional[str]:
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
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

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
            except Exception:
                pass

        return None

    def _extract_files_from_json(self, body: dict) -> Optional[str]:
        """Extract text from base64-encoded images/files in JSON payloads.

        Handles:
        - OpenAI vision: messages[].content[].image_url.url (data:image/...;base64,...)
        - Anthropic: messages[].content[].source.data (base64)
        - Generic: any "data" or "file" field containing base64
        """
        from app.services.file_scanner import scan_base64

        extracted_parts = []

        # Search for base64 image data in the JSON tree
        base64_items = _find_base64_data(body)

        for item in base64_items:
            result = scan_base64(item["data"], filename=item.get("filename", ""))
            if result.extracted_text:
                extracted_parts.append(result.extracted_text)

        return "\n".join(extracted_parts) if extracted_parts else None

    def _extract_multipart_content(self, flow: http.HTTPFlow) -> Optional[str]:
        """Extract text from multipart/form-data file uploads."""
        from app.services.file_scanner import scan_file

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

    async def _inspect(self, content: str) -> dict:
        """Run content through the detection pipeline.

        Uses mtime check for config changes (avoids JSON parse on hot path).
        Pipeline is rebuilt only when config actually changes.

        Note: detector scan methods (GLiNER, regex) do CPU-bound work inside
        async scan(). For a single-user desktop proxy this is fine. For
        multi-user enterprise deployments, wrap in asyncio.to_thread() to
        avoid blocking mitmproxy's event loop on slow detectors.
        """
        try:
            from app.services.pipeline_config import config_mtime_ns, config_hash, load_config_dict
            mtime = config_mtime_ns()
            if mtime != getattr(self, "_config_mtime", 0):
                self._config_mtime = mtime
                h = config_hash(load_config_dict())
                if h != getattr(self, "_config_hash", ""):
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
            from app.services.injection import InjectionDetector, Severity
            inj = InjectionDetector(min_severity=Severity.HIGH).scan(content)
            if inj.is_injection:
                extra.append(f"prompt_injection:{inj.highest_severity.value}")
        except Exception as e:
            ctx.log.debug(f"Injection detector unavailable: {e}")

        try:
            from app.services.code_detection import CodeDetector
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

    # --- Response Scanning (Bidirectional DLP) -----------------------

    async def response(self, flow: http.HTTPFlow) -> None:
        """Inspect LLM responses for leaked sensitive data.

        Detects training data extraction attacks where LLMs leak PII,
        credentials, or internal data in their responses. Operates in
        alert mode: logs and flags but does not block responses.

        Only scans actual LLM API responses (JSON/SSE), not static
        assets like JS bundles, CSS, images, or HTML pages.
        """
        host = flow.request.pretty_host
        if not self._is_llm_endpoint(host):
            return

        if not flow.response or not flow.response.content:
            return
        if len(flow.response.content) < 20:
            return

        # Skip static assets — only scan API responses (JSON / SSE)
        content_type = flow.response.headers.get("content-type", "")
        is_api_response = (
            "application/json" in content_type
            or "text/event-stream" in content_type
        )
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

            self._log_request({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "host": host,
                "method": "RESPONSE",
                "path": flow.request.path[:100],
                "action": "response_alert",
                "reasons": reasons,
                "content_preview": preview,
                "direction": "inbound",
            })

            # Emit audit event for response leak
            self._emit_audit_event(
                action="response_alert",
                host=host,
                method="RESPONSE",
                path=flow.request.path,
                reasons=reasons,
                latency_ms=0,
                content_length=len(flow.response.content),
                content_preview=preview,
            )

            ctx.log.warn(
                f"RESPONSE ALERT from {host}: "
                f"sensitive data in response - {reasons}"
            )

            # Add warning header (doesn't block - alert mode)
            flow.response.headers["X-LLMGuard-Alert"] = (
                f"Sensitive data detected in response: {','.join(reasons)}"
            )

    def _extract_response_content(self, flow: http.HTTPFlow) -> Optional[str]:
        """Extract text content from an LLM response body.

        Handles streaming (SSE) and JSON response formats.
        """
        if not flow.response or not flow.response.content:
            return None

        content_type = flow.response.headers.get("content-type", "")
        raw = flow.response.content

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

    def _extract_sse_content(self, raw: bytes) -> Optional[str]:
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
        except Exception:
            pass

        return "".join(texts) if texts else None

    def _extract_response_text(self, body: dict) -> Optional[str]:
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


def _extract_openai_content(body: dict) -> Optional[str]:
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
                text_parts = [p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"]
                # Also handle plain string parts
                text_parts += [p for p in content if isinstance(p, str)]
                return "\n".join(text_parts) if text_parts else None
            # Handle ChatGPT web format: {"content_type": "text", "parts": [...]}
            if isinstance(content, dict):
                parts = content.get("parts", [])
                texts = [p for p in parts if isinstance(p, str)]
                return "\n".join(texts) if texts else None
    return None


def _extract_anthropic_content(body: dict) -> Optional[str]:
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


def _extract_google_content(body: dict) -> Optional[str]:
    """Extract from Google/Gemini format: {contents: [{parts: [{text}]}]}."""
    contents = body.get("contents", [])
    if not contents:
        return None
    # Last content entry
    last = contents[-1]
    parts = last.get("parts", [])
    texts = [p.get("text", "") for p in parts if "text" in p]
    return "\n".join(texts) if texts else None


def _extract_generic_content(body: dict) -> Optional[str]:
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


def _extract_texts_recursive(obj, texts: list, depth: int = 0):
    """Recursively find all text strings in a nested structure."""
    if depth > 10:
        return
    if isinstance(obj, str):
        if len(obj) > 5:
            texts.append(obj)
    elif isinstance(obj, dict):
        for key, val in obj.items():
            _extract_texts_recursive(val, texts, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _extract_texts_recursive(item, texts, depth + 1)


def _is_metadata(text: str) -> bool:
    """Check if a string looks like metadata rather than user content."""
    import re as _re
    # UUID pattern
    if _re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', text):
        return True
    # ISO timestamp
    if _re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}', text):
        return True
    # Timezone names
    if text.count('/') == 1 and all(c.isalpha() or c in '/_' for c in text):
        return True
    return False


def _find_base64_data(obj, depth: int = 0) -> list[dict]:
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
                results.append({
                    "data": source.get("data", ""),
                    "filename": f"image.{ext}",
                })
                return results

        # Generic: look for file_data, image_data, attachment fields
        for key in ("file_data", "image_data", "attachment", "file_content"):
            if key in obj and isinstance(obj[key], str) and len(obj[key]) > 100:
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
    return bool(_re.match(r'^[A-Za-z0-9+/=]+$', sample))


# mitmproxy addon entry point
addons = [LLMGuardAddon()]
