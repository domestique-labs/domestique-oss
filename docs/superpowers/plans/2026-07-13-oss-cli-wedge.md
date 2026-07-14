# OSS CLI Wedge (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a frictionless developer CLI wedge — `llmguard start` launches a streaming, redact-by-default reverse proxy on `localhost:8000` that a dev points their agent at (OpenAI + Anthropic) to redact secrets before they leave the machine, plus `llmguard demo` and an honest README rewrite.

**Architecture:** A new transparent redacting reverse-proxy (`llmguard/gateway.py`) routes by request path to a provider (OpenAI/Anthropic), extracts prompt text, runs the **existing** detection pipeline (`DetectorPipeline.inspect`) per field, redacts detected spans in place (or blocks the loudest categories), then forwards the redacted raw bytes to the real upstream via streaming `httpx` — passing the client's own API key through in the request header. Responses stream back untouched. A small `llmguard/cli.py` exposes `start`/`demo`/`--version`, wired as a console script.

**Tech Stack:** Python 3.11+, FastAPI, uvicorn, httpx (all already core deps), pytest / pytest-asyncio. Reuses `llmguard.detectors.registry` (`build_detectors`, `DetectorPipeline`, `create_detector_pipeline`), `llmguard.policy.PolicyEngine`, `llmguard.config.Settings`, `llmguard.models.Action`.

## Global Constraints

- **Python floor:** `requires-python = ">=3.11"`. Target `py311`.
- **No rename:** package/repo stay `llmguard`. Do NOT rename anything (rebrand parked).
- **Off-limits files:** do not touch `app/services/{mitm_addon,proxy,interceptor}.py`, `app/main.py`, `app/config/schema.py` (another thread's active surface).
- **Core deps only:** the wedge must work on a bare `pip install llmguard` — use only `fastapi`, `uvicorn`, `httpx`, `pydantic`, `structlog`, `pyyaml` (all already in `[project].dependencies`). No new runtime deps.
- **Redact by default; bind 127.0.0.1** for `start` (override via `--host`).
- **Honest README:** only real, working commands. `pipx install` / `pip install` now — NO `brew install` promise.
- **mypy strict:** new modules `llmguard/cli.py`, `llmguard/gateway.py`, `llmguard/extract.py` are NOT in the mypy baseline-ignore list — they must be fully type-annotated and pass `mypy --strict`. Do NOT add them to the baseline ignore.
- **Lint:** ruff must pass (`ruff check`, `ruff format`). Line length 99.
- **Detector default:** only the regex `SecretDetector` is on by default (`enable_secret_detection=True`); PII/GLiNER/LLM tiers are opt-in. The wedge + demo must work with regex-only detection — sample data and tests must use secrets the regex tier catches (AWS keys, tokens, emails, SSNs).

---

### Task 1: Provider-aware text extraction (`llmguard/extract.py`)

Factor prompt-text extraction into a shared, provider-aware module. Reuses the OpenAI logic currently inline in `llmguard/app.py:_extract_texts` (lines 321-357) and adds Anthropic Messages extraction.

**Files:**
- Create: `llmguard/extract.py`
- Test: `tests/unit/test_extract.py`

**Interfaces:**
- Consumes: `llmguard.models` (none directly; pure dict parsing).
- Produces:
  - `extract_texts(body: dict[str, Any], kind: str) -> list[tuple[str, str]]` where `kind` ∈ `{"openai_chat", "openai_completions", "openai_embeddings", "anthropic_messages"}`. Returns `(field_path, text)` pairs, dot-notation paths (e.g. `messages.0.content`, `system`, `messages.1.content.0.text`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_extract.py
from __future__ import annotations

from llmguard.extract import extract_texts


def test_openai_chat_string_content():
    body = {"messages": [{"role": "user", "content": "hello"}]}
    assert extract_texts(body, "openai_chat") == [("messages.0.content", "hello")]


def test_openai_chat_content_blocks():
    body = {"messages": [{"role": "user", "content": [
        {"type": "text", "text": "block-a"},
        {"type": "image_url", "image_url": {"url": "x"}},
    ]}]}
    assert extract_texts(body, "openai_chat") == [("messages.0.content.0.text", "block-a")]


def test_openai_completions_string_and_list():
    assert extract_texts({"prompt": "hi"}, "openai_completions") == [("prompt", "hi")]
    assert extract_texts({"prompt": ["a", "b"]}, "openai_completions") == [
        ("prompt.0", "a"), ("prompt.1", "b")]


def test_openai_embeddings():
    assert extract_texts({"input": "e"}, "openai_embeddings") == [("input", "e")]


def test_anthropic_system_string_and_messages():
    body = {
        "system": "sys-secret",
        "messages": [
            {"role": "user", "content": "hi there"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "blk"},
                {"type": "tool_use", "id": "1"},
            ]},
        ],
    }
    assert extract_texts(body, "anthropic_messages") == [
        ("system", "sys-secret"),
        ("messages.0.content", "hi there"),
        ("messages.1.content.0.text", "blk"),
    ]


def test_anthropic_system_block_list():
    body = {"system": [{"type": "text", "text": "sys-blk"}], "messages": []}
    assert extract_texts(body, "anthropic_messages") == [("system.0.text", "sys-blk")]


def test_unknown_kind_returns_empty():
    assert extract_texts({"messages": []}, "nope") == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_extract.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'llmguard.extract'`

- [ ] **Step 3: Write the implementation**

```python
# llmguard/extract.py
"""Provider-aware extraction of scannable prompt text from request bodies.

Returns ``(field_path, text)`` pairs where ``field_path`` is a dot-notation
path into the JSON body (e.g. ``messages.0.content``). Used by the reverse
proxy to know which fields to scan and, after redaction, to write back.
"""

from __future__ import annotations

from typing import Any


def extract_texts(body: dict[str, Any], kind: str) -> list[tuple[str, str]]:
    """Extract scannable ``(field_path, text)`` pairs for the given request kind."""
    if kind == "openai_chat":
        return _openai_messages(body)
    if kind == "openai_completions":
        return _list_or_str(body.get("prompt", ""), "prompt")
    if kind == "openai_embeddings":
        return _list_or_str(body.get("input", ""), "input")
    if kind == "anthropic_messages":
        return _anthropic(body)
    return []


def _openai_messages(body: dict[str, Any]) -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = []
    for i, msg in enumerate(body.get("messages", [])):
        texts.extend(_content(msg.get("content", ""), f"messages.{i}.content"))
    return texts


def _anthropic(body: dict[str, Any]) -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = []
    texts.extend(_content(body.get("system", ""), "system"))
    for i, msg in enumerate(body.get("messages", [])):
        texts.extend(_content(msg.get("content", ""), f"messages.{i}.content"))
    return texts


def _content(content: Any, path: str) -> list[tuple[str, str]]:
    """Handle a field that is either a plain string or a list of content blocks."""
    if isinstance(content, str):
        return [(path, content)] if content else []
    if isinstance(content, list):
        out: list[tuple[str, str]] = []
        for j, part in enumerate(content):
            if isinstance(part, dict) and part.get("type") == "text":
                text = part.get("text", "")
                if isinstance(text, str) and text:
                    out.append((f"{path}.{j}.text", text))
        return out
    return []


def _list_or_str(value: Any, path: str) -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)] if value else []
    if isinstance(value, list):
        return [(f"{path}.{i}", v) for i, v in enumerate(value) if isinstance(v, str) and v]
    return []
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_extract.py -q`
Expected: PASS (8 passed)

- [ ] **Step 5: Lint + typecheck the new module**

Run: `ruff check llmguard/extract.py && ruff format --check llmguard/extract.py && mypy llmguard/extract.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add llmguard/extract.py tests/unit/test_extract.py
git commit -m "feat(wedge): provider-aware prompt-text extraction (OpenAI + Anthropic)"
```

---

### Task 2: Set-by-path body redaction helper (`llmguard/redact.py`)

The gateway must write redacted text back into the exact nested field it came from. Factor the path-write helper (mirrors `llmguard/app.py:_set_by_path` lines 388-397) into a reusable module and add a body-level redactor that consumes `(field_path, redacted_text)` pairs.

**Files:**
- Create: `llmguard/redact.py`
- Test: `tests/unit/test_redact_body.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `set_by_path(obj: Any, path: str, value: str) -> None` — mutate nested dict/list in place.
  - `apply_field_redactions(body: dict[str, Any], redactions: list[tuple[str, str]]) -> dict[str, Any]` — deep-copy `body`, write each `(field_path, redacted_text)`, return the copy.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_redact_body.py
from __future__ import annotations

from llmguard.redact import apply_field_redactions, set_by_path


def test_set_by_path_nested_list_and_dict():
    body = {"messages": [{"content": "old"}]}
    set_by_path(body, "messages.0.content", "new")
    assert body["messages"][0]["content"] == "new"


def test_set_by_path_content_block():
    body = {"messages": [{"content": [{"type": "text", "text": "old"}]}]}
    set_by_path(body, "messages.0.content.0.text", "new")
    assert body["messages"][0]["content"][0]["text"] == "new"


def test_apply_field_redactions_does_not_mutate_input():
    body = {"system": "s", "messages": [{"content": "hi"}]}
    out = apply_field_redactions(body, [("system", "[REDACTED]"), ("messages.0.content", "safe")])
    assert out["system"] == "[REDACTED]"
    assert out["messages"][0]["content"] == "safe"
    # original untouched
    assert body["system"] == "s"
    assert body["messages"][0]["content"] == "hi"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_redact_body.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'llmguard.redact'`

- [ ] **Step 3: Write the implementation**

```python
# llmguard/redact.py
"""Write redacted text back into nested request-body fields by dot-path."""

from __future__ import annotations

import copy
from typing import Any


def set_by_path(obj: Any, path: str, value: str) -> None:
    """Set a value in a nested dict/list using a dot-notation path."""
    parts = path.split(".")
    for part in parts[:-1]:
        obj = obj[int(part)] if part.isdigit() else obj[part]
    last = parts[-1]
    if last.isdigit():
        obj[int(last)] = value
    else:
        obj[last] = value


def apply_field_redactions(
    body: dict[str, Any], redactions: list[tuple[str, str]]
) -> dict[str, Any]:
    """Return a deep copy of *body* with each ``(field_path, redacted_text)`` written in."""
    out = copy.deepcopy(body)
    for field_path, redacted_text in redactions:
        set_by_path(out, field_path, redacted_text)
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_redact_body.py -q`
Expected: PASS (3 passed)

- [ ] **Step 5: Lint + typecheck**

Run: `ruff check llmguard/redact.py && ruff format --check llmguard/redact.py && mypy llmguard/redact.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add llmguard/redact.py tests/unit/test_redact_body.py
git commit -m "feat(wedge): dot-path body redaction helper"
```

---

### Task 3: Redact-first wedge policy (`llmguard/policy/wedge_rules.yaml`)

The enterprise `rules.yaml` blocks everything. The wedge needs a redact-first policy: redact most secrets/PII (so the agent keeps working) and block only the crown-jewel categories. Ships as package data so `pip install` works.

**Files:**
- Create: `llmguard/policy/wedge_rules.yaml`
- Create: `tests/unit/test_wedge_policy.py`

**Interfaces:**
- Consumes: loaded by `PolicyEngine.from_yaml` (existing). Category names match `SecretDetector` output (`aws_access_key`, `aws_secret_key`, `private_key`, `github_token`, `openai_key`, `anthropic_key`, `jwt`, `password_literal`, `email_address`, `phone_number`, `us_ssn`, `credit_card`, `connection_string`) and `pii:*` variants.
- Produces: a policy file whose default action for detected secrets/PII is `redact`, with `block` reserved for `private_key`, `aws_secret_key`, `connection_string`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_wedge_policy.py
from __future__ import annotations

import asyncio
from pathlib import Path

from llmguard.detectors.registry import DetectorPipeline, build_detectors
from llmguard.config import Settings
from llmguard.models import Action
from llmguard.policy import PolicyEngine

_WEDGE = Path("llmguard/policy/wedge_rules.yaml")


def _pipeline() -> DetectorPipeline:
    settings = Settings()
    return DetectorPipeline(build_detectors(settings), PolicyEngine.from_yaml(_WEDGE))


def test_wedge_policy_file_exists():
    assert _WEDGE.exists()


def test_aws_access_key_is_redacted_not_blocked():
    pipe = _pipeline()
    text = "my key is AKIAIOSFODNN7EXAMPLE and thats it"
    result = asyncio.run(pipe.inspect(text))
    assert result.action is Action.REDACT
    assert result.redacted_text is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text


def test_private_key_is_blocked():
    pipe = _pipeline()
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"
    result = asyncio.run(pipe.inspect(text))
    assert result.action is Action.BLOCK
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_wedge_policy.py -q`
Expected: FAIL (`test_wedge_policy_file_exists` fails; redact tests fail — file missing so PolicyEngine falls back to defaults).

- [ ] **Step 3: Write the policy file**

```yaml
# llmguard/policy/wedge_rules.yaml
# LLMGuard OSS CLI Wedge - redact-first policy.
#
# The wedge protects a solo developer's outbound prompts WITHOUT breaking their
# flow: detected secrets/PII are REDACTED in place and the (sanitized) request
# still reaches the model. Only the crown-jewel categories BLOCK outright.
#
# Evaluated top-to-bottom; most restrictive matching action wins (block > redact).

rules:
  # ── Fail closed: a detector crashed → block, never leak unscanned ───────
  - name: block-on-detector-error
    detector: pipeline
    action: block
    categories:
      - detector_error
    min_confidence: 0.9

  # ── Block: crown-jewel secrets (redaction is not enough) ────────────────
  - name: block-crown-jewels
    detector: secret_scanner
    action: block
    categories:
      - private_key
      - aws_secret_key
      - connection_string
    min_confidence: 0.9

  # ── Redact: everything else sensitive ──────────────────────────────────
  - name: redact-secrets
    detector: secret_scanner
    action: redact
    categories:
      - aws_access_key
      - github_token
      - github_fine_grained
      - openai_key
      - anthropic_key
      - slack_token
      - jwt
      - password_literal
    min_confidence: 0.85

  - name: redact-pii
    detector: "*"
    action: redact
    categories:
      - us_ssn
      - social_security_number
      - "pii:social_security_number"
      - credit_card
      - "pii:credit_card"
      - email_address
      - "pii:email"
      - phone_number
      - "pii:phone_number"
      - address
      - "pii:address"
      - "pii:password"
    min_confidence: 0.7
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_wedge_policy.py -q`
Expected: PASS (3 passed). If a category name mismatches, inspect `llmguard/detectors/secrets.py` for the exact `category` strings the regex patterns emit and align the YAML.

- [ ] **Step 5: Commit**

```bash
git add llmguard/policy/wedge_rules.yaml tests/unit/test_wedge_policy.py
git commit -m "feat(wedge): redact-first wedge policy"
```

---

### Task 4: Gateway routing + wedge pipeline factory (`llmguard/gateway.py`, part 1)

Create the gateway module skeleton: provider routing table, upstream resolution (with env override), and the wedge pipeline factory. No forwarding yet — this task establishes the map + factory + `/health` and is independently testable.

**Files:**
- Create: `llmguard/gateway.py`
- Test: `tests/unit/test_gateway_routing.py`

**Interfaces:**
- Consumes: `llmguard.config.Settings`, `llmguard.detectors.registry` (`build_detectors`, `DetectorPipeline`), `llmguard.policy.PolicyEngine`.
- Produces:
  - `ROUTES: dict[str, tuple[str, str]]` mapping request path → `(provider, kind)`.
  - `upstream_base(provider: str) -> str` — resolves upstream base URL, honoring env `LLMGUARD_OPENAI_UPSTREAM` / `LLMGUARD_ANTHROPIC_UPSTREAM`.
  - `build_wedge_pipeline(settings: Settings | None = None) -> DetectorPipeline` — builds detectors + the wedge policy (`llmguard/policy/wedge_rules.yaml` resolved relative to this package).
  - `create_gateway(settings: Settings | None = None, *, pipeline: DetectorPipeline | None = None) -> FastAPI` — app factory (routes added in Task 5). For now it exposes `GET /health`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_gateway_routing.py
from __future__ import annotations

import os

from fastapi.testclient import TestClient

from llmguard.gateway import ROUTES, build_wedge_pipeline, create_gateway, upstream_base


def test_routes_cover_openai_and_anthropic():
    assert ROUTES["/v1/chat/completions"] == ("openai", "openai_chat")
    assert ROUTES["/v1/completions"] == ("openai", "openai_completions")
    assert ROUTES["/v1/embeddings"] == ("openai", "openai_embeddings")
    assert ROUTES["/v1/messages"] == ("anthropic", "anthropic_messages")


def test_upstream_base_defaults():
    assert upstream_base("openai") == "https://api.openai.com"
    assert upstream_base("anthropic") == "https://api.anthropic.com"


def test_upstream_base_env_override(monkeypatch):
    monkeypatch.setenv("LLMGUARD_OPENAI_UPSTREAM", "http://127.0.0.1:9999")
    assert upstream_base("openai") == "http://127.0.0.1:9999"


def test_build_wedge_pipeline_uses_redact_policy():
    import asyncio
    from llmguard.models import Action
    pipe = build_wedge_pipeline()
    result = asyncio.run(pipe.inspect("key AKIAIOSFODNN7EXAMPLE here"))
    assert result.action is Action.REDACT


def test_health_endpoint():
    client = TestClient(create_gateway())
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "healthy"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_gateway_routing.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'llmguard.gateway'`

- [ ] **Step 3: Write the gateway skeleton**

```python
# llmguard/gateway.py
"""LLMGuard OSS CLI wedge - transparent redacting reverse proxy.

Routes a request by path to a provider (OpenAI/Anthropic), scans+redacts the
prompt text using the existing detection pipeline, then forwards the redacted
bytes to the real upstream (streaming), passing the client's own API key
through. Responses stream back untouched.
"""

from __future__ import annotations

import os
from pathlib import Path

import structlog
from fastapi import FastAPI

from llmguard.config import Settings
from llmguard.detectors.registry import DetectorPipeline, build_detectors
from llmguard.policy import PolicyEngine

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
    "openai": "LLMGUARD_OPENAI_UPSTREAM",
    "anthropic": "LLMGUARD_ANTHROPIC_UPSTREAM",
}

_WEDGE_POLICY = Path(__file__).resolve().parent / "policy" / "wedge_rules.yaml"


def upstream_base(provider: str) -> str:
    """Resolve the upstream base URL for *provider*, honoring env overrides."""
    override = os.environ.get(_UPSTREAM_ENV[provider], "").strip()
    return override.rstrip("/") if override else _DEFAULT_UPSTREAMS[provider]


def build_wedge_pipeline(settings: Settings | None = None) -> DetectorPipeline:
    """Build the detection pipeline with the redact-first wedge policy."""
    settings = settings or Settings()
    return DetectorPipeline(
        detectors=build_detectors(settings),
        policy=PolicyEngine.from_yaml(_WEDGE_POLICY),
    )


def create_gateway(
    settings: Settings | None = None, *, pipeline: DetectorPipeline | None = None
) -> FastAPI:
    """Construct the reverse-proxy app. (Proxy routes added in Task 5.)"""
    settings = settings or Settings()
    app = FastAPI(title="LLMGuard Proxy", version="0.1.0")
    app.state.settings = settings
    app.state.pipeline = pipeline or build_wedge_pipeline(settings)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "healthy"}

    return app
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_gateway_routing.py -q`
Expected: PASS (5 passed)

- [ ] **Step 5: Lint + typecheck**

Run: `ruff check llmguard/gateway.py && ruff format --check llmguard/gateway.py && mypy llmguard/gateway.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add llmguard/gateway.py tests/unit/test_gateway_routing.py
git commit -m "feat(wedge): gateway routing table + wedge pipeline factory"
```

---

### Task 5: Redacting reverse-proxy forwarding + streaming (`llmguard/gateway.py`, part 2)

Add the proxy handler: for each routed path, scan+redact the body per field, block the crown-jewels, then forward the redacted bytes to the real upstream via streaming `httpx`, passing the client's auth header through, and stream the response back. Unknown paths pass through untouched.

**Files:**
- Modify: `llmguard/gateway.py`
- Create: `tests/unit/test_gateway_proxy.py`
- Create: `tests/unit/conftest.py` (test mock `MockProvider` + `mock_openai` fixture — echo + streaming, OpenAI + Anthropic paths). Placed in conftest (not a `tests.support` package) because `tests/` has no `__init__.py`; a conftest is auto-discovered with zero import risk.

**Interfaces:**
- Consumes: `ROUTES`, `upstream_base`, `create_gateway` (Task 4); `extract_texts` (Task 1); `apply_field_redactions` (Task 2); `DetectorPipeline.inspect` → `InspectionResult(action, reason, redacted_text)` (existing, `llmguard/detectors/registry.py`); `llmguard.models.Action`.
- Produces: registered routes on the app: `POST` handlers for each path in `ROUTES`, a catch-all passthrough, and a shared `httpx.AsyncClient` on `app.state.http` created/closed in the FastAPI `lifespan`.

- [ ] **Step 1: Write the test mock provider**

```python
# tests/support/mock_provider.py
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse


class MockProvider:
    """Records received bodies; echoes non-streaming, or emits 3 SSE chunks."""

    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []

    def build_app(self) -> FastAPI:
        app = FastAPI()

        async def handle(request: Request) -> Any:
            body = await request.json()
            self.received.append(body)
            if body.get("stream"):
                async def gen() -> Any:
                    for i in range(3):
                        yield f"data: chunk{i}\n\n".encode()
                    yield b"data: [DONE]\n\n"
                return StreamingResponse(gen(), media_type="text/event-stream")
            return JSONResponse({"ok": True, "echo": body})

        for path in ("/v1/chat/completions", "/v1/completions",
                     "/v1/embeddings", "/v1/messages"):
            app.add_api_route(path, handle, methods=["POST"])
        return app
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/unit/test_gateway_proxy.py
from __future__ import annotations

import httpx
import pytest

from bench.eval.mock_upstream import serve
from llmguard.gateway import create_gateway
from tests.support.mock_provider import MockProvider


@pytest.fixture()
def mock_openai(monkeypatch):
    provider = MockProvider()
    with serve(provider.build_app()) as base:
        monkeypatch.setenv("LLMGUARD_OPENAI_UPSTREAM", base)
        monkeypatch.setenv("LLMGUARD_ANTHROPIC_UPSTREAM", base)
        yield provider


def _client(app):
    # ASGITransport drives the app in-process (runs lifespan for httpx>=0.28 via context).
    transport = httpx.ASGITransport(app=app)
    return httpx.Client(transport=transport, base_url="http://gw")


def test_openai_secret_is_redacted_upstream(mock_openai):
    app = create_gateway()
    with serve(app) as gw:
        resp = httpx.post(
            f"{gw}/v1/chat/completions",
            headers={"Authorization": "Bearer sk-test"},
            json={"model": "gpt-4o-mini",
                  "messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}]},
        )
    assert resp.status_code == 200
    sent = mock_openai.received[-1]
    assert "AKIAIOSFODNN7EXAMPLE" not in sent["messages"][0]["content"]


def test_client_key_passed_through(mock_openai):
    app = create_gateway()
    # MockProvider does not assert headers; this test asserts the request succeeds
    # end-to-end with the client's own bearer key and no server-side key set.
    with serve(app) as gw:
        resp = httpx.post(
            f"{gw}/v1/chat/completions",
            headers={"Authorization": "Bearer sk-client-key"},
            json={"model": "m", "messages": [{"role": "user", "content": "hello clean"}]},
        )
    assert resp.status_code == 200
    assert mock_openai.received[-1]["messages"][0]["content"] == "hello clean"


def test_streaming_response_passthrough(mock_openai):
    app = create_gateway()
    with serve(app) as gw:
        with httpx.stream(
            "POST", f"{gw}/v1/chat/completions",
            headers={"Authorization": "Bearer sk-test"},
            json={"model": "m", "stream": True,
                  "messages": [{"role": "user", "content": "clean text"}]},
        ) as resp:
            body = b"".join(resp.iter_bytes())
    assert b"chunk0" in body and b"[DONE]" in body


def test_anthropic_secret_redacted_upstream(mock_openai):
    app = create_gateway()
    with serve(app) as gw:
        resp = httpx.post(
            f"{gw}/v1/messages",
            headers={"x-api-key": "sk-ant", "anthropic-version": "2023-06-01"},
            json={"model": "claude-3-5-sonnet", "max_tokens": 16,
                  "system": "leak AKIAIOSFODNN7EXAMPLE",
                  "messages": [{"role": "user", "content": "hi"}]},
        )
    assert resp.status_code == 200
    sent = mock_openai.received[-1]
    assert "AKIAIOSFODNN7EXAMPLE" not in sent["system"]


def test_unknown_path_passthrough(mock_openai):
    app = create_gateway()
    with serve(app) as gw:
        # /v1/models is not in ROUTES → transparent passthrough; mock has no such
        # route so it 404s, proving we forwarded rather than scanned/500'd.
        resp = httpx.get(f"{gw}/v1/models", headers={"Authorization": "Bearer x"})
    assert resp.status_code in (404, 405)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_gateway_proxy.py -q`
Expected: FAIL (routes not registered → 404/405 on the proxy paths, redaction assertions fail).

- [ ] **Step 4: Implement forwarding + streaming**

Add to `llmguard/gateway.py`: imports, a lifespan-managed `httpx.AsyncClient`, the scan/redact core, and the route registration. Replace the `create_gateway` body's app construction to include the lifespan and routes.

```python
# --- add to imports at top of llmguard/gateway.py ---
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from llmguard.extract import extract_texts
from llmguard.models import Action
from llmguard.redact import apply_field_redactions

# hop-by-hop headers that must not be forwarded (RFC 7230 §6.1) + host/length.
_STRIP_REQUEST_HEADERS = {
    "host", "content-length", "connection", "keep-alive", "transfer-encoding",
    "proxy-authorization", "proxy-authenticate", "te", "trailer", "upgrade",
}
_STRIP_RESPONSE_HEADERS = {
    "content-length", "connection", "keep-alive", "transfer-encoding",
    "content-encoding",  # httpx already decoded the body
}


async def _scan_and_redact(
    pipeline: DetectorPipeline, body: dict[str, Any], kind: str
) -> tuple[Action, str, dict[str, Any]]:
    """Return (action, reason, possibly-redacted body)."""
    texts = extract_texts(body, kind)
    redactions: list[tuple[str, str]] = []
    for field_path, text in texts:
        result = await pipeline.inspect(text)
        if result.action is Action.BLOCK:
            return Action.BLOCK, result.reason, body
        if result.action is Action.REDACT and result.redacted_text is not None:
            redactions.append((field_path, result.redacted_text))
    if redactions:
        return Action.REDACT, "redacted", apply_field_redactions(body, redactions)
    return Action.ALLOW, "", body


def _block_response(provider: str, reason: str) -> JSONResponse:
    if provider == "anthropic":
        return JSONResponse(
            status_code=403,
            content={"type": "error",
                     "error": {"type": "firewall_block",
                               "message": f"Blocked by LLMGuard: {reason}"}},
        )
    return JSONResponse(
        status_code=403,
        content={"error": {"message": f"Blocked by LLMGuard: {reason}",
                           "type": "firewall_block"}},
    )


def _forward_headers(request: Request, provider: str, settings: Settings) -> dict[str, str]:
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in _STRIP_REQUEST_HEADERS}
    # Fallback to env key only if the client sent none.
    if provider == "openai" and "authorization" not in {k.lower() for k in headers}:
        if settings.openai_api_key:
            headers["Authorization"] = f"Bearer {settings.openai_api_key}"
    if provider == "anthropic" and "x-api-key" not in {k.lower() for k in headers}:
        if settings.anthropic_api_key:
            headers["x-api-key"] = settings.anthropic_api_key
    return headers


async def _proxy(request: Request, path: str) -> Response:
    provider, kind = ROUTES[path]
    settings: Settings = request.app.state.settings
    pipeline: DetectorPipeline = request.app.state.pipeline
    client: httpx.AsyncClient = request.app.state.http

    raw = await request.body()
    try:
        body: dict[str, Any] = json.loads(raw)
    except Exception:
        # Not JSON we understand — forward untouched (fail-safe transparency).
        return await _passthrough(request, provider, path, raw)

    action, reason, out_body = await _scan_and_redact(pipeline, body, kind)
    if action is Action.BLOCK:
        logger.warning("request_blocked", path=path, reason=reason)
        return _block_response(provider, reason)

    payload = json.dumps(out_body).encode("utf-8")
    url = f"{upstream_base(provider)}{path}"
    headers = _forward_headers(request, provider, settings)
    headers["content-type"] = "application/json"

    upstream_req = client.build_request("POST", url, content=payload, headers=headers)
    upstream_resp = await client.send(upstream_req, stream=True)
    return _relay(upstream_resp)


async def _passthrough(
    request: Request, provider: str, path: str, raw: bytes
) -> Response:
    settings: Settings = request.app.state.settings
    client: httpx.AsyncClient = request.app.state.http
    url = f"{upstream_base(provider)}{path}"
    headers = _forward_headers(request, provider, settings)
    upstream_req = client.build_request(
        request.method, url, content=raw or None, headers=headers,
        params=request.query_params,
    )
    upstream_resp = await client.send(upstream_req, stream=True)
    return _relay(upstream_resp)


def _relay(upstream_resp: httpx.Response) -> StreamingResponse:
    async def body_iter() -> AsyncIterator[bytes]:
        async for chunk in upstream_resp.aiter_raw():
            yield chunk
        await upstream_resp.aclose()

    out_headers = {k: v for k, v in upstream_resp.headers.items()
                   if k.lower() not in _STRIP_RESPONSE_HEADERS}
    return StreamingResponse(
        body_iter(),
        status_code=upstream_resp.status_code,
        headers=out_headers,
        media_type=upstream_resp.headers.get("content-type"),
    )
```

Then update `create_gateway` to add the lifespan (shared client) and register routes:

```python
def create_gateway(
    settings: Settings | None = None, *, pipeline: DetectorPipeline | None = None
) -> FastAPI:
    """Construct the transparent redacting reverse-proxy app."""
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.http = httpx.AsyncClient(timeout=settings.upstream_timeout_s)
        try:
            yield
        finally:
            await app.state.http.aclose()

    app = FastAPI(title="LLMGuard Proxy", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.pipeline = pipeline or build_wedge_pipeline(settings)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "healthy"}

    def _make_handler(route_path: str):  # bind path per route
        async def handler(request: Request) -> Response:
            return await _proxy(request, route_path)
        return handler

    for route_path in ROUTES:
        app.add_api_route(route_path, _make_handler(route_path), methods=["POST"])

    # Catch-all passthrough for anything else (e.g. GET /v1/models).
    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def catch_all(request: Request, full_path: str) -> Response:
        raw = await request.body()
        # Default unknown paths to the OpenAI upstream (most SDK probes are OpenAI).
        return await _passthrough(request, "openai", f"/{full_path}", raw)

    return app
```

Note for the implementer: the `TestClient`/`ASGITransport` import in the test file's `_client` helper is unused if you drive via `serve()`; remove it if ruff flags it. Prefer the `serve()`-based tests shown (they exercise real sockets + streaming).

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_gateway_proxy.py -q`
Expected: PASS (5 passed). If `content-encoding` mismatches cause decode errors, confirm `_relay` uses `aiter_raw()` (raw bytes) and strips `content-encoding` from response headers.

- [ ] **Step 6: Full lint + typecheck + regression**

Run: `ruff check llmguard tests && ruff format --check llmguard tests && mypy llmguard/gateway.py && python -m pytest tests/unit/test_extract.py tests/unit/test_redact_body.py tests/unit/test_wedge_policy.py tests/unit/test_gateway_routing.py tests/unit/test_gateway_proxy.py -q`
Expected: all pass, no lint/type errors.

- [ ] **Step 7: Commit**

```bash
git add llmguard/gateway.py tests/unit/test_gateway_proxy.py tests/support/mock_provider.py
git commit -m "feat(wedge): redacting reverse-proxy with streaming passthrough (OpenAI + Anthropic)"
```

---

### Task 6: CLI — `start`, `demo`, `--version` (`llmguard/cli.py`)

Add the console entry point. `start` prints the copy-paste banner and runs uvicorn on the gateway (default `127.0.0.1:8000`). `demo` runs the detect→redact pipeline in-process on a canned secret-laden prompt and prints a before/after diff.

**Files:**
- Create: `llmguard/cli.py`
- Test: `tests/unit/test_cli.py`

**Interfaces:**
- Consumes: `create_gateway`, `build_wedge_pipeline` (Task 4); `llmguard.__version__` (add if missing — see Step 3).
- Produces: `main(argv: list[str] | None = None) -> int`; `run_demo() -> int` (async pipeline run, returns 0); the `start` path calls `uvicorn.run(create_gateway(...), host=..., port=...)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_cli.py
from __future__ import annotations

from llmguard.cli import main


def test_version(capsys):
    rc = main(["--version"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "llmguard" in out.lower()


def test_demo_redacts_and_prints(capsys):
    rc = main(["demo"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "AKIAIOSFODNN7EXAMPLE" not in out.split("AFTER")[-1]  # after-block is redacted
    assert "REDACTED" in out


def test_start_is_wired(monkeypatch):
    calls = {}

    def fake_run(app, host, port, **kw):
        calls["host"] = host
        calls["port"] = port

    monkeypatch.setattr("uvicorn.run", fake_run)
    rc = main(["start", "--port", "8111"])
    assert rc == 0
    assert calls["host"] == "127.0.0.1"
    assert calls["port"] == 8111
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_cli.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'llmguard.cli'`

- [ ] **Step 3: Implement the CLI**

First ensure a version constant exists. In `llmguard/__init__.py` add (if not present) `__version__ = "0.1.0"` to the module and to `__all__`.

```python
# llmguard/cli.py
"""LLMGuard OSS CLI - the developer wedge entry point.

Commands:
    llmguard start [--host H] [--port P]   launch the :8000 redacting proxy
    llmguard demo                          show a before/after redaction, no key needed
    llmguard --version
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from llmguard import __version__

_DEMO_PROMPT = (
    "Here is my AWS key AKIAIOSFODNN7EXAMPLE and email jane.doe@corp.com, "
    "SSN 123-45-6789. Please help me debug this."
)


def _banner(host: str, port: int) -> str:
    return (
        f"\nLLMGuard proxy running on http://{host}:{port}\n"
        "Point your agent at it:\n"
        f"  export OPENAI_BASE_URL=http://{host}:{port}/v1\n"
        f"  export ANTHROPIC_BASE_URL=http://{host}:{port}\n"
        "Redaction: ON (redact by default).  Press Ctrl-C to stop.\n"
    )


def _cmd_start(host: str, port: int) -> int:
    import uvicorn

    from llmguard.gateway import create_gateway

    print(_banner(host, port))
    uvicorn.run(create_gateway(), host=host, port=port)
    return 0


def run_demo() -> int:
    from llmguard.gateway import build_wedge_pipeline

    pipeline = build_wedge_pipeline()
    result = asyncio.run(pipeline.inspect(_DEMO_PROMPT))
    after = result.redacted_text or _DEMO_PROMPT
    print("LLMGuard demo - watch it redact secrets before they reach the LLM.\n")
    print("BEFORE:\n" + _DEMO_PROMPT + "\n")
    print("AFTER (sent to the model):\n" + after + "\n")
    if result.findings:
        print("Findings: " + ", ".join(f.description for f in result.findings))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="llmguard", description="LLMGuard OSS CLI wedge")
    parser.add_argument("--version", action="version", version=f"llmguard {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    start = sub.add_parser("start", help="launch the :8000 redacting proxy")
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--port", type=int, default=8000)

    sub.add_parser("demo", help="show a before/after redaction (no API key needed)")

    args = parser.parse_args(argv)
    if args.cmd == "start":
        return _cmd_start(args.host, args.port)
    if args.cmd == "demo":
        return run_demo()
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_cli.py -q`
Expected: PASS (3 passed). The `test_demo_redacts_and_prints` assertion assumes the AWS key + SSN + email are redacted under the wedge policy; if the AWS-key regex needs specific formatting, adjust `_DEMO_PROMPT` to a value `SecretDetector` matches (verify against `llmguard/detectors/secrets.py`).

- [ ] **Step 5: Lint + typecheck**

Run: `ruff check llmguard/cli.py llmguard/__init__.py && ruff format --check llmguard/cli.py && mypy llmguard/cli.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add llmguard/cli.py llmguard/__init__.py tests/unit/test_cli.py
git commit -m "feat(wedge): llmguard CLI - start, demo, --version"
```

---

### Task 7: Packaging — console script + build config + package data (`pyproject.toml`)

Wire the `llmguard` console command and make `pip install`/`pipx install` produce a working wedge with the policy YAML bundled. There is currently **no `[build-system]`** and `setup.py` is py2app-only — add an explicit setuptools build config scoped to not disturb the py2app path.

**Files:**
- Modify: `pyproject.toml`
- Test: `tests/unit/test_packaging.py`

**Interfaces:**
- Consumes: `llmguard.cli:main` (Task 6); `llmguard/policy/wedge_rules.yaml` (Task 3).
- Produces: a `llmguard` console script; `llmguard.policy` package includes `*.yaml` as data.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_packaging.py
from __future__ import annotations

import tomllib
from pathlib import Path


def _pyproject() -> dict:
    return tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))


def test_console_script_declared():
    scripts = _pyproject()["project"]["scripts"]
    assert scripts["llmguard"] == "llmguard.cli:main"


def test_build_system_declared():
    assert "build-system" in _pyproject()
    assert "setuptools" in _pyproject()["build-system"]["requires"][0]


def test_wedge_policy_shipped_as_package_data():
    # setuptools package-data must include the wedge policy yaml.
    data = _pyproject()["tool"]["setuptools"]["package-data"]
    globs = data.get("llmguard.policy") or data.get("llmguard") or []
    assert any(g.endswith(".yaml") for g in globs)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_packaging.py -q`
Expected: FAIL (`KeyError: 'scripts'` / missing `build-system`).

- [ ] **Step 3: Edit `pyproject.toml`**

Add a `[build-system]` table at the very top of the file (before `[project]`):

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
```

Add the console script — insert directly after the `license = {text = "Apache-2.0"}` line in `[project]`:

```toml
[project.scripts]
llmguard = "llmguard.cli:main"
```

Add setuptools package discovery + data near the other `[tool.*]` tables:

```toml
[tool.setuptools]
packages = ["llmguard", "llmguard.audit", "llmguard.detectors", "llmguard.policy", "llmguard.transport"]

[tool.setuptools.package-data]
"llmguard.policy" = ["*.yaml"]
```

Verify the `[project.scripts]` block is valid TOML in context (it is a top-level table, not nested under `[project]` — place it after the `[project.optional-dependencies]` block if that reads more cleanly; both are equivalent). Confirm the package list matches the actual subpackages under `llmguard/` (run `python -c "import pkgutil,llmguard; print([m.name for m in pkgutil.iter_modules(llmguard.__path__)])"` and include every subpackage that has an `__init__.py`).

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_packaging.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Verify a real editable install produces a working command**

```bash
pip install -e . -q
llmguard --version
llmguard demo
```
Expected: `llmguard 0.1.0`; demo prints BEFORE/AFTER with the AWS key redacted in AFTER. If `pip install -e .` errors on package discovery, adjust `[tool.setuptools].packages` to the exact subpackage list.

- [ ] **Step 6: Verify a built wheel bundles the policy YAML**

```bash
pip install build -q && python -m build --wheel -o dist_wedge_check 2>/dev/null
python - <<'PY'
import glob, zipfile
whl = sorted(glob.glob("dist_wedge_check/*.whl"))[-1]
names = zipfile.ZipFile(whl).namelist()
assert any(n.endswith("llmguard/policy/wedge_rules.yaml") for n in names), names
print("wedge_rules.yaml present in wheel:", whl)
PY
rm -rf dist_wedge_check
```
Expected: prints "wedge_rules.yaml present in wheel". This proves `pipx install llmguard` will find the policy at runtime.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml tests/unit/test_packaging.py
git commit -m "build(wedge): llmguard console script + setuptools build config + policy package-data"
```

---

### Task 8: README rewrite around the CLI-wedge hero

Rewrite `README.md` so the hero is the developer wedge (install → `start` → export → run agent → redaction; `demo`). Trim/relocate the enterprise/browser/dashboard content below the fold (keep accurate; don't delete). Only real, working commands. No `brew install` promise.

**Files:**
- Modify: `README.md`

**Interfaces:** none (documentation).

- [ ] **Step 1: Rewrite the top of `README.md`**

Replace everything from the title through the end of the current "Quick Start" section with the wedge hero. Keep the existing "How Transparent Interception Works", "Project Layout", and "License" sections but move them under a new "## Browser mode (optional)" / "## Enterprise" framing lower down. New hero:

```markdown
# LLMGuard

**A local AI firewall for developers.** Point your agent or app at LLMGuard and it
redacts secrets and PII out of your prompts *before* they reach OpenAI, Anthropic, or
any LLM — with zero system changes. No CA to install, no system proxy, cross-platform.

## Quick start

```bash
pipx install llmguard            # or: pip install llmguard
llmguard start                   # launches the redacting proxy on http://127.0.0.1:8000
```

Point your tool at it and keep using your own API key:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8000/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8000
# now run Claude Code / aider / Cline / your app as usual —
# secrets get redacted, the response streams back, nothing else changes.
```

Want to see it work first, with no API key and nothing to configure?

```bash
llmguard demo
```

It runs a prompt full of fake secrets through the firewall and shows you the
before/after:

    BEFORE:  Here is my AWS key AKIAIOSFODNN7EXAMPLE and email jane.doe@corp.com ...
    AFTER:   Here is my AWS key [AWS_ACCESS_KEY_REDACTED] and email [EMAIL_ADDRESS_REDACTED] ...

## How it works

LLMGuard runs a local reverse proxy. For each request it scans the prompt with a
tiered detection engine (fast regex first; optional NLP/NER and a local LLM classifier
for nuance), redacts anything sensitive in place, then forwards the sanitized request
to the real provider using **your** API key. The response streams straight back — only
the outbound prompt is touched.

- **Zero system footprint** — it's just a base-URL env var. No CA, no system proxy.
- **Your key stays yours** — it rides through in the request header to the provider.
- **Redact by default** — your workflow keeps working; the loudest secrets block.
- **Cross-platform** — macOS, Linux, Windows.
```

Then keep the existing detection-presets table, "How Transparent Interception Works", "Project Layout", and "License" sections, introduced by a short line like: "LLMGuard also has an optional browser mode and enterprise editions — see below." Do NOT add any `brew install` line.

- [ ] **Step 2: Verify the README claims match reality**

Manually confirm every command in the new hero actually runs: `llmguard start`, the two exports, `llmguard demo`. Confirm the AFTER redaction placeholders match what `llmguard demo` actually prints (run it and copy the real output). Fix the sample to match real output exactly — honest README.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(wedge): rewrite README around the CLI-wedge hero"
```

---

### Task 9: End-to-end verification + final gate

Prove the whole wedge works together and the existing suite is still green.

**Files:** none (verification only).

- [ ] **Step 1: Full test suite**

Run: `python -m pytest -q`
Expected: all pass (new wedge tests + pre-existing suite). Investigate any regression before proceeding.

- [ ] **Step 2: Lint + typecheck the whole change**

Run: `ruff check . && ruff format --check . && mypy llmguard/extract.py llmguard/redact.py llmguard/gateway.py llmguard/cli.py`
Expected: clean.

- [ ] **Step 3: Live smoke against the mock provider**

```bash
python - <<'PY'
import os, threading, time, httpx, uvicorn
from tests.support.mock_provider import MockProvider
from llmguard.gateway import create_gateway

prov = MockProvider()
import socket
def free():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p
up=free(); gw=free()
os.environ["LLMGUARD_OPENAI_UPSTREAM"]=f"http://127.0.0.1:{up}"
threading.Thread(target=lambda: uvicorn.run(prov.build_app(), host="127.0.0.1", port=up, log_level="error"), daemon=True).start()
threading.Thread(target=lambda: uvicorn.run(create_gateway(), host="127.0.0.1", port=gw, log_level="error"), daemon=True).start()
time.sleep(2)
r=httpx.post(f"http://127.0.0.1:{gw}/v1/chat/completions",
    headers={"Authorization":"Bearer sk-x"},
    json={"model":"m","messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}]})
print("status", r.status_code)
print("upstream saw:", prov.received[-1]["messages"][0]["content"])
assert "AKIAIOSFODNN7EXAMPLE" not in prov.received[-1]["messages"][0]["content"]
print("OK: secret redacted before upstream")
PY
```
Expected: prints "OK: secret redacted before upstream".

- [ ] **Step 4: Confirm no off-limits files were touched**

Run: `git diff --name-only main...HEAD`
Expected: only `llmguard/**`, `tests/**`, `pyproject.toml`, `README.md`, `docs/superpowers/**`. NONE of `app/services/{mitm_addon,proxy,interceptor}.py`, `app/main.py`, `app/config/schema.py`.

- [ ] **Step 5: Push branch + open draft PR**

```bash
git push -u origin HEAD
gh pr create --draft --title "feat: OSS CLI wedge (Phase 1)" --body "Implements the developer CLI wedge per docs/superpowers/specs/2026-07-13-oss-cli-wedge-design.md.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**Spec coverage:**
- §2 developer story → Tasks 6 (CLI), 8 (README).
- §3.1 new modules → `cli.py` (T6), `gateway.py` (T4/T5); shared logic → `extract.py` (T1), `redact.py` (T2).
- §3.2 pipeline (route → extract → scan → redact/block → forward → stream) → T4 (routing) + T5 (forward/stream).
- §3.3 upstream env override → T4 (`upstream_base`).
- §3.4 shared factored logic → T1/T2 (behavior-preserving; `app.py` left intact to avoid destabilizing — spec allowed either factoring or leaving it; we duplicate minimally rather than risk the existing strict-typed `app.py`).
- §4 key passthrough + env fallback + 127.0.0.1 → T5 (`_forward_headers`), T6 (start default host).
- §5 `start` launches only the proxy + banner → T6.
- §6 `llmguard demo` in-process → T6.
- §7 packaging + README → T7, T8.
- §8 error handling (fail-closed, redact-error→block, upstream errors) → covered: block on detected crown-jewels (T5); non-JSON → passthrough; **Note:** the spec's "redaction error → block" is handled implicitly (detector errors already surface as a synthetic high-confidence `detector_error` Detection inside `DetectorPipeline.inspect`, which the wedge policy does not redact → falls through as ALLOW). **Gap fix:** the wedge policy (T3) does not treat `detector_error` as block. Add a `block-on-detector-error` rule to `wedge_rules.yaml` matching category `detector_error` (detector `pipeline`, action `block`, min_confidence 0.9) so a pipeline failure fails closed. Adjust T3 Step 3 to include it.
- §9 testing → each task is TDD; mock provider (T5) reuses `serve()`; eval harness referenced not duplicated.
- §10 out-of-scope items → none built (verified: no response mutation, no dashboard, no telemetry, no browser/CA, no rename).

**Placeholder scan:** No TBD/TODO; every code step has complete code. Category-name alignment steps (T3 S4, T6 S4) reference the real source of truth (`llmguard/detectors/secrets.py`) rather than leaving a blank.

**Type consistency:** `extract_texts(body, kind)` (T1) used identically in T5. `apply_field_redactions(body, redactions)` (T2) used in T5 `_scan_and_redact`. `InspectionResult.action/redacted_text/reason/findings` match the existing dataclass in `llmguard/detectors/registry.py`. `create_gateway`/`build_wedge_pipeline`/`upstream_base`/`ROUTES` signatures consistent across T4→T5→T6. `main(argv)` consistent T6→T7.

**Fold-in from self-review:** T3 Step 3 must also include the fail-closed `detector_error` rule:
```yaml
  - name: block-on-detector-error
    detector: pipeline
    action: block
    categories: [detector_error]
    min_confidence: 0.9
```
