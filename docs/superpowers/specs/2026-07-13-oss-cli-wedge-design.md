# OSS CLI Wedge (Phase 1) — Design

**Date:** 2026-07-13
**Status:** Approved for planning
**Product:** Domestique OSS (Community Edition) — code/package name unchanged (rebrand parked)
**Scope:** The developer CLI/proxy wedge — `domestique start` launches a redacting proxy on
`localhost:8000` that a developer points their agent/app at via a base-URL env var, and watches
it redact secrets, with zero system changes (no CA, no system proxy).
**Related (strategy):** `Domestique-Notes/docs/superpowers/specs/2026-07-12-promptseal-positioning-architecture.md`
(§3 CLI wedge leads; §7 Phase 1). Cross-thread status: `.superpowers/HANDOFF.md`.

---

## 1. Context & Goal

Domestique is an AI firewall that scans/redacts/blocks sensitive data before it reaches an LLM.
The OSS adoption strategy is a **developer wedge**: friction = 0. A developer installs the tool,
points their existing agent (Claude Code, aider, Cline, LangChain, the OpenAI/Anthropic SDKs) at
a local endpoint via an env var, and immediately sees secrets get redacted before they leave the
machine — no CA install, no system proxy, cross-platform.

The `localhost:8000` Python path already exists in the repo, but it is **not yet frictionless or
real**:
- The current forward path (`domestique/transport` → `LLMProxy.forward`) is **non-streaming**
  (buffers a full `litellm.acompletion` and returns JSON). Real agents default to SSE streaming,
  so pointing a real agent at `:8000` today would hang/fail.
- Only **OpenAI-compatible** endpoints exist (`/v1/chat/completions`, `/v1/completions`,
  `/v1/embeddings`). There is **no `/v1/messages`**, so `ANTHROPIC_BASE_URL` + Claude Code does
  not work.
- The default policy (`domestique/policy/rules.yaml`) is **block-everything**; the wedge story is
  "watch it *redact*".
- There is **no console entry point** (`pyproject.toml` has no `[project.scripts]`) — no
  `domestique` command, no `start`, no `demo`.

**Goal:** make the CLI wedge genuinely real and frictionless — a streaming, multi-provider,
redact-by-default reverse proxy behind a clean `domestique start` command, plus a `domestique demo`
first-run experience and an honest README rewrite around this hero.

**North-star constraint (from the strategy spec):** speed to adoption over architectural purity.
Python now; Rust is a triggered-future decision. Do not rename anything (rebrand parked until the
cofounder meeting). Stay out of the browser/system-proxy code
(`app/services/{mitm_addon,proxy,interceptor}.py`, `app/main.py`, `app/config/schema.py`) — that
is another thread's active surface.

---

## 2. The Developer Story (the contract)

```
pipx install domestique            # or: pip install domestique
domestique start                   # launches the :8000 redacting proxy — one command
export OPENAI_BASE_URL=http://localhost:8000/v1
export ANTHROPIC_BASE_URL=http://localhost:8000
# run Claude Code / aider / your app normally
#   → secrets redacted in the outbound prompt, response streams back, zero system changes
domestique demo                    # instant before/after redaction, no key or agent needed
```

`start` prints a banner with the exact export lines to copy. The developer's **own** provider API
key rides through in the request header — no server-side key, no `.env` required.

---

## 3. Architecture — transparent redacting reverse-proxy

One new transport that **reuses the existing detection engine unchanged**
(`domestique/detectors/registry.py:build_detectors`, `domestique/policy.PolicyEngine`,
`domestique/models.Action`). New modules live entirely within the agreed surface: `domestique/` +
`pyproject.toml` + `README.md`/`docs/`.

### 3.1 New modules

- **`domestique/cli.py`** — argparse entry point `main()`:
  - `domestique start [--host 127.0.0.1] [--port 8000]` — launch the proxy (uvicorn) in the
    foreground, print the copy-paste banner.
  - `domestique demo` — in-process before/after redaction (see §6).
  - `domestique --version`.
- **`domestique/gateway.py`** — the reverse-proxy FastAPI app (`create_gateway(settings)` factory,
  mirroring the existing `create_app` pattern in `domestique/app.py`). This is what `start` serves.

The existing `domestique/app.py` (litellm round-trip) is **left in place** for backward
compatibility (docker-compose, existing tests). The wedge is a new, focused app so we do not
destabilize the current path. Shared redaction/extraction logic is factored into a small reusable
module (see §3.4) and consumed by both.

### 3.2 Request pipeline (per request, in `gateway.py`)

1. **Route by path → provider + schema:**
   - `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings` → **OpenAI** schema, upstream
     `https://api.openai.com`.
   - `/v1/messages` → **Anthropic** schema, upstream `https://api.anthropic.com`.
   - `/health` → local `{"status":"healthy"}` (not proxied).
   - Any other path/method → **transparent passthrough** (no scanning), so agent probes like
     `GET /v1/models` still work.
2. **Extract prompt text** as `(field_path, text)` pairs:
   - OpenAI: reuse the extraction already in `domestique/app.py:_extract_texts`.
   - Anthropic: new extraction for `system` (str or content-block list) + `messages[].content`
     (str or content-block list, `type == "text"`).
3. **Scan** with `build_detectors(settings)` run concurrently (reuse the `_run_detectors`
   pattern), then **decide** via `PolicyEngine.explain(detections)`.
4. **Act — redact by default:** The wedge ships a **redact-first default policy** (a
   wedge-specific `rules.yaml`, or a redact-default applied when a finding matches no explicit
   rule) so detected secrets/PII are redacted rather than blocked. The current
   `domestique/policy/rules.yaml` (block-everything) is **not** changed in place — the enterprise
   path keeps it; the wedge selects its own policy via `Settings.policy_path`. Only the loudest
   categories (e.g. private keys) stay `block` in the wedge policy.
   - `REDACT` (default for detected secrets/PII): replace detected spans with
     `[<CATEGORY>_REDACTED]` placeholders in the body (reuse the span-replace logic from
     `app.py:_apply_redactions`, generalized to both schemas). Forward the sanitized body.
   - `BLOCK` (reserved for the loudest categories via policy): return a provider-shaped error
     (OpenAI: 403 JSON `error` object; Anthropic: 403 `{"type":"error","error":{...}}`) so the
     agent surfaces a clean message.
   - `ALLOW`: forward unchanged.
5. **Forward** the (possibly redacted) **raw body bytes** to the real upstream via a shared
   `httpx.AsyncClient`, **passing the client's auth header through unchanged**
   (`Authorization` for OpenAI, `x-api-key` + `anthropic-version` for Anthropic). Strip/rewrite
   only hop-by-hop headers and `Host`. If the client sent no key, fall back to
   `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` from the process env.
6. **Stream the response back untouched:**
   - If the response is `text/event-stream` (SSE) or the request asked for `stream: true`, stream
     bytes straight through with a `StreamingResponse` preserving status + content-type.
   - Otherwise return the buffered body + status + content-type.
   - **The response is never modified.** We protect data flowing *out*; response de-tokenization
     is explicitly out of MVP scope (§8).

### 3.3 Upstream configuration

Provider → upstream base URL is a small map with env overrides so tests and a mock upstream can
redirect without touching real providers:
- `DOMESTIQUE_OPENAI_UPSTREAM` (default `https://api.openai.com`)
- `DOMESTIQUE_ANTHROPIC_UPSTREAM` (default `https://api.anthropic.com`)

### 3.4 Shared logic (factored for reuse, no behavior change)

Extract the schema-agnostic pieces so both `app.py` and `gateway.py` use them:
- text extraction (OpenAI today; add Anthropic),
- span redaction (`_apply_redactions` / `_set_by_path`),
- the concurrent detector run.

Keep the refactor minimal and behavior-preserving — existing `app.py` tests must stay green.

---

## 4. Key handling & config

**Passthrough-first.** The developer keeps their key exactly where it already is (their agent's
env → sent as the request header → forwarded upstream). No `.env`, no server-side key required —
this is the zero-config promise. Env keys (`OPENAI_API_KEY`/`ANTHROPIC_API_KEY`) are a fallback
only when the client sends none. `start` inherits the launching shell, so a dev who already
exported their key for their agent is done.

Settings reuse `domestique/config.py:Settings`. `start` defaults bind to **127.0.0.1** (single-dev
safe; the current `Settings.host` default of `0.0.0.0` is not used for the wedge unless `--host`
overrides it).

---

## 5. What `start` launches

**Only** the `gateway.py` reverse proxy via uvicorn, foreground, with a friendly banner:

```
Domestique proxy running on http://127.0.0.1:8000
Point your agent at it:
  export OPENAI_BASE_URL=http://127.0.0.1:8000/v1
  export ANTHROPIC_BASE_URL=http://127.0.0.1:8000
Redaction: ON (redact by default).  Ctrl-C to stop.
```

No dashboard, no mitmproxy, no browser/PAC/CA code. Cross-platform, zero system footprint.

---

## 6. The demo (`domestique demo`)

Runs the **detect → redact pipeline in-process** on a canned prompt containing a fake AWS key, an
email, and an SSN, and prints a colored **before/after diff** showing the redactions. No network,
no API key, no running proxy required — so it always works immediately after install and is the
guaranteed "see it work" moment.

(Optional stretch, not required for MVP: if a real key is detected in env, also fire one live
proxied round-trip to show it end-to-end. The in-process transform is the guaranteed path.)

---

## 7. Packaging & README

- **`pyproject.toml`:** add `[project.scripts]` → `domestique = "domestique.cli:main"`. Ensure
  runtime deps for the wedge (`fastapi`, `uvicorn`, `httpx` — already present) are in the core
  dependency set, not an extra, so `pip install domestique` yields a working `start`.
- **Install path:** `pipx install domestique` / `pip install domestique` now. **No `brew install`
  promise** — brew is a Rust-era concern (strategy spec §5). README stays honest: only real,
  working commands.
- **README rewrite** around the §2 hero: install → `start` → two exports → run agent → redaction;
  plus `domestique demo`. The enterprise/browser/dashboard content is trimmed and moved below the
  fold (kept accurate, not deleted). No overpromising.

---

## 8. Error handling & failure modes

- **Upstream errors:** honor the existing `fail_mode` (`closed` → 502; `open` → surface). Default
  `closed`.
- **Detector exceptions:** already swallowed per-detector (fail-safe) — one bad detector never
  takes down a request.
- **Redaction errors:** the safe move is **block, not leak** — if span replacement raises, return
  a block response rather than forwarding unredacted content.
- **Missing/invalid key:** pass the upstream's own auth error straight back to the agent (it is
  the developer's key; the provider's message is the right one to show).

---

## 9. Testing (TDD)

Write tests first for each unit:
- Anthropic text extraction (`system` + content blocks) and OpenAI extraction (regression).
- Span redaction across both schemas (placeholder correctness, ordering, nested paths).
- Provider/upstream routing (path → provider → upstream URL, incl. env override).
- Header passthrough (client key forwarded; env fallback when absent; hop-by-hop headers
  stripped).
- Streaming passthrough and buffered passthrough against a **mock upstream** (reuse
  `bench/eval/mock_upstream.py`), asserting the redacted body reaches upstream and the response
  streams back unmodified.
- `domestique demo` output contains the placeholders and not the raw fake secret.
- `cli.py` arg parsing (`start`/`demo`/`--version`).

The existing `bench/eval` harness already validates redaction **quality** deterministically —
reference it, do not duplicate it.

**Verification (end-to-end):** `pip install -e .` then `domestique --version`, `domestique demo`
(shows redaction), and `domestique start` against the mock upstream with a scripted OpenAI and an
Anthropic streaming request → assert the fake secret is redacted upstream and the stream returns.

---

## 10. Out of scope for MVP (noted, not built)

Response de-tokenization/restore; the local dashboard / mini-SIEM; usage telemetry; browser / PAC
/ CA / mitmproxy anything; the Rust core; the classifier marketplace; any rename/rebrand. Blocking
remains available via policy but redaction is the default.
