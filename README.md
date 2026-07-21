<p align="center">
  <img src=".github/assets/domestique-oss-logo.png" alt="Domestique — a local AI firewall for developers" width="420" />
</p>

<p align="center">
  <strong>A local AI firewall for developers.</strong>
</p>

<p align="center">
  Point your agent or app at Domestique and it redacts secrets and PII out of your prompts
  <em>before</em> they reach OpenAI, Anthropic, or any LLM.<br>
  For CLI/API tools the setup is just one env var — no CA, no system proxy, no admin.
  (Web chat UIs like ChatGPT/Claude are covered by the optional
  <a href="#browser-mode-optional">browser mode</a>, a heavier path.) Cross-platform.
</p>

<!-- Badges are added in the README-badges change (#23); when merged they slot in here, centered. -->

**Contents** · [Quick start](#quick-start) · [How it works](#how-it-works) · [Browser mode](#browser-mode-optional) · [License](#license)

[![CI](https://img.shields.io/github/actions/workflow/status/domestique-labs/domestique-oss/ci.yml?branch=main&label=CI)](https://github.com/domestique-labs/domestique-oss/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Code style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![GitHub stars](https://img.shields.io/github/stars/domestique-labs/domestique-oss?style=flat)](https://github.com/domestique-labs/domestique-oss/stargazers)
<!-- Enable once the package is published to PyPI (blocked on the final package name — see CHANGELOG):
[![PyPI version](https://img.shields.io/pypi/v/domestique)](https://pypi.org/project/domestique/)
[![PyPI downloads](https://static.pepy.tech/badge/domestique)](https://pepy.tech/project/domestique)
[![Downloads/month](https://static.pepy.tech/badge/domestique/month)](https://pepy.tech/project/domestique)
-->

📖 [Docs](./docs/) · [Changelog](./docs/CHANGELOG.md) · [Recipes](./docs/recipes/) · [Contributing](./CONTRIBUTING.md)

## Quick start

```bash
pipx install domestique            # or: pip install domestique
domestique start                   # launches the redacting proxy on http://127.0.0.1:8000
```

Point your tool at it and keep using your own API key:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8000/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8000
# now run Claude Code / aider / Cline / your app as usual —
# secrets get redacted, the response streams back, nothing else changes.
```

Per-tool setup guides live in [`docs/recipes/`](./docs/recipes/) (Claude Code, Codex,
Cursor, aider, and any OpenAI/Anthropic SDK).

Want to see it work first, with no API key and nothing to configure?

```bash
domestique demo
```

It runs a prompt full of fake secrets through the firewall and shows you the
before/after:

```
BEFORE:  Here is my AWS key AKIAIOSFODNN7EXAMPLE and email jane.doe@corp.com, SSN 123-45-6789. ...
AFTER:   Here is my AWS key [AWS_ACCESS_KEY_REDACTED] and email [EMAIL_ADDRESS_REDACTED], SSN [US_SSN_REDACTED]. ...
```

## How it works

Domestique runs a local reverse proxy. For each request it scans the prompt with a
tiered detection engine (fast regex first; optional NLP/NER and a local LLM classifier
for nuance), redacts anything sensitive in place, then forwards the sanitized request
to the real provider using **your** API key. The response streams straight back — only
the outbound prompt is touched.

- **No CA, no system proxy, no admin** — pointing a tool at the wedge is just a base-URL env var.
- **Your key stays yours** — it rides through in the request header to the provider.
- **Redact by default** — your workflow keeps working; the loudest secrets block.
- **You can see what it caught** — each redaction/block prints a live line, and
  `domestique report` totals them by type (metadata only, never your prompt text).
- **Cross-platform** — macOS, Linux, Windows.

Supported front doors today: OpenAI-compatible (`/v1/chat/completions`, `/v1/completions`,
`/v1/embeddings`) via `OPENAI_BASE_URL`, and Anthropic (`/v1/messages`) via
`ANTHROPIC_BASE_URL`. Any other path is passed straight through untouched.

### Turning on deeper detection (optional)

Regex secret-scanning is always on and needs nothing extra. For names/addresses and
nuanced content, install the optional detectors:

| Component | Install extra | Size | Description |
|---|---|---|---|
| Regex scanner | (always on) | 0 | API keys, JWTs, SSNs, credit cards, emails, phones |
| GLiNER PII | `[ner]` | ~300 MB | Zero-shot NER for names, addresses, DOBs |
| Presidio PII | `[pii]` | ~500 MB | spaCy-based PII with en_core_web_lg model |
| LLM classifier | Ollama + model | 1-4 GB | Nuanced classification via a local LLM |

If a tier is **enabled but its dependency isn't installed**, `domestique start` prints a
loud warning and keeps running with whatever protection *is* available (fail-loud-but-open).
Prefer to never run half-protected? Add `--strict` and it will refuse to start until the
gap is fixed (fail-closed).

---

## Reference — commands, flags & env vars

### Commands

| Command | What it does |
|---|---|
| `domestique start` | Launch the redacting proxy on `http://127.0.0.1:8000`. |
| `domestique demo` | Before/after redaction on a sample prompt — no API key needed. |
| `domestique report` | Summarize how many secrets/PII were redacted or blocked, by type. |
| `domestique setup` | Hardware-aware first-run wizard (enables the optional detection tiers). |
| `domestique browser on\|off\|status` | Toggle browser interception (needs the dashboard app). |
| `domestique --version` | Print the version. |

### `start` flags

| Flag | Default | Meaning |
|---|---|---|
| `--host` | `127.0.0.1` | Address to bind the proxy to. |
| `--port` | `8000` | Port to listen on. |
| `--quiet` | off | Suppress the live redaction ticker (also auto-suppressed when stdout isn't a TTY). |
| `--strict` | off | Fail **closed** — refuse to start if a configured detection tier is unavailable. Default is fail-loud-but-open: warn and run. |
| `--access-log` | off | Restore uvicorn's raw per-request HTTP access log. Off by default so the live ticker is the single per-request voice (a clean request stays silent). |
| `--no-setup` | off | Skip the first-run setup offer. |

`report` accepts `--json` (machine-readable) and `--days N` (only count the last N days).

### Environment variables

**Point your tool at the wedge (client side):**

| Var | Example | Used by |
|---|---|---|
| `OPENAI_BASE_URL` | `http://127.0.0.1:8000/v1` | OpenAI-compatible clients |
| `ANTHROPIC_BASE_URL` | `http://127.0.0.1:8000` | Anthropic clients |

Your `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` stay exactly as they are — Domestique passes
them straight through to the provider.

**Configure Domestique itself (`DOMESTIQUE_` prefix, all optional):**

| Var | Default | Meaning |
|---|---|---|
| `DOMESTIQUE_OPENAI_UPSTREAM` | `https://api.openai.com` | Override the OpenAI upstream. |
| `DOMESTIQUE_ANTHROPIC_UPSTREAM` | `https://api.anthropic.com` | Override the Anthropic upstream. |
| `DOMESTIQUE_AUDIT_LOG` | `~/.domestique/audit.jsonl` | Where `report` events are written (metadata only). |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | — | Optional server-side fallback key, used only if the client sends none. |

Detection settings (which tiers are on, thresholds) are written by `domestique setup` to
`~/.domestique/config.json`; every field is also settable via a `DOMESTIQUE_`-prefixed env
var — see [`domestique/config.py`](./domestique/config.py).

---

## Browser mode (optional)

Domestique also has an optional **browser mode** — it can intercept web LLM UIs
(ChatGPT, Claude, Gemini, Copilot, and others) through a local proxy. The developer
CLI wedge above is the fastest way to
get value — no CA, no system proxy, no admin. Browser mode below is more invasive by nature:
it trusts a local CA and sets a system proxy so it can inspect HTTPS traffic from your browser.

### How transparent (browser) interception works

```
User / App  -->  System Proxy (PAC)  -->  Domestique (mitmproxy)  -->  LLM API
                 Routes only LLM          Inspect + Decide           OpenAI,
                 domains through           (<5ms p99 regex)          Claude, etc.
                 the firewall
```

1. A PAC file routes LLM domains (chatgpt.com, api.openai.com, etc.) through the local proxy.
2. mitmproxy terminates TLS with a locally-trusted CA certificate.
3. The firewall scans request content in parallel (regex + GLiNER + LLM classifier).
4. Clean requests forward immediately; violations block or redact.

The CA certificate is auto-generated and trusted on first launch. Browser mode is
opt-in and installs the `[browser-proxy]` extra.

If the certificate gate doesn't clear automatically (fresh installs on Windows, and
Linux, where system-store trust needs a manual step), run the helper for your OS from
the project root:

```
./infra/certs/fix-cert.sh        # Linux — generates + trusts the CA (uses sudo)
.\infra\certs\fix-cert.ps1       # Windows — generates + trusts the CA (click Yes on the prompt)
```

#### Disable QUIC (HTTP/3) so traffic can't bypass the proxy

Chromium browsers prefer **QUIC**, which runs over UDP/443 and skips the TCP proxy
entirely — a silent DLP blind spot. For a reliable browser-mode test or deployment,
turn QUIC off. A helper is included for the Chromium browsers:

```powershell
# Chrome / Brave / Edge — writes the standard QuicAllowed machine-wide policy
# (the same lever device-management tools pull). Auto-elevates via UAC. -Enable to revert.
scripts/toggle-quic.ps1 -Browser chrome        # or: brave | edge
```

For **Opera** and **Firefox** the script prints the correct manual step (they use
different mechanisms).

### Detection presets (Tier 3 LLM classifier)

| Preset | Stack | VRAM | Latency | F1 | Notes |
|---|---|---|---|---|---|
| `minimal` | Regex only | 0 | <1ms | 14% | Pattern matching, no LLM |
| `balanced` | Regex + Qwen3 1.7B | 1.8 GB | ~164ms | 92% | Recommended - fits 16GB laptops |
| `maximum` | Regex + GLiNER + Qwen3 | 1.8 GB | ~209ms | 91% recall | Highest recall, more false positives |

### Project layout

```
domestique/
  cli.py              # CLI entry point: `domestique start` / `domestique demo`
  gateway.py          # Transparent redacting reverse proxy (the CLI wedge)
  extract.py          # Provider-aware prompt-text extraction (OpenAI + Anthropic)
  redact.py           # Dot-path body redaction helpers
  detectors/          # Pluggable detection modules
    secrets.py        # Regex patterns (API keys, SSNs, emails)
    pii.py            # Presidio PII detector
    registry.py       # Detector registry + pipeline
    local_llm.py      # Ollama LLM classifier (Gemma / Qwen3)
  policy/
    browser-rules.yaml # Browser block-first policy
    cli-rules.yaml     # CLI proxy redact-first policy
  config.py           # Settings model (env-driven)

domestique_app/                  # Browser mode + native desktop app + dashboard
```

## License

**[Apache License 2.0](./LICENSE)** — open source. Use it, modify it, ship it, contribute
back. See [`NOTICE`](./NOTICE).

The full single-device LLM firewall is free and open under Apache-2.0.
