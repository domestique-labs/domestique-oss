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

```
BEFORE:  Here is my AWS key AKIAIOSFODNN7EXAMPLE and email jane.doe@corp.com, SSN 123-45-6789. ...
AFTER:   Here is my AWS key [AWS_ACCESS_KEY_REDACTED] and email [EMAIL_ADDRESS_REDACTED], SSN [US_SSN_REDACTED]. ...
```

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

---

## Browser mode (optional) & Enterprise

LLMGuard also has an optional **browser mode** — it can intercept web LLM UIs
(ChatGPT, Claude, Gemini, Copilot, and others) through a local proxy — and commercial
**Enterprise** editions for fleets. The developer CLI wedge above is the fastest way to
get value with zero system changes; the sections below cover the broader deployment.

### How transparent (browser) interception works

```
User / App  -->  System Proxy (PAC)  -->  LLMGuard (mitmproxy)  -->  LLM API
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

### Detection presets (Tier 3 LLM classifier)

| Preset | Stack | VRAM | Latency | F1 | Notes |
|---|---|---|---|---|---|
| `minimal` | Regex only | 0 | <1ms | 14% | Pattern matching, no LLM |
| `balanced` | Regex + Qwen3 1.7B | 1.8 GB | ~164ms | 92% | Recommended - fits 16GB laptops |
| `maximum` | Regex + GLiNER + Qwen3 | 1.8 GB | ~209ms | 91% recall | Highest recall, more false positives |

### Project layout

```
llmguard/
  cli.py              # CLI entry point: `llmguard start` / `llmguard demo`
  gateway.py          # Transparent redacting reverse proxy (the CLI wedge)
  extract.py          # Provider-aware prompt-text extraction (OpenAI + Anthropic)
  redact.py           # Dot-path body redaction helpers
  detectors/          # Pluggable detection modules
    secrets.py        # Regex patterns (API keys, SSNs, emails)
    pii.py            # Presidio PII detector
    registry.py       # Detector registry + pipeline
    local_llm.py      # Ollama LLM classifier (Gemma / Qwen3)
  policy/
    rules.yaml        # Default (enterprise) block-first rules
    wedge_rules.yaml  # CLI-wedge redact-first policy
  config.py           # Settings model (env-driven)

app/                  # Browser mode + native desktop app + dashboard
```

## License

**[Apache License 2.0](./LICENSE)** — open source. Use it, modify it, ship it, contribute
back. See [`NOTICE`](./NOTICE).

This is the **Community Edition**: the full single-device LLM firewall, free and open. The
commercial LLMGuard editions — fleet management, non-bypassable MDM enforcement, compliance
automation, analytics, and support — are separate proprietary products. "LLMGuard" is a
trademark of LLM-Guard; the license covers the code, not the name.
