# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet published to a package index — the `0.1.0` items below ship from source
(`pip install -e .`) while the PyPI package name is finalized.

### Added — browser interception coverage
- Qwen-cloud destinations (`chat.qwen.ai`, `dashscope.aliyuncs.com`,
  `dashscope-intl.aliyuncs.com`) added to the intercepted-domain list. DashScope's
  OpenAI-compatible endpoint is handled by the existing generic extraction. Qwen-cloud
  (the destination) is distinct from the local `qwen3` classifier (detection).
- DeepSeek API coverage confirmed (`api.deepseek.com` via the generic
  `/chat/completions` path). Full web-UI (`chat.deepseek.com`, `chat.qwen.ai`)
  prompt-extraction is a follow-up pending live-traffic captures.

### Added — the developer CLI wedge (0.1.0)
- `domestique start` — a local redacting reverse proxy on `http://127.0.0.1:8000`.
  Point any OpenAI- or Anthropic-compatible tool at it via `OPENAI_BASE_URL` /
  `ANTHROPIC_BASE_URL`; secrets and PII are redacted out of prompts before they reach
  the provider, and the response streams straight back. Your API key rides through in
  the request header — Domestique never stores it.
- `domestique demo` — a self-contained before/after redaction on a fake-secret prompt.
  No API key, no network, nothing to configure.
- OpenAI front doors: `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`.
- Anthropic front door: `/v1/messages` (native, with `anthropic-version` passthrough).
- Redact-by-default policy (`domestique/policy/cli-rules.yaml`): the loudest secrets
  (private keys, cloud secret keys, connection strings) block; everything else redacts
  in place so your workflow keeps working.
- Streaming preserved end to end (SSE and chunked responses relay untouched, including
  `content-encoding`).
- Packaging: `domestique` console entry point, PEP 517 build, bundled policy YAML.
- Live-provider smoke tests (`tests/integration/`) that prove real OpenAI and Anthropic
  responses never echo a planted secret, plus a secrets-gated CI workflow.

### Notes / known gaps
- Any path the proxy doesn't recognize is **passed through untouched** — including
  OpenAI's `/v1/responses` API (used by Codex). Redaction does not yet apply there.
  See `docs/recipes/` for per-agent status.
- macOS is the fully-validated platform; Windows and Linux paths exist but are less
  exercised.

[Unreleased]: https://github.com/domestique-labs/domestique-oss/commits/main
