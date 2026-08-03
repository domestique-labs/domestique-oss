# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet published to a package index — the `0.1.0` items below ship from source
(`pip install -e .`). The package name `domestique` is settled; publishing is blocked
on configuring a PyPI Trusted Publisher and clearing the `pypi` environment's
approval gate, not on naming.

### Fixed — pre-release correctness pass
- **Untrusted model output no longer reaches the outbound token or disk** (#61). The
  Tier-3 extractor's category field is model-supplied and was carried into the redaction
  token that is *sent upstream* (a 25-character password egressed as
  `[CORRECTHORSEBATTERYSTAP_1]`) and persisted into `~/.domestique/taxonomy.json`. A
  category that echoes the scanned text is now treated as a leaked value, not a label:
  it falls back to a generic `SENSITIVE` prefix and is never written to disk.
- **A secret is no longer dropped on the model's say-so** (#61). The Tier-3 confidence
  gate used the model's self-reported score, so `v: 0.0` on a genuine secret silently
  allowed it through in cleartext. Spans are now verified verbatim against the text
  *before* the gate, and a verified span's confidence is floored.
- **The config header reports what can actually run** (#60). Detection tiers were
  ticked from configuration alone, so a machine with GLiNER enabled but not installed
  printed `✔ GLiNER`. The header now probes availability and distinguishes
  "unavailable" from "off", with an install hint.
- The demo's redaction tokens are highlighted again — the pattern still required the
  pre-0.1.0 `_REDACTED` suffix and matched nothing after the switch to numbered tokens.
- Coined redaction categories survive concurrent processes; the wedge, browser proxy
  and demo previously clobbered each other's taxonomy writes.
- The workshop competition scorer counted an unparseable response as a detection,
  reporting ~90% F1 for a run that scored 0% accuracy. It now reports non-answers as
  such. Related unreproducible figures have been removed from `HINTS.md`.
- `docker-compose.yml` pointed `DOMESTIQUE_POLICY_PATH` at a file that does not ship,
  silently falling back to built-in rules instead of the configured policy.
- `README.md` renders correctly as the PyPI project page (it is the long description,
  and its relative links and logo would all 404 there).

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
