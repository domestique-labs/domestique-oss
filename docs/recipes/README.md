# Recipes — pointing your agent at Domestique

Every recipe here is the same three moves:

1. **Start the proxy**
   ```bash
   domestique start        # http://127.0.0.1:8000
   ```
2. **Point the tool's base URL at it** (keep using your own API key).
3. **Run the tool normally** — secrets and PII are redacted out of prompts before they
   reach the provider; the response streams straight back.

Nothing else on your system changes: no CA to install, no system proxy. It's just a
base-URL environment variable.

## The two front doors

| Provider | Env var | What it points at |
|---|---|---|
| OpenAI-compatible | `OPENAI_BASE_URL` | `http://127.0.0.1:8000/v1` |
| Anthropic | `ANTHROPIC_BASE_URL` | `http://127.0.0.1:8000` |

Handled paths: `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`,
`/v1/messages`. **Any other path is passed straight through untouched** — see the
per-tool caveats below.

## Per-tool recipes

| Tool | Recipe | Status |
|---|---|---|
| Claude Code | [claude-code.md](./claude-code.md) | ⚗️ Setup documented — end-to-end pass pending |
| OpenAI Codex CLI | [codex.md](./codex.md) | ⚠️ Uses `/v1/responses` — **not yet redacted** |
| Cursor CLI | [cursor.md](./cursor.md) | ⚗️ Setup documented — end-to-end pass pending |
| aider | [aider.md](./aider.md) | ⚗️ Setup documented — end-to-end pass pending |
| Any OpenAI/Anthropic SDK | [generic.md](./generic.md) | ✅ Covered by live-provider tests |

**Status legend**
- ✅ Verified end to end (in CI or a recorded run).
- ⚗️ The wiring is correct and the front door is supported, but we haven't yet run the
  full tool against it and recorded the result. Try it and tell us — open an issue.
- ⚠️ A known gap applies (usually an unsupported API path). Read the recipe.

> Ran one of these successfully — or hit a snag? A one-line report on the issue tracker
> (tool + version + what happened) is the fastest way to move a row to ✅.
