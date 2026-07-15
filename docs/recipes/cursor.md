# Cursor CLI → Domestique

**Status:** ⚗️ Setup documented — end-to-end pass pending.

Cursor's CLI can target an OpenAI-compatible endpoint. Point that endpoint at Domestique.

## Setup

```bash
domestique start
export OPENAI_BASE_URL=http://127.0.0.1:8000/v1
export OPENAI_API_KEY=sk-...
```

If Cursor exposes its base URL in a config file or a `--base-url` style flag rather than
the env var, set it to `http://127.0.0.1:8000/v1` there. The rule is the same: the
OpenAI base URL must resolve to the proxy's `/v1`.

## Caveats

- Only the Chat Completions family (`/v1/chat/completions`, `/v1/completions`,
  `/v1/embeddings`) is redacted. If Cursor uses the OpenAI **Responses API**
  (`/v1/responses`), those requests pass through **unredacted** — see
  [codex.md](./codex.md) for the same gap.
- Redaction is one-way on the outbound prompt; the response streams back untouched.

## Verify

```bash
domestique demo
```
