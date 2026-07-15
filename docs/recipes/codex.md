# OpenAI Codex CLI → LLMGuard

**Status:** ⚠️ Known gap — Codex uses the OpenAI **Responses API** (`/v1/responses`),
which LLMGuard does **not** yet intercept. Prompts sent that way reach OpenAI
**unredacted.**

## What works today

LLMGuard handles the OpenAI **Chat Completions** family
(`/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`). If you run Codex — or any
tool — in a mode that uses Chat Completions, the standard wiring applies:

```bash
llmguard start
export OPENAI_BASE_URL=http://127.0.0.1:8000/v1
export OPENAI_API_KEY=sk-...
```

## The gap

Codex defaults to the Responses API. LLMGuard's proxy passes any unrecognized path —
including `/v1/responses` — **straight through untouched**, so redaction is not applied.
Don't rely on LLMGuard to sanitize a Codex session until this row turns ✅.

Tracking: a `/v1/responses` handler is the next transport-layer task (Lane 3). Until it
lands, treat Codex as **unprotected** through LLMGuard.

## Check what path your tool uses

```bash
# with the proxy running, watch its console while you send one request.
# a redacted request logs as a handled route; a passthrough does not.
```

If you have a way to force Codex onto Chat Completions, the wiring above will redact.
Otherwise, wait for the Responses handler.
