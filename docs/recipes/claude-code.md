# Claude Code → LLMGuard

**Status:** ⚗️ Setup documented — end-to-end pass pending.

Claude Code talks to Anthropic's Messages API (`/v1/messages`), which LLMGuard handles
natively.

## Setup

```bash
# 1. start the proxy
llmguard start

# 2. in the shell where you run Claude Code:
export ANTHROPIC_BASE_URL=http://127.0.0.1:8000
# keep your own key exactly as you have it now:
export ANTHROPIC_API_KEY=sk-ant-...

# 3. run Claude Code as usual
claude
```

Prompts flow through the proxy; anything matching a secret/PII rule is redacted before
it reaches Anthropic, and the streamed response comes back untouched.

## Notes

- The API key rides through in the `x-api-key` header — LLMGuard forwards it and never
  stores it.
- Redaction is **one-way on the request**. If a coding agent pastes a secret and then
  relies on the model echoing that exact secret back, the model will see the redacted
  placeholder instead. For most workflows this is invisible; if you hit friction, file
  an issue — reversible tokenization is on the roadmap.
- Using Claude Code *to develop against LLMGuard itself*? Point a **second** shell's
  `ANTHROPIC_BASE_URL` at the proxy so you don't route your dev session through it by
  accident.

## Verify

```bash
llmguard demo   # confirms the redaction engine locally, no key needed
```
