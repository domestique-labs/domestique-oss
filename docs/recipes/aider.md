# aider → Domestique

**Status:** ⚗️ Setup documented — end-to-end pass pending.

aider uses LiteLLM under the hood and honors the standard provider base-URL env vars, so
it drops in cleanly.

## OpenAI models

```bash
domestique start
export OPENAI_BASE_URL=http://127.0.0.1:8000/v1
export OPENAI_API_KEY=sk-...
aider --model gpt-4o
```

## Anthropic models

```bash
domestique start
export ANTHROPIC_BASE_URL=http://127.0.0.1:8000
export ANTHROPIC_API_KEY=sk-ant-...
aider --model claude-haiku-4-5
```

## Notes

- aider sends chat-completions / messages requests, both of which Domestique redacts.
- aider often includes file contents in the prompt — that's exactly where an accidental
  secret (a `.env`, a hardcoded key) gets caught before it leaves your machine.
- Redaction is one-way on the request; responses stream back untouched.

## Verify

```bash
domestique demo
```
