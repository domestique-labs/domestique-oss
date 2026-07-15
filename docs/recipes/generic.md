# Any OpenAI / Anthropic SDK → LLMGuard

**Status:** ✅ Covered by the live-provider smoke tests (`tests/integration/`).

Any code that lets you override the provider base URL works with LLMGuard. Set the base
URL to the proxy and use your normal key.

## OpenAI Python SDK

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8000/v1")  # OPENAI_API_KEY from env
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "my key is AKIAIOSFODNN7EXAMPLE"}],
)
# the model never sees the raw key — it's redacted before the request leaves the proxy
```

## Anthropic Python SDK

```python
from anthropic import Anthropic

client = Anthropic(base_url="http://127.0.0.1:8000")  # ANTHROPIC_API_KEY from env
msg = client.messages.create(
    model="claude-haiku-4-5",
    max_tokens=256,
    messages=[{"role": "user", "content": "my key is AKIAIOSFODNN7EXAMPLE"}],
)
```

## curl

```bash
curl http://127.0.0.1:8000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}]}'
```

## What's handled

`/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/messages`. Streaming
and non-streaming both work. Any other path passes through untouched.
