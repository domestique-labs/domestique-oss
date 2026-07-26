"""Live OpenAI smoke test for reversible redaction (needs a real API key).

Starts the CLI-wedge gateway in-process (session-only vault — no keyring, no
~/.domestique files), then sends ONE chat completion through it to the REAL
OpenAI API. The prompt asks the model to echo a credential back, which makes
the round-trip visible in a single call:

    client ── "repeat: AKIA…real…" ──▶ proxy ── "repeat: [AWSKEY_1]" ──▶ OpenAI
    client ◀── "AKIA…real…" ──────────  proxy ◀── "[AWSKEY_1]" ──────────  OpenAI

So OpenAI never sees the secret (it sees the token), yet the client gets the
real value back — proving redaction is reversible on the wire.

Requires:  OPENAI_API_KEY in the environment, network access.
Optional:  MODEL (default: gpt-4o-mini), PORT (default: 8000).

Run:  OPENAI_API_KEY=sk-... python scripts/live_openai_smoke.py

Without a key it prints only the OFFLINE half (what OpenAI would receive) and
exits 0, so you can eyeball the redaction without spending a token.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time

import httpx
import uvicorn

from domestique.config import Settings
from domestique.gateway import build_cli_pipeline, create_gateway
from domestique.vault.service import TokenService
from domestique.vault.session import SessionStore

# A realistic-looking but well-known EXAMPLE key + email — safe to put in a repo.
SAMPLE_AWS = "AKIAIOSFODNN7EXAMPLE"
SAMPLE_EMAIL = "jane.doe@corp.com"
PROMPT = (
    "Repeat the following two values back to me verbatim, each on its own line, "
    f"with no extra words: {SAMPLE_AWS} and {SAMPLE_EMAIL}"
)


def _offline_preview(settings: Settings, service: TokenService) -> str:
    """Show exactly what the upstream provider would receive (tokens, not secrets)."""
    pipeline = build_cli_pipeline(settings, token_service=service)
    result = asyncio.run(pipeline.inspect(PROMPT))
    redacted = result.redacted_text or PROMPT
    print("── What OpenAI actually receives (egress) ──")
    print(f"   {redacted}")
    print(f"   minted tokens: {sorted(result.minted_tokens)}\n")
    return redacted


def _serve(app: object, port: int) -> uvicorn.Server:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    return server


def main() -> int:
    settings = Settings()
    port = int(os.environ.get("PORT", "8000"))
    model = os.environ.get("MODEL", "gpt-4o-mini")

    # One shared TokenService drives BOTH pipeline (mint) and gateway (reverse).
    service = TokenService(SessionStore(), None)
    _offline_preview(settings, service)

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        print("OPENAI_API_KEY not set — skipping the live call (offline preview only).")
        return 0

    pipeline = build_cli_pipeline(settings, token_service=service)
    app = create_gateway(settings, pipeline=pipeline, token_service=service, enable_audit=False)
    server = _serve(app, port)
    try:
        resp = httpx.post(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "content-type": "application/json"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": PROMPT}],
                "temperature": 0,
            },
            timeout=60.0,
        )
    finally:
        server.should_exit = True

    if resp.status_code != 200:
        print(f"── Live call FAILED (HTTP {resp.status_code}) ──\n{resp.text[:500]}")
        return 1

    reply = resp.json()["choices"][0]["message"]["content"]
    print("── Assistant reply, as the CLIENT sees it (post-detokenization) ──")
    print("   " + reply.replace("\n", "\n   "))

    key_ok = SAMPLE_AWS in reply
    email_ok = SAMPLE_EMAIL in reply
    token_leak = "[AWSKEY_1]" in reply or "[EMAIL_1]" in reply
    print("\n── Verdict ──")
    print(f"   real AWS key restored in client reply:  {key_ok}")
    print(f"   real email restored in client reply:    {email_ok}")
    print(f"   raw tokens leaked to client (bad):       {token_leak}")
    ok = key_ok and email_ok and not token_leak
    print("\nRESULT:", "✅ reversible redaction confirmed live" if ok else "❌ FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
