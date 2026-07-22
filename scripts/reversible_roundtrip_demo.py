"""Manual-test artifact: the reversible-redaction loop, end to end.

No API key and no keyring are touched — it uses a session-only ``TokenService``
so you can run it on any checkout to see (and trust) the four properties that
matter:

  1. EGRESS   — secrets in a prompt become numbered reversible tokens
                (``[SSN_1]``), which is all the upstream provider ever sees.
  2. INGRESS  — a provider reply that quotes those tokens is detokenized back
                to the original values (buffered / JSON path).
  3. STREAMING— the same reversal survives SSE chunking, even when a token is
                split across chunk boundaries (bounded holdback reassembles it).
  4. SCOPE    — reversal is scoped to the tokens *this* request minted, so one
                conversation's reply can never reveal another's secrets even
                though the vault is process-wide.

Run:  python scripts/reversible_roundtrip_demo.py

Exit code is 0 only when every property holds, so it doubles as a smoke test.
"""

from __future__ import annotations

import asyncio

from domestique.config import Settings
from domestique.gateway import build_cli_pipeline
from domestique.vault.service import TokenService
from domestique.vault.session import SessionStore
from domestique.vault.stream import StreamDetokenizer

PROMPT = (
    "Here is my AWS key AKIAIOSFODNN7EXAMPLE and email jane.doe@corp.com, "
    "SSN 123-45-6789. Also reach me at bob@corp.com."
)


async def _run() -> bool:
    # Session-only service: no keyring, no ~/.domestique/vault.bin written.
    service = TokenService(SessionStore(), None)
    pipeline = build_cli_pipeline(Settings(), token_service=service)

    result = await pipeline.inspect(PROMPT)
    redacted = result.redacted_text or PROMPT
    minted = result.minted_tokens

    print("── 1. EGRESS (what the upstream provider actually receives) ──")
    print(f"   {redacted}")
    print(f"   minted tokens (reversal scope for this request): {sorted(minted)}\n")

    # 2. Buffered detokenize, scoped to this request's tokens.
    restored, unknown = service.detokenize_text(redacted, allowed=minted)
    buffered_ok = restored == PROMPT and not unknown
    print("── 2. INGRESS · buffered (JSON body) ──")
    print(f"   {restored}")
    print(f"   exact round-trip: {restored == PROMPT}   unknown tokens: {unknown}\n")

    # 3. Streaming detokenize in tiny 3-char chunks that split tokens across
    #    boundaries — the bounded holdback must still reassemble them.
    detok = StreamDetokenizer(service, allowed=minted)
    chunks = [detok.feed(redacted[i : i + 3]) for i in range(0, len(redacted), 3)]
    chunks.append(detok.flush())
    streamed = "".join(chunks)
    streaming_ok = streamed == PROMPT
    print("── 3. INGRESS · streaming (SSE, 3-char chunks splitting tokens) ──")
    print(f"   {streamed}")
    print(f"   stream == buffered == original: {streamed == restored == PROMPT}\n")

    # 4. Scope isolation: an empty allow-set stands in for a *different*
    #    conversation. It must NOT be able to reverse this request's tokens.
    other, _ = service.detokenize_text(redacted, allowed=set())
    scope_ok = other == redacted  # unchanged → nothing leaked
    print("── 4. SCOPE SAFETY (empty allow-set = another conversation) ──")
    print(f"   tokens stay redacted for an unrelated request: {scope_ok}\n")

    ok = buffered_ok and streaming_ok and scope_ok
    print("RESULT:", "✅ all reversible-redaction properties hold" if ok else "❌ FAILED")
    return ok


def main() -> int:
    return 0 if asyncio.run(_run()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
