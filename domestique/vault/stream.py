"""Chunk-boundary-safe streaming detokenization.

An LLM response streams back in arbitrary chunks, so a token like
``[SSN_1]`` can arrive split as ``…[SS`` + ``N_1]…``. The rewriter holds
back *only* an unterminated potential-token suffix (bounded at the max
rendered token length) and emits everything else immediately, so added
latency is zero for token-free chunks and at most one chunk for tokens.

Invariant (fuzz-tested): for any chunking of a text,
``"".join(feed(chunk) for chunk in chunks) + flush()`` equals the
non-streaming ``TokenService.detokenize_text`` output.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

#: Longest rendered token we will ever mint (``[PREFIX_n]``). Owned by the
#: mint site (``session.render_token`` guarantees it); imported here so the
#: hold-back bound can never drift out of sync with what minting produces.
from domestique.vault.session import MAX_TOKEN_LEN

if TYPE_CHECKING:
    from collections.abc import Set as AbstractSet

    from domestique.vault.service import TokenService

__all__ = ["MAX_TOKEN_LEN", "StreamDetokenizer"]

#: An unterminated token candidate at end-of-buffer: ``[``, ``[SSN``, ``[SSN_1``.
_PARTIAL_TOKEN_TAIL = re.compile(r"\[[A-Z0-9_]*$")


class StreamDetokenizer:
    """Stateful per-response rewriter over a ``TokenService``.

    ``allowed`` scopes which token strings this rewriter may reverse. When
    given (the gateway passes the set of tokens minted for the request being
    answered), any token outside it — e.g. one echoed from another
    conversation, or hallucinated — is left verbatim, so a response can only
    ever reveal secrets that its own request redacted.
    """

    def __init__(self, service: TokenService, allowed: AbstractSet[str] | None = None) -> None:
        self._service = service
        self._allowed = allowed
        self._held = ""
        self.unknown_tokens: list[str] = []

    @property
    def held(self) -> str:
        """Currently held-back suffix (bounded by ``MAX_TOKEN_LEN``)."""
        return self._held

    def feed(self, chunk: str) -> str:
        """Consume *chunk*, return the detokenized text safe to emit now."""
        buf = self._held + chunk
        if "[" not in buf:
            self._held = ""
            return buf

        match = _PARTIAL_TOKEN_TAIL.search(buf)
        if match is not None and len(buf) - match.start() <= MAX_TOKEN_LEN:
            cut = match.start()
        else:
            # No unterminated candidate, or it is already too long to ever
            # complete into a legal token — release everything.
            cut = len(buf)

        emit, self._held = buf[:cut], buf[cut:]
        if not emit:
            return ""
        out, unknown = self._service.detokenize_text(emit, self._allowed)
        self.unknown_tokens.extend(unknown)
        return out

    def flush(self) -> str:
        """End of stream: emit any held-back partial verbatim."""
        held, self._held = self._held, ""
        return held
