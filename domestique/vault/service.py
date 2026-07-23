"""TokenService — the single facade the pipeline talks to.

Minting is pinned-first: a value already in the persistent vault keeps its
stable token; everything else gets a session token whose number can never
collide with a pinned one (``sync_counter_floors``). Detokenization is
strict: unknown tokens (e.g. hallucinated by the model) are left in place
and reported, never guessed.
"""

from __future__ import annotations

import re
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Set as AbstractSet

    from domestique.vault.pinned import PinnedVault
    from domestique.vault.session import SessionStore

#: Grammar for every rendered redaction token.
TOKEN_RE = re.compile(r"\[([A-Z0-9_]+)_(\d+)\]")

#: Sightings of the same value before we suggest pinning it.
SUGGEST_THRESHOLD = 3


class TokenService:
    """Mint numbered tokens and reverse them (session + pinned vault)."""

    def __init__(self, session: SessionStore, pinned: PinnedVault | None = None) -> None:
        self.session = session
        self.pinned = pinned
        self._lock = threading.Lock()
        self._sightings: dict[str, int] = {}
        self._suggestions: dict[str, str] = {}  # value -> category
        self.sync_counter_floors()

    def sync_counter_floors(self) -> None:
        """Reserve pinned indices so session tokens never collide with them."""
        if self.pinned is None or not self.pinned.available:
            return
        seen: set[str] = set()
        for token, _category in self.pinned.values().values():
            match = TOKEN_RE.fullmatch(token)
            if match:
                seen.add(match.group(1))
        for prefix in seen:
            self.session.set_counter_floor(prefix, self.pinned.max_index(prefix))

    def tokenize(self, value: str, category: str) -> str:
        if self.pinned is not None:
            pinned_token = self.pinned.lookup_value(value)
            if pinned_token:
                return pinned_token
        # Shares self._lock with pin()'s floor-compute-and-reserve section: a
        # session mint racing a concurrent pin (same category, different
        # thread) must not land on the index pin() is about to claim, or
        # detokenize_text's session-first resolution would return the wrong
        # value for one of them. See pin()'s docstring for the failure this
        # closes.
        with self._lock:
            return self.session.tokenize(value, category)

    def pin(self, value: str, category: str) -> str:
        """Promote *value* into the persistent pinned vault safely.

        The pinned and session stores share one ``[PREFIX_n]`` namespace but
        count independently, and ``detokenize_text`` resolves session-first —
        so a pin whose index collides with a live session token would make
        that token reverse to the wrong value. This reserves an index above
        *both* stores' current max for the prefix, then re-floors the session
        counter above the new pinned index so future session tokens stay
        clear. Use this rather than ``PinnedVault.pin`` directly whenever the
        vault shares a live ``SessionStore``. Returns '' if no pinned vault.

        The floor-compute-then-reserve sequence below is not safe to split
        across two lock acquisitions: a ``tokenize()`` call for the same
        category between reading ``floor`` and committing it to
        ``self.pinned`` could mint a session token at the very index this
        pin is about to claim — self._lock (shared with tokenize()) makes
        the whole sequence atomic against that race.
        """
        if self.pinned is None:
            return ""
        with self._lock:
            floor = max(self.pinned.max_index(category), self.session.max_index(category)) + 1
            token = self.pinned.pin(value, category, min_index=floor)
            self.sync_counter_floors()
            return token

    def detokenize_text(
        self, text: str, allowed: AbstractSet[str] | None = None
    ) -> tuple[str, list[str]]:
        """Replace known tokens with originals; return (text, unknown_tokens).

        ``allowed`` scopes reversal to a specific set of token strings. The
        gateway passes the tokens minted for the request being answered, so a
        token minted in another conversation (or hallucinated) is never
        reversed here even though the process-wide store could resolve it —
        this is what keeps one conversation's secret out of another's reply.
        When ``allowed`` is ``None`` (default) every known token resolves,
        preserving the original process-global behaviour for callers that
        don't need scoping.
        """
        unknown: list[str] = []
        if "[" not in text:
            return text, unknown

        def _sub(match: re.Match[str]) -> str:
            token = match.group(0)
            if allowed is not None and token not in allowed:
                unknown.append(token)
                return token
            original = self.session.lookup(token)
            if original is None and self.pinned is not None:
                original = self.pinned.lookup_token(token)
            if original is None:
                unknown.append(token)
                return token
            return original

        return TOKEN_RE.sub(_sub, text), unknown

    def pinned_values(self) -> list[str]:
        """All pinned plaintext values (for the guaranteed-recall fast path)."""
        if self.pinned is None:
            return []
        return list(self.pinned.values().keys())

    def record_sighting(self, value: str, category: str) -> bool:
        """Count a redaction of *value*; True when it just crossed the
        suggestion threshold (dashboard should offer pinning)."""
        if self.pinned is not None and self.pinned.lookup_value(value):
            return False
        with self._lock:
            count = self._sightings.get(value, 0) + 1
            self._sightings[value] = count
            if count == SUGGEST_THRESHOLD:
                self._suggestions[value] = category
                return True
            return False

    def suggestions(self) -> list[tuple[str, str]]:
        """Values that crossed the sighting threshold and are not yet pinned."""
        with self._lock:
            return [(v, c) for v, c in self._suggestions.items()]

    def dismiss_suggestion(self, value: str) -> None:
        with self._lock:
            self._suggestions.pop(value, None)
