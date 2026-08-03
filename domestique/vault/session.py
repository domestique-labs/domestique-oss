"""Session-scoped numbered token store (memory-only, thread-safe).

Within one store instance the same value always maps to the same token,
and distinct values of a category get distinct sequential numbers —
``[SSN_1]``, ``[SSN_2]`` — so an LLM (and the detokenizer) can tell them
apart. Nothing here ever touches disk.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from domestique.taxonomy import CANONICAL as _PREFIX_ALIASES  # noqa: F401  (back-compat re-export)
from domestique.taxonomy import normalize_category
from domestique.taxonomy import prefix_for as _prefix_for

#: Longest rendered token we will ever mint, e.g. ``[PREFIX_123]``. The
#: streaming detokenizer relies on this bound to hold back a token split
#: across chunk boundaries, so minting MUST guarantee it (see
#: ``render_token``). ``stream.py`` imports this constant rather than
#: redefining it, keeping the mint-side and stream-side bound in lockstep.
MAX_TOKEN_LEN = 32

#: Digits reserved for the numeric index when sizing the prefix budget.
_INDEX_DIGITS = 6

#: Longest category prefix that still fits ``MAX_TOKEN_LEN`` alongside the
#: brackets, the ``_`` separator, and a reserved index:
#: ``"[" + prefix + "_" + index + "]"``.
MAX_PREFIX_LEN = MAX_TOKEN_LEN - 3 - _INDEX_DIGITS


def category_prefix(category: str) -> str:
    """Token prefix for a detector category, via the canonical taxonomy.

    Normalizes the raw category first (``pii:person`` → ``person``) so every
    tier that flags the same entity mints the same token, then maps it to a
    compact, token-grammar-safe prefix (canonical, store-learned, or derived).
    """
    return _prefix_for(normalize_category(category))


def render_token(prefix: str, index: int) -> str:
    """Render ``[PREFIX_index]``, guaranteeing ``len(token) <= MAX_TOKEN_LEN``.

    ``category_prefix`` already bounds the prefix for normal indices; this
    is the belt-and-suspenders clamp that upholds the invariant even for a
    pathologically large index (more digits than ``_INDEX_DIGITS`` reserved).

    The clamp itself assumes ``len(str(index)) <= MAX_TOKEN_LEN - 3`` (i.e.
    the index alone still fits once the prefix is truncated to empty); past
    that point (~10**29 tokens of one category) the returned token could
    exceed ``MAX_TOKEN_LEN``, silently breaking the streaming holdback bound.
    Not reachable by any real session -- noted so ``max(budget, 0)`` isn't
    mistaken for an airtight bound.
    """
    idx = str(index)
    budget = MAX_TOKEN_LEN - 3 - len(idx)
    if len(prefix) > budget:
        prefix = prefix[: max(budget, 0)]
    return f"[{prefix}_{idx}]"


@dataclass
class _Entry:
    token: str
    original: str
    category: str
    created_at: float = field(default_factory=time.time)


class SessionStore:
    """Bidirectional value↔token registry for one process session."""

    def __init__(self, ttl: float = 3600.0) -> None:
        self._ttl = ttl
        self._lock = threading.Lock()
        self._forward: dict[str, str] = {}  # value -> token
        self._reverse: dict[str, _Entry] = {}  # token -> entry
        self._counters: dict[str, int] = {}  # prefix -> last used index

    def tokenize(self, value: str, category: str) -> str:
        """Return the stable numbered token for *value*, minting if new."""
        prefix = category_prefix(category)
        with self._lock:
            existing = self._forward.get(value)
            if existing is not None:
                return existing
            count = self._counters.get(prefix, 0) + 1
            self._counters[prefix] = count
            token = render_token(prefix, count)
            self._forward[value] = token
            self._reverse[token] = _Entry(token=token, original=value, category=category)
            return token

    def lookup(self, token: str) -> str | None:
        """Original value for *token*, or None if unknown/expired."""
        with self._lock:
            entry = self._reverse.get(token)
            return entry.original if entry else None

    def entries(self) -> dict[str, str]:
        """Snapshot of token → original value."""
        with self._lock:
            return {token: e.original for token, e in self._reverse.items()}

    def set_counter_floor(self, category: str, floor: int) -> None:
        """Reserve indices ≤ *floor* (used so session tokens never collide
        with pinned-vault tokens of the same category)."""
        prefix = category_prefix(category)
        with self._lock:
            if self._counters.get(prefix, 0) < floor:
                self._counters[prefix] = floor

    def max_index(self, category: str) -> int:
        """Highest numbered index minted so far for *category* (0 if none).

        Lets a runtime pin reserve an index above the live session counter so
        a newly-pinned value can never collide with an already-minted session
        token of the same prefix."""
        prefix = category_prefix(category)
        with self._lock:
            return self._counters.get(prefix, 0)

    def clear(self) -> None:
        with self._lock:
            self._forward.clear()
            self._reverse.clear()
            self._counters.clear()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._reverse)

    def cleanup_expired(self) -> int:
        """Drop entries older than the TTL. Counters are not reused."""
        now = time.time()
        removed = 0
        with self._lock:
            expired = [t for t, e in self._reverse.items() if now - e.created_at > self._ttl]
            for token in expired:
                entry = self._reverse.pop(token)
                self._forward.pop(entry.original, None)
                removed += 1
        return removed
