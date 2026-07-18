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


def category_prefix(category: str) -> str:
    """Normalize a detector category to a token prefix (``aws_key`` → ``AWS_KEY``)."""
    return category.upper()


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
            token = f"[{prefix}_{count}]"
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
