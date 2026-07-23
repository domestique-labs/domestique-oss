"""Session-scoped numbered token store (memory-only, thread-safe).

Within one store instance the same value always maps to the same token,
and distinct values of a category get distinct sequential numbers —
``[SSN_1]``, ``[SSN_2]`` — so an LLM (and the detokenizer) can tell them
apart. Nothing here ever touches disk.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field

#: Short semantic prefixes for verbose detector categories. Redaction
#: markers ride along on every conversation turn, so their BPE cost
#: matters; ``[SSN_1]`` reads as clearly to a model as ``[US_SSN_1]`` at
#: roughly half the tokens. Aliases must stay unique (collision would
#: merge two categories' counters) and fit the ``[A-Z0-9_]+`` grammar.
_PREFIX_ALIASES: dict[str, str] = {
    "us_ssn": "SSN",
    "email_address": "EMAIL",
    "phone_number": "PHONE",
    "credit_card": "CARD",
    "aws_access_key": "AWSKEY",
    "aws_secret_key": "AWSSECRET",
    "private_key": "PRIVKEY",
    "connection_string": "CONNSTR",
    "github_token": "GHTOKEN",
    "github_fine_grained": "GHPAT",
    "anthropic_key": "ANTKEY",
    "openai_key": "OAIKEY",
    "slack_token": "SLACKKEY",
    "jwt": "JWT",
    "generic_api_key": "APIKEY",
    "password_literal": "PASSWORD",
}

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

#: Characters not permitted by the token grammar (``TOKEN_RE`` in
#: ``service.py``: ``[A-Z0-9_]``). Runs of them collapse to a single ``_``.
_NON_TOKEN_CHARS = re.compile(r"[^A-Z0-9_]+")


def category_prefix(category: str) -> str:
    """Token prefix for a detector category: short alias when known
    (``email_address`` → ``EMAIL``), else the uppercased category sanitized
    to the ``[A-Z0-9_]`` token grammar and length-bounded.

    Sanitizing is mandatory, not cosmetic: categories like ``pii:person``
    (GLiNER) or ``llm_classified:customer data`` (LLM classifier) would
    otherwise mint tokens such as ``[PII:PERSON_1]`` whose ``:``/space
    ``TOKEN_RE`` cannot match, silently breaking detokenization for the
    whole NER/LLM path. Bounding the prefix keeps every rendered token
    within ``MAX_TOKEN_LEN`` so the streaming rewriter can never split an
    over-length token un-held across a chunk boundary.
    """
    alias = _PREFIX_ALIASES.get(category.lower())
    if alias is not None:
        return alias
    prefix = _NON_TOKEN_CHARS.sub("_", category.upper()).strip("_")
    # Strip the trailing "_" AFTER truncation too: truncating at a "_"
    # boundary would otherwise leave one, making category_prefix
    # non-idempotent — and sync_counter_floors re-derives the prefix from a
    # minted token, so a mismatched key silently defeats the pinned/session
    # counter floor and re-opens the cross-conversation collision.
    prefix = prefix[:MAX_PREFIX_LEN].rstrip("_")
    return prefix or "REDACTED"


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
