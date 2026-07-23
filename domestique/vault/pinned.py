"""Encrypted persistent vault for pinned (common) values.

The vault file is an AES-256-GCM envelope — ``{"v":1,"nonce":b64,"ct":b64}``
— whose plaintext is JSON ``{value: {token, category, created_at}}``. The
key lives in the OS keyring (or any ``KeyProvider``), never on disk.

Fail-safe contract: any problem (no key, corrupt file, wrong key) flips
``available`` to False and every method becomes a no-op. The pinned vault
degrading NEVER weakens redaction — session tokens still cover everything;
only cross-restart stability is lost.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import tempfile
import threading
import time
from typing import TYPE_CHECKING, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    from pathlib import Path

from domestique.vault.session import category_prefix, render_token

logger = logging.getLogger(__name__)

_KEYRING_SERVICE = "domestique-vault"
_KEYRING_USER = "vault-key"


class KeyProvider(Protocol):
    """Source of the 32-byte vault key. Return None when unavailable."""

    def get_or_create_key(self) -> bytes | None: ...


class KeyringKeyProvider:
    """Stores a random AES-256 key in the OS keyring (DPAPI/Keychain/SecretService)."""

    def get_or_create_key(self) -> bytes | None:
        try:
            import keyring

            stored = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USER)
            if stored:
                return base64.b64decode(stored)
            key = os.urandom(32)
            keyring.set_password(_KEYRING_SERVICE, _KEYRING_USER, base64.b64encode(key).decode())
            return key
        except Exception:  # noqa: BLE001  # any backend failure = unavailable, never crash startup
            logger.warning(
                "vault_keyring_unavailable — pinned vault disabled (session redaction unaffected)"
            )
            return None


class PinnedVault:
    """Persistent value↔token registry for user-confirmed common values."""

    def __init__(self, path: Path, key_provider: KeyProvider) -> None:
        self._path = path
        self._key_provider = key_provider
        self._key: bytes | None = None
        self._entries: dict[str, dict[str, object]] = {}  # value -> {token, category, created_at}
        self._by_token: dict[str, str] = {}  # token -> value
        self._available = False
        # Guards every read/write of the two dicts. Pins mutate them while
        # hot-path threads iterate them (values()/max_index()); without this
        # lock those concurrent iterations raise "dictionary changed size
        # during iteration" and racing writers clobber each other's file.
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return self._available

    def load(self) -> None:
        """Unlock and read the vault. Runs once at startup — never on the hot path."""
        self._key = self._key_provider.get_or_create_key()
        if self._key is None:
            self._available = False
            return
        if not self._path.exists():
            with self._lock:
                self._entries = {}
                self._by_token = {}
            self._available = True
            return
        try:
            envelope = json.loads(self._path.read_text(encoding="utf-8"))
            nonce = base64.b64decode(envelope["nonce"])
            ct = base64.b64decode(envelope["ct"])
            plaintext = AESGCM(self._key).decrypt(nonce, ct, None)
            entries = json.loads(plaintext.decode("utf-8"))
            by_token = {str(e["token"]): value for value, e in entries.items()}
            with self._lock:
                self._entries = entries
                self._by_token = by_token
            self._available = True
        except (KeyError, ValueError, InvalidTag, OSError, json.JSONDecodeError):
            logger.warning("vault_unreadable path=%s — pinned vault disabled", self._path)
            self._available = False

    def pin(self, value: str, category: str, min_index: int = 1) -> str:
        """Persist *value* with a stable numbered token; returns the token ('' if unavailable).

        *min_index* floors the numeric index. Callers that share a token
        namespace with a live ``SessionStore`` (see ``TokenService.pin``) pass
        ``session_max + 1`` so a freshly-pinned value cannot collide with an
        already-minted session token of the same prefix. Defaults to 1, which
        preserves standalone behaviour (first pin of a prefix → ``_1``)."""
        if not self._available or self._key is None:
            return ""
        with self._lock:
            existing = self._entries.get(value)
            if existing is not None:
                return str(existing["token"])
            prefix = category_prefix(category)
            index = max(self._max_index_locked(prefix) + 1, min_index)
            token = render_token(prefix, index)
            self._entries[value] = {
                "token": token,
                "category": category,
                "created_at": time.time(),
            }
            self._by_token[token] = value
            self._write_locked()
            return token

    def lookup_value(self, value: str) -> str | None:
        if not self._available:
            return None
        with self._lock:
            entry = self._entries.get(value)
            return str(entry["token"]) if entry else None

    def lookup_token(self, token: str) -> str | None:
        if not self._available:
            return None
        with self._lock:
            return self._by_token.get(token)

    def values(self) -> dict[str, tuple[str, str]]:
        """Snapshot: value -> (token, category)."""
        if not self._available:
            return {}
        with self._lock:
            return {v: (str(e["token"]), str(e["category"])) for v, e in self._entries.items()}

    def max_index(self, category: str) -> int:
        """Highest numbered token index used for *category* (0 if none)."""
        if not self._available:
            return 0
        with self._lock:
            return self._max_index_locked(category_prefix(category))

    def _max_index_locked(self, prefix: str) -> int:
        """``max_index`` body; caller must already hold ``self._lock``.

        Takes an already-resolved *prefix* (not a raw category) so the
        locked ``pin`` path can reuse it without re-deriving.
        """
        best = 0
        for token in self._by_token:
            head, _, tail = token.strip("[]").rpartition("_")
            if head == prefix and tail.isdigit():
                best = max(best, int(tail))
        return best

    def _write_locked(self) -> None:
        """Atomic encrypt-and-replace of the vault file. Caller holds the lock.

        Serializing a snapshot of ``self._entries`` requires no concurrent
        mutation, which the lock guarantees. A per-write unique temp file
        (rather than a fixed ``vault.tmp``) means two writers — even in
        separate processes/instances sharing the path — never corrupt each
        other's write by renaming a shared temp out from under the pending
        ``os.replace``.

        That's the only cross-process guarantee this makes. ``self._entries``
        is an in-memory snapshot taken at ``load()`` time and never re-read
        from disk before a write, so two ``PinnedVault`` instances (e.g. two
        processes) pinning different values concurrently can still silently
        lose one writer's pin -- the later ``os.replace`` overwrites the file
        wholesale rather than merging. Closing this needs either a read-
        merge-write or an OS-level file lock around the read-modify-write
        sequence; not attempted here because today's only caller (``cli.py``)
        is single-process. Multi-process use of the same vault path is not
        currently supported.
        """
        if self._key is None:
            return
        plaintext = json.dumps(self._entries).encode("utf-8")
        nonce = os.urandom(12)
        ct = AESGCM(self._key).encrypt(nonce, plaintext, None)
        envelope = json.dumps(
            {
                "v": 1,
                "nonce": base64.b64encode(nonce).decode(),
                "ct": base64.b64encode(ct).decode(),
            }
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=".vault-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(envelope)
            os.replace(tmp_name, self._path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise
