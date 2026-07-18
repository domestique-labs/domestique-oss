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
import json
import logging
import os
import time
from typing import TYPE_CHECKING, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    from pathlib import Path

from domestique.vault.session import category_prefix

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
            self._entries = {}
            self._by_token = {}
            self._available = True
            return
        try:
            envelope = json.loads(self._path.read_text(encoding="utf-8"))
            nonce = base64.b64decode(envelope["nonce"])
            ct = base64.b64decode(envelope["ct"])
            plaintext = AESGCM(self._key).decrypt(nonce, ct, None)
            self._entries = json.loads(plaintext.decode("utf-8"))
            self._by_token = {str(e["token"]): value for value, e in self._entries.items()}
            self._available = True
        except (KeyError, ValueError, InvalidTag, OSError, json.JSONDecodeError):
            logger.warning("vault_unreadable path=%s — pinned vault disabled", self._path)
            self._available = False

    def pin(self, value: str, category: str) -> str:
        """Persist *value* with a stable numbered token; returns the token ('' if unavailable)."""
        if not self._available or self._key is None:
            return ""
        existing = self._entries.get(value)
        if existing is not None:
            return str(existing["token"])
        prefix = category_prefix(category)
        index = self.max_index(prefix) + 1
        token = f"[{prefix}_{index}]"
        self._entries[value] = {"token": token, "category": category, "created_at": time.time()}
        self._by_token[token] = value
        self._write()
        return token

    def lookup_value(self, value: str) -> str | None:
        entry = self._entries.get(value) if self._available else None
        return str(entry["token"]) if entry else None

    def lookup_token(self, token: str) -> str | None:
        return self._by_token.get(token) if self._available else None

    def values(self) -> dict[str, tuple[str, str]]:
        """Snapshot: value -> (token, category)."""
        if not self._available:
            return {}
        return {v: (str(e["token"]), str(e["category"])) for v, e in self._entries.items()}

    def max_index(self, category: str) -> int:
        """Highest numbered token index used for *category* (0 if none)."""
        prefix = category_prefix(category)
        best = 0
        for token in self._by_token:
            head, _, tail = token.strip("[]").rpartition("_")
            if head == prefix and tail.isdigit():
                best = max(best, int(tail))
        return best

    def _write(self) -> None:
        """Atomic encrypt-and-replace of the vault file."""
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
        tmp = self._path.with_suffix(".tmp")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(envelope, encoding="utf-8")
        os.replace(tmp, self._path)
