"""Reversible-redaction vault: session tokens, pinned vault, detokenization.

The vault package owns the value↔token mappings behind numbered redaction
tokens like ``[SSN_1]``. Detection lives in ``domestique.detectors``; this
package only mints, stores, and reverses tokens.
"""

from __future__ import annotations

from pathlib import Path

from domestique.vault.pinned import KeyringKeyProvider, PinnedVault
from domestique.vault.service import TokenService
from domestique.vault.session import SessionStore
from domestique.vault.stream import StreamDetokenizer

__all__ = [
    "KeyringKeyProvider",
    "PinnedVault",
    "SessionStore",
    "StreamDetokenizer",
    "TokenService",
    "build_default_token_service",
]


def build_default_token_service(*, pinned: bool = True) -> TokenService:
    """Production TokenService: session store + (optionally) the user's
    keyring-encrypted pinned vault at ``~/.domestique/vault.bin``.

    Touches the OS keyring once; if unavailable the pinned vault disables
    itself and session-scoped redaction continues at full strength.
    """
    vault: PinnedVault | None = None
    if pinned:
        vault = PinnedVault(Path.home() / ".domestique" / "vault.bin", KeyringKeyProvider())
        vault.load()
    return TokenService(SessionStore(), vault)
