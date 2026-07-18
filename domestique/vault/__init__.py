"""Reversible-redaction vault: session tokens, pinned vault, detokenization.

The vault package owns the value↔token mappings behind numbered redaction
tokens like ``[SSN_1]``. Detection lives in ``domestique.detectors``; this
package only mints, stores, and reverses tokens.
"""

from __future__ import annotations

from domestique.vault.session import SessionStore

__all__ = ["SessionStore"]
