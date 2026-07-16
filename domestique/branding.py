"""Shared console branding for Domestique surfaces.

Both the developer CLI wedge (``domestique start``) and the desktop app
launcher (``python -m app``) print the same figlet logo on startup. It lives
here so the two entry points cannot drift apart.

Constraints (deliberate):
  - stdlib only — this module is imported by ``app/`` (which may depend on
    ``domestique/``, never the reverse) and must add zero dependencies.
  - ``LOGO`` is pure ASCII so the logo itself renders on any console; only
    decorative glyphs around it are gated on :func:`supports_unicode`.
"""

from __future__ import annotations

import sys

# figlet "standard" rendering of "domestique"
LOGO = r"""
     _                           _   _
  __| | ___  _ __ ___   ___  ___| |_(_) __ _ _   _  ___
 / _` |/ _ \| '_ ` _ \ / _ \/ __| __| |/ _` | | | |/ _ \
| (_| | (_) | | | | | |  __/\__ \ |_| | (_| | |_| |  __/
 \__,_|\___/|_| |_| |_|\___||___/\__|_|\__, |\__,_|\___|
                                          |_|
"""


def supports_unicode() -> bool:
    """Whether stdout can encode the fancy banner glyphs (False on a cp1252 console)."""
    enc = getattr(sys.stdout, "encoding", None) or ""
    try:
        "►✔→─".encode(enc)
    except (LookupError, UnicodeError):
        return False
    return True
