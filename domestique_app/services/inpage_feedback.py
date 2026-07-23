"""In-page block-feedback injection helpers.

Pure string logic — no mitmproxy/flow objects — so it is unit-testable in
isolation and keeps the block/CSP decisions in one reviewable place. The
addon (mitm_addon.py) calls these to inject the widget asset into top-level
HTML pages of intercepted LLM hosts and to narrow the page CSP so the inline
widget is allowed. Everything here is presentation-only: callers must treat
any failure as "leave the body untouched" and never let it affect the block.
"""

from __future__ import annotations

import base64
import hashlib
import re
from functools import lru_cache
from importlib.resources import files

INJECTION_MARKER = "domestique-inpage-widget"

_HEAD_RE = re.compile(r"<head[^>]*>", re.IGNORECASE)
_BODY_CLOSE_RE = re.compile(r"</body\s*>", re.IGNORECASE)


@lru_cache(maxsize=1)
def load_widget_js() -> str:
    """Return the widget asset text (cached for the process lifetime)."""
    return (files("domestique_app") / "assets" / "inpage_widget.js").read_text(encoding="utf-8")


def compute_script_hash(js: str) -> str:
    """Base64 SHA-256 of the script's UTF-8 bytes (bare digest, no prefix).

    The CSP source expression is built by the CSP layer as 'sha256-<digest>'.
    """
    digest = hashlib.sha256(js.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


def _script_block() -> str:
    # The id doubles as the idempotency sentinel. The CSP hash is computed over
    # the script's text content only (attributes don't affect the hash), so the
    # inlined body must be exactly load_widget_js().
    return f'<script id="{INJECTION_MARKER}">{load_widget_js()}</script>'


def inject_widget(html: str) -> str | None:
    """Insert the widget <script> right after <head> (fallback: before </body>).

    Returns the modified HTML, or None if the widget is already present or no
    injection point exists.
    """
    if INJECTION_MARKER in html:
        return None
    block = _script_block()
    m = _HEAD_RE.search(html)
    if m:
        idx = m.end()
        return html[:idx] + block + html[idx:]
    m2 = _BODY_CLOSE_RE.search(html)
    if m2:
        idx = m2.start()
        return html[:idx] + block + html[idx:]
    return None
