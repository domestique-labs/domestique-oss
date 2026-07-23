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

_HEAD_RE = re.compile(r"<head\b[^>]*>", re.IGNORECASE)
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


def _parse_csp(policy: str) -> list[tuple[str, list[str]]]:
    """Parse a CSP into an ordered list of (directive, [sources])."""
    parsed: list[tuple[str, list[str]]] = []
    for chunk in policy.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split()
        parsed.append((parts[0], parts[1:]))
    return parsed


def _serialize_csp(directives: list[tuple[str, list[str]]]) -> str:
    return "; ".join(
        name if not sources else f"{name} {' '.join(sources)}" for name, sources in directives
    )


def relax_csp_for_injection(policy: str, script_hash: str) -> str:
    """Add exactly the widget's sha256 to the policy's script-src.

    - If a ``script-src`` directive exists, append the hash to it.
    - Else if a ``default-src`` exists, add a new ``script-src`` = its sources
      plus the hash (so scripts stay as restricted as before, plus our widget).
    - Else the policy doesn't restrict scripts, so return it unchanged.
    Every other directive is preserved verbatim. Blank input is returned as-is.
    """
    if not policy.strip():
        return policy
    token = f"'sha256-{script_hash}'"
    directives = _parse_csp(policy)
    names = [name.lower() for name, _ in directives]

    if "script-src" in names:
        i = names.index("script-src")
        name, sources = directives[i]
        if token not in sources:
            directives[i] = (name, [*sources, token])
        return _serialize_csp(directives)

    if "default-src" in names:
        default_sources = directives[names.index("default-src")][1]
        directives.append(("script-src", [*default_sources, token]))
        return _serialize_csp(directives)

    return policy
