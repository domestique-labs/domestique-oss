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


def _has_nonce_or_hash(sources: list[str]) -> bool:
    """True if the source list already contains a nonce or hash expression
    (which per CSP2/3 means 'unsafe-inline' is already being ignored)."""
    return any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sources)


def _ensure_hash_on_directive(
    directives: list[tuple[str, list[str]]], names: list[str], dname: str, token: str
) -> bool:
    """Ensure `token` is allowed by directive `dname` if it exists. Returns True
    if a change was made. If the directive already permits inline via
    'unsafe-inline' and has no nonce/hash yet, leave it untouched (our script
    already runs, and adding a hash would disable 'unsafe-inline' and break the
    page's own inline scripts)."""
    if dname not in names:
        return False
    i = names.index(dname)
    name, sources = directives[i]
    if "'unsafe-inline'" in sources and not _has_nonce_or_hash(sources):
        return False
    if token in sources:
        return False
    directives[i] = (name, [*sources, token])
    return True


def relax_csp_for_injection(policy: str, script_hash: str) -> str:
    """Add exactly the widget's sha256 to whichever directive governs element
    scripts, without ever weakening the policy. See module docstring.

    - If `script-src-elem`/`script-src` exist, ensure the hash is allowed there
      (respecting the 'unsafe-inline' guard, and covering `script-src-attr` too).
    - Else if `default-src` exists, add a `script-src` = its sources + the hash
      (unless default-src already allows inline via 'unsafe-inline' with no
      nonce/hash, in which case the widget already runs — leave it).
    - Else the policy doesn't restrict scripts; return it unchanged.
    Every other directive is preserved verbatim. Blank input returned as-is.
    """
    if not policy.strip():
        return policy
    token = f"'sha256-{script_hash}'"
    directives = _parse_csp(policy)
    names = [name.lower() for name, _ in directives]

    if "script-src-elem" in names or "script-src" in names or "script-src-attr" in names:
        changed = False
        for dname in ("script-src-elem", "script-src", "script-src-attr"):
            if _ensure_hash_on_directive(directives, names, dname, token):
                changed = True
        return _serialize_csp(directives) if changed else policy

    if "default-src" in names:
        default_sources = directives[names.index("default-src")][1]
        if "'unsafe-inline'" in default_sources and not _has_nonce_or_hash(default_sources):
            return policy
        directives.append(("script-src", [*default_sources, token]))
        return _serialize_csp(directives)

    return policy
