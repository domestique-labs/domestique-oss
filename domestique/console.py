"""Cross-platform console primitives for Domestique CLI output.

stdlib only. Color is emitted only to a color-capable TTY (honoring
NO_COLOR); on Windows, VT processing is enabled best-effort via ctypes.
Glyphs degrade to ASCII on consoles that cannot encode them (cp1252).
"""

from __future__ import annotations

import os
import sys

from domestique.branding import supports_unicode

_ANSI = {
    "red": "\033[31m",
    "green": "\033[32m",
    "cyan": "\033[36m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}

_UNICODE_GLYPHS = {"check": "✔", "cross": "✖", "dot": "•", "arrow": "→", "rule": "─"}
_ASCII_GLYPHS = {"check": "+", "cross": "x", "dot": "*", "arrow": "->", "rule": "-"}


def enable_windows_vt() -> bool:
    """Best-effort enable of ANSI VT processing on a Windows console.

    Returns True only if VT was successfully enabled. No-op (False) on any
    non-Windows platform or on any failure.
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        enable_vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, mode.value | enable_vt))
    except Exception:
        return False


def supports_color(stream: object | None = None) -> bool:
    """Whether ANSI color should be emitted to *stream* (default stdout)."""
    stream = stream if stream is not None else sys.stdout
    if "NO_COLOR" in os.environ:
        return False
    try:
        if not (stream is not None and stream.isatty()):  # type: ignore[union-attr]
            return False
    except (ValueError, AttributeError):
        return False
    if sys.platform == "win32":
        return enable_windows_vt()
    return True


def glyphs(unicode_ok: bool | None = None) -> dict[str, str]:
    """Glyph set for the current console — unicode or ASCII fallback."""
    ok = supports_unicode() if unicode_ok is None else unicode_ok
    return dict(_UNICODE_GLYPHS if ok else _ASCII_GLYPHS)


class Palette:
    """Colorizer that no-ops when color is disabled."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, color: str) -> str:
        if not self.enabled:
            return text
        return f"{_ANSI[color]}{text}{_ANSI['reset']}"
