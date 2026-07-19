from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from domestique import console

if TYPE_CHECKING:
    import pytest


class TestSupportsColor:
    def _stream(self, *, tty: bool) -> MagicMock:
        s = MagicMock()
        s.isatty.return_value = tty
        return s

    def test_no_color_env_disables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        assert console.supports_color(self._stream(tty=True)) is False

    def test_empty_no_color_still_disables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "")
        assert console.supports_color(self._stream(tty=True)) is False

    def test_non_tty_disables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert console.supports_color(self._stream(tty=False)) is False

    def test_closed_stream_disables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        s = MagicMock()
        s.isatty.side_effect = ValueError("I/O operation on closed file")
        assert console.supports_color(s) is False

    def test_posix_tty_enables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setattr(console.sys, "platform", "linux")
        assert console.supports_color(self._stream(tty=True)) is True

    def test_windows_defers_to_vt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setattr(console.sys, "platform", "win32")
        with patch.object(console, "enable_windows_vt", return_value=False):
            assert console.supports_color(self._stream(tty=True)) is False
        with patch.object(console, "enable_windows_vt", return_value=True):
            assert console.supports_color(self._stream(tty=True)) is True


class TestGlyphs:
    def test_unicode_glyphs(self) -> None:
        g = console.glyphs(unicode_ok=True)
        assert g["check"] == "✔" and g["arrow"] == "→"

    def test_ascii_fallback(self) -> None:
        g = console.glyphs(unicode_ok=False)
        assert g == {"check": "+", "cross": "x", "dot": "*", "arrow": "->", "rule": "-"}


class TestPalette:
    def test_enabled_wraps_in_ansi(self) -> None:
        p = console.Palette(enabled=True)
        assert p("hi", "red") == "\033[31mhi\033[0m"

    def test_disabled_is_identity(self) -> None:
        p = console.Palette(enabled=False)
        assert p("hi", "red") == "hi"

    def test_enable_windows_vt_noop_off_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(console.sys, "platform", "linux")
        assert console.enable_windows_vt() is False
