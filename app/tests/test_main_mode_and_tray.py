"""Tests for launch-mode resolution and tray startup degrading gracefully.

Two first-run crashes observed on macOS when optional extras are missing:

1. ``--mode auto`` unconditionally picked native on darwin, then crashed with
   ``ModuleNotFoundError: No module named 'AppKit'`` when pyobjc
   (``[macos-native]`` extra) wasn't installed. Auto must fall back to
   portable; an *explicit* ``--mode native`` should fail with an install hint.

2. Portable mode started ``SystemTray`` whose pystray import happens inside a
   background thread, so a missing ``[desktop]`` extra surfaced as an
   unhandled thread traceback mid-startup instead of a clean "tray disabled"
   notice.

Availability probes are mocked so these run identically on every CI OS.
"""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from app import main


class TestResolveMode:
    def test_auto_on_macos_with_appkit_is_native(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("app.main._native_available", return_value=True):
            assert main._resolve_mode("auto") == "native"

    def test_auto_on_macos_without_appkit_falls_back_to_portable(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("app.main._native_available", return_value=False):
            assert main._resolve_mode("auto") == "portable"
        out = capsys.readouterr().out
        assert "macos-native" in out  # install hint, not a traceback

    def test_auto_off_macos_is_portable_without_probing_appkit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        with patch("app.main._native_available", side_effect=AssertionError) as probe:
            assert main._resolve_mode("auto") == "portable"
        probe.assert_not_called()

    def test_explicit_native_off_macos_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        with pytest.raises(RuntimeError, match="only available on macOS"):
            main._resolve_mode("native")

    def test_explicit_native_without_appkit_raises_with_install_hint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        with (
            patch("app.main._native_available", return_value=False),
            pytest.raises(RuntimeError, match="macos-native"),
        ):
            main._resolve_mode("native")

    def test_explicit_portable_never_probes_appkit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("app.main._native_available", side_effect=AssertionError) as probe:
            assert main._resolve_mode("portable") == "portable"
        probe.assert_not_called()


class TestStartSystemTray:
    def test_missing_tray_deps_returns_none_with_hint(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with patch("app.main._tray_available", return_value=False):
            assert main._start_system_tray(9876) is None
        assert "desktop" in capsys.readouterr().out  # install hint printed

    def test_available_tray_deps_start_the_tray(self) -> None:
        with (
            patch("app.main._tray_available", return_value=True),
            patch("app.services.tray.SystemTray") as tray_cls,
        ):
            tray = main._start_system_tray(9876)
        assert tray is tray_cls.return_value
        tray_cls.return_value.start.assert_called_once()
