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

from domestique_app import main


class TestResolveMode:
    def test_auto_on_macos_with_appkit_is_native(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("domestique_app.main._native_available", return_value=True):
            assert main._resolve_mode("auto") == "native"

    def test_auto_on_macos_without_appkit_falls_back_to_portable(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("domestique_app.main._native_available", return_value=False):
            assert main._resolve_mode("auto") == "portable"
        out = capsys.readouterr().out
        assert "macos-native" in out  # install hint, not a traceback

    def test_auto_off_macos_is_portable_without_probing_appkit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        with patch("domestique_app.main._native_available", side_effect=AssertionError) as probe:
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
            patch("domestique_app.main._native_available", return_value=False),
            pytest.raises(RuntimeError, match="macos-native"),
        ):
            main._resolve_mode("native")

    def test_explicit_portable_never_probes_appkit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("domestique_app.main._native_available", side_effect=AssertionError) as probe:
            assert main._resolve_mode("portable") == "portable"
        probe.assert_not_called()


class TestAvailabilityProbes:
    """find_spec itself can raise in edge states (module stubbed into
    sys.modules with __spec__ unset, broken meta-path finder) — the probes
    must degrade to False, never crash (review finding)."""

    def test_native_probe_swallows_valueerror(self) -> None:
        with patch("importlib.util.find_spec", side_effect=ValueError("__spec__ is None")):
            assert main._native_available() is False

    def test_native_probe_swallows_importerror(self) -> None:
        with patch("importlib.util.find_spec", side_effect=ImportError):
            assert main._native_available() is False

    def test_tray_probe_swallows_valueerror(self) -> None:
        with patch("importlib.util.find_spec", side_effect=ValueError("__spec__ is None")):
            assert main._tray_available() is False


class TestMainErrorPresentation:
    def test_explicit_native_off_macos_exits_cleanly(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Mode-resolution RuntimeErrors are config problems: message + exit 2,
        not a raw traceback (review finding)."""
        monkeypatch.setattr(sys, "platform", "linux")
        with pytest.raises(SystemExit) as excinfo:
            main.main(["--mode", "native"])
        assert excinfo.value.code == 2
        err = capsys.readouterr().err
        assert "error:" in err
        assert "only available on macOS" in err


class TestStartSystemTray:
    def test_missing_tray_deps_returns_none_with_hint(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with patch("domestique_app.main._tray_available", return_value=False):
            assert main._start_system_tray(9876) is None
        assert "desktop" in capsys.readouterr().out  # install hint printed

    def test_available_tray_deps_start_the_tray(self) -> None:
        with (
            patch("domestique_app.main._tray_available", return_value=True),
            patch("domestique_app.services.tray.SystemTray") as tray_cls,
        ):
            tray = main._start_system_tray(9876)
        assert tray is tray_cls.return_value
        tray_cls.return_value.start.assert_called_once()
