"""Tests for the bare `domestique browser` full-auto launcher.

Never imports domestique_app; the dashboard is a stub HTTP server and all
side-effecting calls (install, spawn, open-browser) are mocked.
"""

from __future__ import annotations

import sys

import pytest

import domestique.cli as cli


class TestDetectInstallContext:
    def test_pipx_when_pipx_home_set(self, monkeypatch):
        monkeypatch.setenv("PIPX_HOME", "/Users/x/.local/pipx")
        monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/pipx")
        kind, cmd = cli._detect_install_context()
        assert kind == "pipx"
        assert cmd == ["pipx", "inject", "domestique", "domestique[browser-proxy]"]

    def test_pip_fallback_when_not_pipx(self, monkeypatch):
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setattr(cli.sys, "prefix", "/opt/venv")
        kind, cmd = cli._detect_install_context()
        assert kind == "pip"
        assert cmd == [sys.executable, "-m", "pip", "install", "domestique[browser-proxy]"]


class TestEnsureBrowserDependency:
    def test_present_returns_true_no_install(self, monkeypatch):
        monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: object())
        called = []
        monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: called.append(a))
        assert cli._ensure_browser_dependency(assume_yes=True, no_install=False) is True
        assert called == []

    def test_missing_no_install_prints_hint(self, monkeypatch, capsys):
        monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
        assert cli._ensure_browser_dependency(assume_yes=True, no_install=True) is False
        assert "pipx inject domestique" in capsys.readouterr().out

    def test_missing_yes_installs_and_succeeds(self, monkeypatch):
        monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
        monkeypatch.setattr(cli, "_detect_install_context", lambda: ("pip", ["x"]))
        monkeypatch.setattr(
            cli.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0})()
        )
        assert cli._ensure_browser_dependency(assume_yes=True, no_install=False) is True

    def test_missing_install_fails_returns_false(self, monkeypatch, capsys):
        monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
        monkeypatch.setattr(cli, "_detect_install_context", lambda: ("pip", ["x"]))
        monkeypatch.setattr(
            cli.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 1})()
        )
        assert cli._ensure_browser_dependency(assume_yes=True, no_install=False) is False
        assert "pipx inject domestique" in capsys.readouterr().out
