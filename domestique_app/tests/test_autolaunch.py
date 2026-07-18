"""Tests for auto-launch management."""

from __future__ import annotations

import plistlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from domestique_app.services.autolaunch import (
    BUNDLE_ID,
    AutoLaunchManager,
    generate_installer_script,
    generate_uninstaller_script,
)


@pytest.fixture
def manager(tmp_path, monkeypatch):
    """Create an AutoLaunchManager with temp paths."""
    monkeypatch.setattr("domestique_app.services.autolaunch.is_macos", lambda: True)
    monkeypatch.setattr("domestique_app.services.autolaunch.is_windows", lambda: False)
    plist_path = tmp_path / "LaunchAgents" / f"{BUNDLE_ID}.plist"
    monkeypatch.setattr("domestique_app.services.autolaunch.LAUNCH_AGENT_PLIST", plist_path)
    monkeypatch.setattr(
        "domestique_app.services.autolaunch.LAUNCH_AGENT_DIR", tmp_path / "LaunchAgents"
    )
    return AutoLaunchManager()


class TestAutoLaunchManager:
    """Test auto-launch lifecycle."""

    def test_not_enabled_by_default(self, manager):
        assert not manager.is_enabled

    @patch("domestique_app.services.autolaunch.subprocess.run")
    def test_enable_creates_plist(self, mock_run, manager, tmp_path, monkeypatch):
        # Mock launchctl commands
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        plist_path = tmp_path / "LaunchAgents" / f"{BUNDLE_ID}.plist"
        monkeypatch.setattr("domestique_app.services.autolaunch.LAUNCH_AGENT_PLIST", plist_path)

        # Mock log dir creation
        log_dir = Path.home() / ".domestique" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        result = manager.enable()
        assert result is True
        assert plist_path.exists()

        # Verify plist content
        with open(plist_path, "rb") as f:
            plist = plistlib.load(f)
        assert plist["Label"] == BUNDLE_ID
        assert plist["RunAtLoad"] is True
        assert plist["KeepAlive"]["SuccessfulExit"] is False

    @patch("domestique_app.services.autolaunch.subprocess.run")
    def test_disable_removes_plist(self, mock_run, manager, tmp_path, monkeypatch):
        mock_run.return_value = MagicMock(returncode=0)

        plist_path = tmp_path / "LaunchAgents" / f"{BUNDLE_ID}.plist"
        monkeypatch.setattr("domestique_app.services.autolaunch.LAUNCH_AGENT_PLIST", plist_path)

        # Create a fake plist
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        plist_path.write_text("fake")

        result = manager.disable()
        assert result is True
        assert not plist_path.exists()

    @patch("domestique_app.services.autolaunch.subprocess.run")
    def test_is_enabled_checks_launchctl(self, mock_run, manager, tmp_path, monkeypatch):
        plist_path = tmp_path / "LaunchAgents" / f"{BUNDLE_ID}.plist"
        monkeypatch.setattr("domestique_app.services.autolaunch.LAUNCH_AGENT_PLIST", plist_path)

        # Create plist and mock launchctl list success
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        plist_path.write_text("fake")
        mock_run.return_value = MagicMock(returncode=0)

        assert manager.is_enabled


class TestInstallerScripts:
    """Test installer/uninstaller script generation."""

    def test_installer_script_is_valid_bash(self):
        script = generate_installer_script()
        assert script.startswith("#!/bin/bash")
        assert "set -euo pipefail" in script
        assert "pip install" in script
        assert "launchctl" not in script  # Uses Python AutoLaunchManager

    def test_uninstaller_script_is_valid_bash(self):
        script = generate_uninstaller_script()
        assert script.startswith("#!/bin/bash")
        assert BUNDLE_ID in script
        assert "networksetup" in script
        assert "security delete-certificate" in script

    def test_installer_references_correct_paths(self):
        script = generate_installer_script()
        assert "$HOME/.domestique" in script
        assert "generate_ca" in script
        assert "AutoLaunchManager" in script
