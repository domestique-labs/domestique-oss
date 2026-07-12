"""Tests for scripts/install.py's Linux auto-venv bootstrap (I1).

README's Linux Quick Start ran `python3 scripts/install.py` directly
against the system Python, with no venv step — on PEP 668
("externally-managed-environment") distros like Debian 12+/Ubuntu 23.10+,
`pip install -e` fails outright. `_ensure_linux_venv` creates `.venv` and
re-execs the installer inside it, mirroring what install.ps1 (Windows) and
scripts/install.sh (macOS) already do before running pip.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from scripts import install


class TestEnsureLinuxVenv:
    def test_noop_on_non_linux(self):
        with patch.object(install.platform, "system", return_value="Windows"), \
             patch.object(install.subprocess, "run") as mock_run, \
             patch.object(install.os, "execv") as mock_execv:
            install._ensure_linux_venv()

        mock_run.assert_not_called()
        mock_execv.assert_not_called()

    def test_noop_when_already_running_inside_venv(self):
        venv_python = install.ROOT / ".venv" / "bin" / "python"
        with patch.object(install.platform, "system", return_value="Linux"), \
             patch.object(install.sys, "executable", str(venv_python)), \
             patch.object(install.subprocess, "run") as mock_run, \
             patch.object(install.os, "execv") as mock_execv:
            install._ensure_linux_venv()

        mock_run.assert_not_called()
        mock_execv.assert_not_called()

    def test_creates_venv_and_reexecs_when_missing(self):
        run_calls = []

        def fake_run(cmd, check=False, **kw):
            run_calls.append(cmd)
            return MagicMock(returncode=0)

        with patch.object(install.platform, "system", return_value="Linux"), \
             patch.object(install.sys, "executable", "/usr/bin/python3"), \
             patch.object(install.Path, "exists", return_value=False), \
             patch.object(install.subprocess, "run", side_effect=fake_run), \
             patch.object(install.os, "execv") as mock_execv:
            install._ensure_linux_venv()

        # First call creates the venv, second upgrades pip inside it.
        assert len(run_calls) == 2
        assert "venv" in run_calls[0]
        assert "pip" in run_calls[1]
        mock_execv.assert_called_once()
        exec_python, exec_argv = mock_execv.call_args[0]
        assert exec_python.endswith("python")
        assert exec_argv[0] == exec_python

    def test_reexecs_without_recreating_existing_venv(self):
        with patch.object(install.platform, "system", return_value="Linux"), \
             patch.object(install.sys, "executable", "/usr/bin/python3"), \
             patch.object(install.Path, "exists", return_value=True), \
             patch.object(install.subprocess, "run") as mock_run, \
             patch.object(install.os, "execv") as mock_execv:
            install._ensure_linux_venv()

        mock_run.assert_not_called()
        mock_execv.assert_called_once()
