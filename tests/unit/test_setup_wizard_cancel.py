"""Ctrl+C during the wizard must cancel cleanly, not traceback.

KeyboardInterrupt inside any prompt should print a cancellation notice
and exit with the conventional SIGINT code (130) — never a raw traceback,
and never with anything half-installed. The banner also must not claim
"first-run": the wizard is re-runnable by design.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import domestique.setup_wizard as wizard
from domestique.cli import _cmd_setup

HW = wizard.HardwareProfile(
    ram_gb=16.0,
    gpu="Test GPU",
    vram_gb=4.0,
    free_vram_gb=1.0,
    ollama_present=True,
    ollama_version="ollama version is 0.32.0",
)


@pytest.fixture
def interrupted_stdin(monkeypatch):
    monkeypatch.setattr("builtins.input", MagicMock(side_effect=KeyboardInterrupt))


class TestSetupCommandCtrlC:
    def test_ctrl_c_cancels_cleanly_with_exit_130(self, interrupted_stdin, monkeypatch, capsys):
        monkeypatch.setattr(wizard, "detect_hardware", MagicMock(return_value=HW))
        install = MagicMock()
        write_cfg = MagicMock()
        monkeypatch.setattr(wizard, "_install_wizard_selection", install)
        monkeypatch.setattr(wizard, "apply_wizard_config", write_cfg)

        rc = _cmd_setup(False)

        assert rc == 130
        install.assert_not_called()
        write_cfg.assert_not_called()
        out = capsys.readouterr().out
        assert "cancelled" in out

    def test_banner_does_not_claim_first_run(self, interrupted_stdin, monkeypatch, capsys):
        monkeypatch.setattr(wizard, "detect_hardware", MagicMock(return_value=HW))
        monkeypatch.setattr(wizard, "_install_wizard_selection", MagicMock())
        monkeypatch.setattr(wizard, "apply_wizard_config", MagicMock())

        _cmd_setup(False)

        assert "first-run" not in capsys.readouterr().out


class TestInstallerMainCtrlC:
    def test_ctrl_c_cancels_cleanly_with_exit_130(self, interrupted_stdin, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["setup_wizard"])
        monkeypatch.setattr(wizard, "detect_hardware", MagicMock(return_value=HW))
        install = MagicMock()
        monkeypatch.setattr(wizard, "install_extras", install)

        rc = wizard.main()

        assert rc == 130
        install.assert_not_called()
        assert "cancelled" in capsys.readouterr().out
