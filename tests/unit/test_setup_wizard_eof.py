"""EOF on stdin must fail SAFE everywhere in the wizard.

A non-interactive stdin (pipe, CI, `docker run -t` without -i) makes
``input()`` raise EOFError. Prompts whose accept-path has side effects
(pip installs, HuggingFace/spaCy downloads, `ollama pull`) must decline
on EOF instead of auto-accepting their default — otherwise
``echo | domestique setup`` silently installs hundreds of MB of extras
and pulls an Ollama model. Only ``--yes`` may opt into that.
"""

from __future__ import annotations

import argparse
from unittest.mock import MagicMock

import pytest

import domestique.setup_wizard as wizard

HW = wizard.HardwareProfile(
    ram_gb=16.0,
    gpu="Test GPU",
    vram_gb=4.0,
    free_vram_gb=1.0,
    ollama_present=True,
    ollama_version="ollama version is 0.32.0",
)


@pytest.fixture
def eof_stdin(monkeypatch):
    monkeypatch.setattr("builtins.input", MagicMock(side_effect=EOFError))


def _installer_args(**overrides) -> argparse.Namespace:
    defaults = {"yes": False, "features": None, "no_local_llm": False, "preset": None}
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestWalkthroughPromptsFailSafeOnEof:
    def test_decide_eof_declines_even_when_default_is_yes(self, eof_stdin):
        assert wizard._decide("enable thing?", default=True, yes=False) is False

    def test_wizard_plan_confirm_eof_aborts(self, eof_stdin):
        choices = wizard.WizardChoices(
            gliner=True, preset="legacy-cpu", browser=False, desktop_ui=False
        )
        assert wizard._confirm_wizard_plan(choices, ["ner"]) is False


class TestInstallerPromptsFailSafeOnEof:
    def test_pick_features_eof_selects_nothing(self, eof_stdin):
        assert wizard.pick_features(_installer_args()) == set()

    def test_pick_preset_eof_returns_none(self, eof_stdin):
        preset = wizard.pick_preset(
            _installer_args(), ram_gb=16.0, vram_gb=4.0, free_vram_gb=1.0
        )
        assert preset is None

    def test_confirm_plan_eof_aborts(self, eof_stdin):
        assert wizard.confirm_plan({"ner"}, "legacy-cpu") is False


class TestRunWizardEofEndToEnd:
    def test_run_wizard_eof_aborts_without_installing(self, eof_stdin, monkeypatch, capsys):
        """`domestique setup` on a piped/EOF stdin: exit 1, zero side effects."""
        monkeypatch.setattr(wizard, "detect_hardware", MagicMock(return_value=HW))
        install = MagicMock()
        write_cfg = MagicMock()
        monkeypatch.setattr(wizard, "_install_wizard_selection", install)
        monkeypatch.setattr(wizard, "apply_wizard_config", write_cfg)

        rc = wizard.run_wizard(yes=False, demo=False)

        assert rc == 1
        install.assert_not_called()
        write_cfg.assert_not_called()
        assert "aborted" in capsys.readouterr().out
