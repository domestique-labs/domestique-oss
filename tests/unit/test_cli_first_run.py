"""Tests for the first-run setup offer in `domestique start`.

The gate must NEVER prompt when: --no-setup was passed, a config already
exists, or stdin is not an interactive TTY (pipes, CI, service managers).
It prompts exactly once on a true first interactive run.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import domestique.setup_wizard as wizard
from domestique.cli import _maybe_offer_first_run_setup


class TestFirstRunGate:
    def _arm(self, monkeypatch, tmp_path, *, tty: bool):
        """Point the config home at tmp and stub out prompt/wizard."""
        monkeypatch.setattr(wizard, "DOMESTIQUE_HOME", tmp_path)
        prompt = MagicMock(return_value=False)
        run = MagicMock(return_value=0)
        monkeypatch.setattr(wizard, "prompt_yes_no", prompt)
        monkeypatch.setattr(wizard, "run_wizard", run)
        stdin = MagicMock()
        stdin.isatty.return_value = tty
        monkeypatch.setattr("sys.stdin", stdin)
        return prompt, run

    def test_no_prompt_when_not_a_tty(self, monkeypatch, tmp_path):
        prompt, run = self._arm(monkeypatch, tmp_path, tty=False)
        _maybe_offer_first_run_setup(False)
        prompt.assert_not_called()
        run.assert_not_called()

    def test_no_prompt_when_config_exists(self, monkeypatch, tmp_path):
        prompt, run = self._arm(monkeypatch, tmp_path, tty=True)
        (tmp_path / "config.json").write_text("{}")
        _maybe_offer_first_run_setup(False)
        prompt.assert_not_called()
        run.assert_not_called()

    def test_no_prompt_with_no_setup_flag(self, monkeypatch, tmp_path):
        prompt, run = self._arm(monkeypatch, tmp_path, tty=True)
        _maybe_offer_first_run_setup(True)
        prompt.assert_not_called()
        run.assert_not_called()

    def test_prompts_on_true_first_interactive_run(self, monkeypatch, tmp_path):
        prompt, run = self._arm(monkeypatch, tmp_path, tty=True)
        _maybe_offer_first_run_setup(False)
        prompt.assert_called_once()

    def test_decline_skips_wizard_and_continues(self, monkeypatch, tmp_path, capsys):
        prompt, run = self._arm(monkeypatch, tmp_path, tty=True)
        prompt.return_value = False
        _maybe_offer_first_run_setup(False)
        run.assert_not_called()
        assert "regex-only" in capsys.readouterr().out

    def test_accept_runs_wizard(self, monkeypatch, tmp_path):
        prompt, run = self._arm(monkeypatch, tmp_path, tty=True)
        prompt.return_value = True
        _maybe_offer_first_run_setup(False)
        run.assert_called_once()
