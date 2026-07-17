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


class TestFirstRunRobustness:
    """Review findings: the gate must survive hostile stdin states, and EOF
    must fail SAFE (decline) — auto-accepting would install extras and pull
    multi-GB models unattended in the middle of `domestique start`."""

    def _home(self, monkeypatch, tmp_path):
        monkeypatch.setattr(wizard, "DOMESTIQUE_HOME", tmp_path)

    def test_stdin_none_is_not_interactive(self, monkeypatch, tmp_path):
        self._home(monkeypatch, tmp_path)
        run = MagicMock()
        monkeypatch.setattr(wizard, "run_wizard", run)
        monkeypatch.setattr("sys.stdin", None)
        _maybe_offer_first_run_setup(False)  # must not raise AttributeError
        run.assert_not_called()

    def test_closed_stdin_is_not_interactive(self, monkeypatch, tmp_path):
        self._home(monkeypatch, tmp_path)
        run = MagicMock()
        monkeypatch.setattr(wizard, "run_wizard", run)
        stdin = MagicMock()
        stdin.isatty.side_effect = ValueError("I/O operation on closed file")
        monkeypatch.setattr("sys.stdin", stdin)
        _maybe_offer_first_run_setup(False)  # must not raise ValueError
        run.assert_not_called()

    def test_eof_on_tty_declines_wizard(self, monkeypatch, tmp_path, capsys):
        """`docker run -t` without -i: isatty() is True but input() EOFs."""
        self._home(monkeypatch, tmp_path)
        run = MagicMock()
        monkeypatch.setattr(wizard, "run_wizard", run)
        stdin = MagicMock()
        stdin.isatty.return_value = True
        monkeypatch.setattr("sys.stdin", stdin)
        monkeypatch.setattr("builtins.input", MagicMock(side_effect=EOFError))
        _maybe_offer_first_run_setup(False)
        run.assert_not_called()
        assert "regex-only" in capsys.readouterr().out

    def test_wizard_systemexit_does_not_kill_start(self, monkeypatch, tmp_path, capsys):
        self._home(monkeypatch, tmp_path)
        monkeypatch.setattr(wizard, "prompt_yes_no", MagicMock(return_value=True))
        monkeypatch.setattr(wizard, "run_wizard", MagicMock(side_effect=SystemExit(1)))
        stdin = MagicMock()
        stdin.isatty.return_value = True
        monkeypatch.setattr("sys.stdin", stdin)
        _maybe_offer_first_run_setup(False)  # must not raise SystemExit
        out = capsys.readouterr().out
        assert "did not complete" in out
        assert "regex-only" in out


class TestPromptEofDefault:
    def test_eof_returns_eof_default_not_default(self, monkeypatch):
        monkeypatch.setattr("builtins.input", MagicMock(side_effect=EOFError))
        assert wizard.prompt_yes_no("q?", default=True, eof_default=False) is False

    def test_eof_without_eof_default_keeps_old_behavior(self, monkeypatch):
        monkeypatch.setattr("builtins.input", MagicMock(side_effect=EOFError))
        assert wizard.prompt_yes_no("q?", default=True) is True


class TestInteractiveDemo:
    """`domestique demo` grows a TTY-only try-your-own loop (user feedback:
    the canned demo alone isn't convincing). Non-TTY behavior is unchanged."""

    def _pipeline(self, monkeypatch):
        from unittest.mock import AsyncMock

        result = MagicMock()
        result.redacted_text = "AFTER [REDACTED]"
        f = MagicMock()
        f.description = "secret_scanner:aws_access_key (99%)"
        result.findings = [f]
        pipeline = MagicMock()
        pipeline.inspect = AsyncMock(return_value=result)
        monkeypatch.setattr(
            "domestique.gateway.build_wedge_pipeline", MagicMock(return_value=pipeline)
        )
        return pipeline

    def test_non_tty_skips_interactive_loop(self, monkeypatch, capsys):
        from domestique.cli import run_demo

        self._pipeline(monkeypatch)
        stdin = MagicMock()
        stdin.isatty.return_value = False
        monkeypatch.setattr("sys.stdin", stdin)
        assert run_demo() == 0
        out = capsys.readouterr().out
        assert "try your own" not in out.lower()

    def test_interactive_loop_redacts_user_input(self, monkeypatch, capsys):
        from domestique.cli import run_demo

        pipeline = self._pipeline(monkeypatch)
        monkeypatch.setattr(
            "builtins.input", MagicMock(side_effect=["my key AKIA123", ""])
        )
        assert run_demo(interactive=True) == 0
        out = capsys.readouterr().out
        assert "try your own" in out.lower()
        assert "AFTER [REDACTED]" in out
        assert "aws_access_key" in out
        assert pipeline.inspect.await_count == 2  # canned + one user prompt

    def test_interactive_loop_eof_exits_cleanly(self, monkeypatch):
        from domestique.cli import run_demo

        self._pipeline(monkeypatch)
        monkeypatch.setattr("builtins.input", MagicMock(side_effect=EOFError))
        assert run_demo(interactive=True) == 0  # must not raise
