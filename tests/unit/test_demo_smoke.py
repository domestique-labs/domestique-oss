"""Hermetic end-to-end smoke test for `domestique demo`.

Unlike test_wedge_cli.py (which calls ``main()`` in-process), this runs the CLI as a
real subprocess — exercising the packaged console entry point when installed, or the
module path otherwise. `demo` needs no API key and no network, so the tight timeout
also guards against a regression that starts reaching out.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest

_SECRET = "AKIAIOSFODNN7EXAMPLE"


def _demo_argv() -> list[str]:
    # Prefer the installed console script (proves packaging); fall back to the module.
    script = shutil.which("domestique")
    if script:
        return [script, "demo"]
    return [sys.executable, "-m", "domestique.cli", "demo"]


def test_demo_subprocess_redacts_secret():
    proc = subprocess.run(
        _demo_argv(),
        capture_output=True,
        text=True,
        timeout=60,  # local, no network — a hang means something reached out
    )

    assert proc.returncode == 0, proc.stderr
    out = proc.stdout

    # The secret appears in the BEFORE line but must be gone from what the model sees.
    after_block = out.split("AFTER")[-1]
    assert _SECRET not in after_block
    assert "REDACTED" in out


class TestDemoFormatting:
    def test_canned_output_has_config_header_and_findings(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from domestique.cli import run_demo

        run_demo(interactive=False)
        out = capsys.readouterr().out
        assert "Active configuration" in out
        assert "Detection stack" in out
        assert "BEFORE" in out and "AFTER" in out
        assert "[AWS_ACCESS_KEY_REDACTED]" in out

    def test_non_tty_emits_no_ansi(self, capsys: pytest.CaptureFixture[str]) -> None:
        from domestique.cli import run_demo

        # capsys makes stdout a non-tty -> color must be off
        run_demo(interactive=False)
        out = capsys.readouterr().out
        assert "\033[" not in out

    def test_interactive_ledger_on_user_input(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import MagicMock

        from domestique.cli import run_demo

        monkeypatch.setattr("builtins.input", MagicMock(side_effect=["ssn 123-45-6789", ""]))
        run_demo(interactive=True)
        out = capsys.readouterr().out
        assert "redacted" in out
        assert "[US_SSN_REDACTED]" in out
