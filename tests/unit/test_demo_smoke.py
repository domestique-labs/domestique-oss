"""Hermetic end-to-end smoke test for `llmguard demo`.

Unlike test_wedge_cli.py (which calls ``main()`` in-process), this runs the CLI as a
real subprocess — exercising the packaged console entry point when installed, or the
module path otherwise. `demo` needs no API key and no network, so the tight timeout
also guards against a regression that starts reaching out.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

_SECRET = "AKIAIOSFODNN7EXAMPLE"


def _demo_argv() -> list[str]:
    # Prefer the installed console script (proves packaging); fall back to the module.
    script = shutil.which("llmguard")
    if script:
        return [script, "demo"]
    return [sys.executable, "-m", "llmguard.cli", "demo"]


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
