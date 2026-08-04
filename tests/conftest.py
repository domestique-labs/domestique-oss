"""Pytest configuration."""

import os
import sys
from pathlib import Path

import pytest

# Ensure the project root is importable.
sys.path.insert(0, str(Path(__file__).parent.parent))

# No test may touch the real OS keyring. Set before anything imports `keyring`,
# because the backend is chosen at import time.
#
# On macOS this is not merely hygiene. `keyring.set_password` reaches the
# Security framework, which looks for `$HOME/Library/Keychains/login.keychain-db`.
# Run the suite with HOME pointed anywhere else — a scratch dir, a sandbox, CI —
# and it fails with `A keychain cannot be found to store "vault-key"`, surfaced
# as a *system dialog*. pytest then blocks indefinitely waiting for a human to
# dismiss it, which is the "hang" reported in issue #74. With the real HOME it
# is worse in a different way: the suite writes a key into the developer's
# actual login keychain.
os.environ.setdefault("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")


@pytest.fixture(autouse=True)
def _isolate_user_state(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep every test out of the developer's real ``~/.domestique``.

    This lives at ``tests/`` rather than ``tests/unit/`` on purpose. The audit
    isolation used to be unit-only, so ``tests/integration`` still wrote real
    ``audit.jsonl`` and ``debug_trace.jsonl`` entries into the developer's home
    — verified by running the integration suite against a scratch HOME and
    finding both files created.

    Two names are needed for the audit log and they are not interchangeable:
    ``DOMESTIQUE_AUDIT_LOG_PATH`` is the ``Settings`` field ``audit_log_path``
    (env_prefix + field name) and controls where the proxy *writes*, while
    ``DOMESTIQUE_AUDIT_LOG`` is read by ``domestique/report.py`` and controls
    where ``report`` *reads*.

    ``debug_trace`` has no env var at all — ``TRACE_PATH`` is computed from
    ``Path.home()`` at import — so it is patched directly.
    """
    monkeypatch.setenv("DOMESTIQUE_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("DOMESTIQUE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))

    import domestique.debug_trace as dt

    monkeypatch.setattr(dt, "TRACE_PATH", tmp_path / "debug_trace.jsonl")
