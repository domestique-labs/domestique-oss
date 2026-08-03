"""Pytest configuration."""

import sys
from pathlib import Path

import pytest

# Ensure the project root is importable.
sys.path.insert(0, str(Path(__file__).parent.parent))


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
