"""Tests for app.main's winget-install PATH-refresh retry helper (I5).

Mirrors tests/unit/test_install_ollama_retry.py for scripts/install.py's
copy of the same helper — both call sites poll `shutil.which` a few times
after `winget install Ollama.Ollama` instead of giving up on a single
immediate miss.
"""

from __future__ import annotations

from domestique_app import main


class TestWaitForCommand:
    def test_returns_immediately_when_already_present(self):
        calls = []

        def which(name):
            calls.append(name)
            return "C:/tools/ollama.exe"

        sleeps = []
        result = main._wait_for_command(
            "ollama", attempts=5, delay_seconds=0, which=which, sleep=sleeps.append
        )

        assert result == "C:/tools/ollama.exe"
        assert len(calls) == 1
        assert sleeps == []

    def test_retries_until_binary_appears(self):
        """Simulate winget's PATH lagging: which() misses twice, then hits."""
        responses = [None, None, "C:/tools/ollama.exe"]
        calls = []

        def which(name):
            calls.append(name)
            return responses[len(calls) - 1]

        sleeps = []
        result = main._wait_for_command(
            "ollama", attempts=5, delay_seconds=0.01, which=which, sleep=sleeps.append
        )

        assert result == "C:/tools/ollama.exe"
        assert len(calls) == 3
        assert sleeps == [0.01, 0.01]

    def test_gives_up_after_exhausting_attempts(self):
        calls = []

        def which(name):
            calls.append(name)
            return None

        sleeps = []
        result = main._wait_for_command(
            "ollama", attempts=3, delay_seconds=0.01, which=which, sleep=sleeps.append
        )

        assert result is None
        assert len(calls) == 3
        assert sleeps == [0.01, 0.01]
