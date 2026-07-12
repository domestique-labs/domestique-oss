"""Tests for the winget-install PATH-refresh retry helper (I5).

After `winget install Ollama.Ollama`, the installed binary's directory can
take a moment to become visible on PATH (winget's post-install steps can
lag behind the process returning). `_wait_for_command` polls `shutil.which`
a few times instead of giving up after a single immediate check.
"""

from __future__ import annotations

from scripts import install


class TestWaitForCommand:
    def test_returns_immediately_when_already_present(self):
        calls = []

        def which(name):
            calls.append(name)
            return "C:/tools/ollama.exe"

        sleeps = []
        result = install._wait_for_command(
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
        result = install._wait_for_command(
            "ollama", attempts=5, delay_seconds=0.01, which=which, sleep=sleeps.append
        )

        assert result == "C:/tools/ollama.exe"
        assert len(calls) == 3
        # Slept between misses, but not after the final hit.
        assert sleeps == [0.01, 0.01]

    def test_gives_up_after_exhausting_attempts(self):
        calls = []

        def which(name):
            calls.append(name)
            return None

        sleeps = []
        result = install._wait_for_command(
            "ollama", attempts=3, delay_seconds=0.01, which=which, sleep=sleeps.append
        )

        assert result is None
        assert len(calls) == 3
        # Slept between attempts, but not a trailing sleep after the last miss.
        assert sleeps == [0.01, 0.01]
