"""Installing Ollama does not start it — the wizard must handle that.

`brew install ollama` leaves the daemon stopped (Homebrew says so in its own
caveats). The wizard went straight to `ollama pull` and died with

    Error: could not connect to ollama server, run 'ollama serve' to start it

killing the whole run *after* the user had already sat through the extras and
a 1.9 GB model download.
"""

from __future__ import annotations

import pytest

from domestique import setup_wizard as sw


class TestEnsureOllamaRunning:
    def test_no_op_when_already_reachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sw, "ollama_server_reachable", lambda timeout=2.0: True)

        def _boom(*a: object, **k: object) -> object:
            raise AssertionError("tried to start a daemon that was already up")

        monkeypatch.setattr(sw.subprocess, "run", _boom)
        monkeypatch.setattr(sw.subprocess, "Popen", _boom)
        assert sw.ensure_ollama_running() is True

    def test_returns_false_when_it_never_comes_up(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sw, "ollama_server_reachable", lambda timeout=2.0: False)
        monkeypatch.setattr(sw.shutil, "which", lambda _n: None)
        monkeypatch.setattr(sw.time, "sleep", lambda _s: None)
        # Bounded: must not spin forever waiting for a daemon that never starts.
        assert sw.ensure_ollama_running(wait_s=0.01) is False

    def test_probe_never_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import urllib.request

        def _explode(*a: object, **k: object) -> object:
            raise OSError("network is down")

        monkeypatch.setattr(urllib.request, "urlopen", _explode)
        assert sw.ollama_server_reachable() is False


class TestPullDoesNotKillTheWizard:
    def test_unreachable_daemon_warns_instead_of_exiting(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(sw, "ensure_ollama_running", lambda **_k: False)

        def _must_not_run(*a: object, **k: object) -> object:
            raise AssertionError("attempted `ollama pull` with no daemon")

        monkeypatch.setattr(sw, "run", _must_not_run)
        sw.pull_ollama_model("qwen3:1.7b", set())  # must not raise SystemExit
        out = capsys.readouterr().out
        assert "ollama serve" in out, "the message must say how to fix it"
        assert "qwen3:1.7b" in out
        assert "regex and GLiNER are unaffected" in out

    def test_pull_failure_is_not_fatal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A failed download must not throw away the extras already installed."""
        monkeypatch.setattr(sw, "ensure_ollama_running", lambda **_k: True)
        calls: list[dict[str, object]] = []
        monkeypatch.setattr(sw, "run", lambda cmd, **kw: calls.append(kw) or 1)
        sw.pull_ollama_model("qwen3:1.7b", set())
        assert calls and calls[0].get("check") is False, calls


class TestDownloadSizesAreHonest:
    def test_gliner_size_reflects_the_real_download(self) -> None:
        """A clean install pulls 1.87 GB of weights; the wizard said ~300 MB."""
        assert sw.FEATURE_EXTRAS["ner"]["extra_download_mb"] >= 1500

    @pytest.mark.parametrize(
        ("mb", "expected"), [(20, "~20 MB"), (300, "~300 MB"), (1900, "~1.9 GB")]
    )
    def test_multi_gb_downloads_render_as_gb(self, mb: int, expected: str) -> None:
        assert sw._fmt_download(mb) == expected
