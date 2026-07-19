"""Tests for the ``python -m domestique_app`` splash banner and first-run pull notice.

Everything here is deterministic and offline: services, threads, and the
run-forever loop in ``_launch_portable`` are all mocked.
"""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, Any

import pytest

import domestique_app.main as app_main

if TYPE_CHECKING:
    from collections.abc import Callable


class TestRenderAppBanner:
    def test_contains_logo_status_and_urls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(app_main, "supports_unicode", lambda: True)
        banner = app_main._render_app_banner(9876)
        # greppable status line kept verbatim from the old plain prints
        assert "Domestique API running at http://127.0.0.1:9876" in banner
        assert "Dashboard: http://127.0.0.1:9876/" in banner
        assert "[OSS DASHBOARD]" in banner
        assert "Press Ctrl+C to stop." in banner
        # the figlet logo is included
        assert app_main.LOGO in banner
        assert "►" in banner and "─" in banner

    def test_ascii_fallback_on_dumb_console(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(app_main, "supports_unicode", lambda: False)
        banner = app_main._render_app_banner(9876)
        assert banner.encode("ascii")  # pure ASCII, no exception
        assert "[>]" in banner and "[+]" in banner

    def test_port_is_respected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(app_main, "supports_unicode", lambda: True)
        assert "http://127.0.0.1:1234" in app_main._render_app_banner(1234)


class TestPullNotice:
    def test_known_model_includes_size(self) -> None:
        notice = app_main._pull_notice("qwen3:1.7b")
        assert "qwen3:1.7b" in notice
        assert "~1.4 GB" in notice
        assert "one-time" in notice

    def test_unknown_model_has_generic_size(self) -> None:
        notice = app_main._pull_notice("some-future-model:9b")
        assert "some-future-model:9b" in notice
        assert "a few GB" in notice

    def test_ascii_fallback_is_cp1252_safe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Reviewer finding: the ungated \u25b6 glyph raised UnicodeEncodeError on
        cp1252 consoles when launch() was called without _configure_console_utf8."""
        monkeypatch.setattr(app_main, "supports_unicode", lambda: False)
        notice = app_main._pull_notice("qwen3:1.7b")
        notice.encode("cp1252")  # must not raise
        assert notice.startswith("> Pulling model")

    def test_unicode_console_keeps_glyphs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(app_main, "supports_unicode", lambda: True)
        assert app_main._pull_notice("qwen3:1.7b").startswith("\u25b6 Pulling model")


class TestPortableStartupOrdering:
    def test_banner_prints_before_worker_threads(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The banner must be fully flushed before the Ollama/proxy threads start.

        Otherwise the first-run `ollama pull` progress bar interleaves with —
        and corrupts — the startup output.
        """
        events: list[str] = []

        monkeypatch.setattr(app_main.ConfigStore, "load", classmethod(lambda cls: None))
        server = types.SimpleNamespace(shutdown=lambda: None, server_close=lambda: None)
        monkeypatch.setattr(app_main, "start_api_server", lambda port: server)
        monkeypatch.setattr(app_main.atexit, "register", lambda *a, **k: None)
        monkeypatch.setattr(app_main.signal, "signal", lambda *a, **k: None)
        monkeypatch.setattr(
            app_main, "_ensure_cert_generated_portable", lambda: events.append("cert")
        )
        monkeypatch.setattr(app_main, "_start_system_tray", lambda port: None)
        monkeypatch.setattr(app_main, "_cleanup_services", lambda: None)
        monkeypatch.setattr(app_main.webbrowser, "open", lambda url: events.append("browser-open"))

        class FakeThread:
            def __init__(
                self,
                *,
                target: Callable[..., Any],
                daemon: bool = False,
                args: tuple[Any, ...] = (),
            ) -> None:
                self._label = getattr(target, "__name__", "thread")

            def start(self) -> None:
                events.append(f"thread-start:{self._label}")

        monkeypatch.setattr("threading.Thread", FakeThread)

        def record_print(*args: Any, **kwargs: Any) -> None:
            events.append("print:" + " ".join(str(a) for a in args))

        monkeypatch.setattr("builtins.print", record_print)

        def stop_loop(_seconds: float) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(app_main.time, "sleep", stop_loop)

        with pytest.raises(KeyboardInterrupt):
            app_main._launch_portable(api_port=9876, open_dashboard=True)

        banner_idx = next(i for i, e in enumerate(events) if "Domestique API running at" in e)
        ollama_idx = events.index("thread-start:_ensure_ollama")
        proxies_idx = events.index("thread-start:_auto_start_proxies")
        assert banner_idx < ollama_idx
        assert banner_idx < proxies_idx
        # dashboard still opens, after the banner
        assert events.index("browser-open") > banner_idx
