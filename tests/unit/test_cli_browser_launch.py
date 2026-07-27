"""Tests for the bare `domestique browser` full-auto launcher.

Never imports domestique_app; the dashboard is a stub HTTP server and all
side-effecting calls (install, spawn, open-browser) are mocked.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import domestique.cli as cli


@pytest.fixture()
def stub_dashboard():
    """In-process dashboard-API stub; records (method, path) of every request."""
    requests: list[tuple[str, str]] = []
    responses = {
        ("GET", "/api/browser-proxy"): (
            200,
            {"running": True, "setup_complete": True, "intercepted_domains": ["x.ai"]},
        ),
        ("POST", "/api/browser-proxy/start"): (200, {"ok": True}),
        ("POST", "/api/browser-proxy/stop"): (200, {"ok": True}),
        ("GET", "/api/cert-status"): (200, {"generated": True, "trusted": True, "path": "/x"}),
    }

    class Handler(BaseHTTPRequestHandler):
        def _respond(self, method: str) -> None:
            requests.append((method, self.path))
            status, body = responses.get((method, self.path), (404, {"error": "not found"}))
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            self._respond("GET")

        def do_POST(self):
            self._respond("POST")

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    yield url, requests, responses
    server.shutdown()
    server.server_close()


class TestDetectInstallContext:
    def test_pipx_when_pipx_home_set(self, monkeypatch):
        monkeypatch.setenv("PIPX_HOME", "/Users/x/.local/pipx")
        monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/pipx")
        kind, cmd = cli._detect_install_context()
        assert kind == "pipx"
        assert cmd == ["pipx", "inject", "domestique", "domestique[browser-proxy]"]

    def test_pip_fallback_when_not_pipx(self, monkeypatch):
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setattr(cli.sys, "prefix", "/opt/venv")
        kind, cmd = cli._detect_install_context()
        assert kind == "pip"
        assert cmd == [sys.executable, "-m", "pip", "install", "domestique[browser-proxy]"]

    def test_pipx_windows_style_prefix(self, monkeypatch):
        # sys.prefix uses backslashes on Windows; the pipx-venv marker must
        # still be recognised (regression: forward-slash literal never matched).
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setattr(
            cli.sys, "prefix", r"C:\Users\x\AppData\Local\pipx\venvs\domestique"
        )
        monkeypatch.setattr(cli.shutil, "which", lambda name: r"C:\pipx.exe")
        kind, cmd = cli._detect_install_context()
        assert kind == "pipx"
        assert cmd == ["pipx", "inject", "domestique", "domestique[browser-proxy]"]

    def test_pipx_via_metadata_marker_custom_home(self, monkeypatch, tmp_path):
        # Custom PIPX_HOME (dir not literally named "pipx") — the substring check
        # misses it on every OS, but pipx_metadata.json at the venv root is
        # definitive.
        (tmp_path / "pipx_metadata.json").write_text("{}")
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setattr(cli.sys, "prefix", str(tmp_path))
        monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/pipx")
        assert cli._detect_install_context()[0] == "pipx"

    def test_linux_pipx_prefix_still_detected(self, monkeypatch):
        # Regression guard: posix pipx layout keeps working.
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setattr(
            cli.sys, "prefix", "/home/u/.local/share/pipx/venvs/domestique"
        )
        monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/pipx")
        assert cli._detect_install_context()[0] == "pipx"

    def test_pip_when_pipx_binary_absent(self, monkeypatch):
        # Detected as under-pipx but the pipx CLI isn't on PATH -> safe pip fallback.
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setattr(cli.sys, "prefix", r"C:\Users\x\pipx\venvs\domestique")
        monkeypatch.setattr(cli.shutil, "which", lambda name: None)
        kind, cmd = cli._detect_install_context()
        assert kind == "pip"
        assert cmd == [sys.executable, "-m", "pip", "install", "domestique[browser-proxy]"]


class TestEnsureBrowserDependency:
    def test_present_returns_true_no_install(self, monkeypatch):
        monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: object())
        called = []
        monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: called.append(a))
        assert cli._ensure_browser_dependency(assume_yes=True, no_install=False) is True
        assert called == []

    def test_missing_no_install_prints_hint(self, monkeypatch, capsys):
        monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
        monkeypatch.setattr(cli, "_detect_install_context", lambda: ("pipx", ["pipx", "inject"]))
        assert cli._ensure_browser_dependency(assume_yes=True, no_install=True) is False
        assert "pipx inject" in capsys.readouterr().out

    def test_hint_matches_actual_install_method_not_hardcoded_pipx(self, monkeypatch, capsys):
        # Regression: _print_mitmproxy_hint used to always say "pipx inject",
        # even for a plain pip/venv install where that command may not even
        # have pipx on PATH. It must reflect _detect_install_context()'s real
        # answer instead.
        monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
        monkeypatch.setattr(
            cli, "_detect_install_context", lambda: ("pip", [cli.sys.executable, "-m", "pip"])
        )
        assert cli._ensure_browser_dependency(assume_yes=True, no_install=True) is False
        out = capsys.readouterr().out
        assert "pip" in out
        assert "pipx" not in out

    def test_missing_yes_installs_and_succeeds(self, monkeypatch):
        monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
        monkeypatch.setattr(cli, "_detect_install_context", lambda: ("pip", ["x"]))
        monkeypatch.setattr(
            cli.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0})()
        )
        assert cli._ensure_browser_dependency(assume_yes=True, no_install=False) is True

    def test_missing_install_fails_returns_false(self, monkeypatch, capsys):
        monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
        monkeypatch.setattr(cli, "_detect_install_context", lambda: ("pipx", ["pipx", "inject"]))
        monkeypatch.setattr(
            cli.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 1})()
        )
        assert cli._ensure_browser_dependency(assume_yes=True, no_install=False) is False
        assert "pipx inject" in capsys.readouterr().out

    def test_interactive_tty_decline_prints_hint_and_returns_false(self, monkeypatch, capsys):
        monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
        monkeypatch.setattr(cli, "_detect_install_context", lambda: ("pip", ["x"]))
        monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(cli, "input", lambda prompt: "n", raising=False)
        called = []
        monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: called.append(a))

        assert cli._ensure_browser_dependency(assume_yes=False, no_install=False) is False
        assert called == []  # declining must never invoke the installer
        assert "isn't installed" in capsys.readouterr().out

    def test_interactive_tty_accept_proceeds_to_install(self, monkeypatch):
        monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
        monkeypatch.setattr(cli, "_detect_install_context", lambda: ("pip", ["x"]))
        monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(cli, "input", lambda prompt: "y", raising=False)
        monkeypatch.setattr(
            cli.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0})()
        )

        assert cli._ensure_browser_dependency(assume_yes=False, no_install=False) is True

    def test_non_tty_without_yes_or_no_install_proceeds_to_install(self, monkeypatch):
        # Documents the current, deliberate behavior: when stdin isn't a TTY
        # (piped/non-interactive) and the caller passed neither --yes nor
        # --no-install, there's no way to prompt, so the launcher proceeds to
        # install rather than hanging or silently doing nothing. Locking this
        # in as a test rather than leaving it as an unverified side effect.
        monkeypatch.setattr(cli.importlib.util, "find_spec", lambda name: None)
        monkeypatch.setattr(cli, "_detect_install_context", lambda: ("pip", ["x"]))
        monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
        called = []
        monkeypatch.setattr(
            cli.subprocess,
            "run",
            lambda *a, **k: (called.append(a), type("R", (), {"returncode": 0})())[1],
        )

        assert cli._ensure_browser_dependency(assume_yes=False, no_install=False) is True
        assert len(called) == 1


class TestDashboardHelpers:
    def test_call_returns_json(self, stub_dashboard):
        url, _requests, _resp = stub_dashboard
        assert cli._dashboard_call(url, "/api/browser-proxy") == {
            "running": True,
            "setup_complete": True,
            "intercepted_domains": ["x.ai"],
        }

    def test_call_returns_none_when_unreachable(self):
        # Nothing is listening on this port.
        assert cli._dashboard_call("http://127.0.0.1:9", "/api/browser-proxy", timeout=0.2) is None

    def test_call_returns_json_body_on_error_status(self, stub_dashboard):
        url, _requests, _resp = stub_dashboard
        assert cli._dashboard_call(url, "/api/does-not-exist") == {"error": "not found"}

    def test_call_returns_none_for_malformed_url(self):
        assert cli._dashboard_call("notaurl", "/x") is None

    def test_reachable_true_against_stub(self, stub_dashboard):
        url, _requests, _resp = stub_dashboard
        assert cli._dashboard_reachable(url) is True

    def test_reachable_false_when_down(self):
        assert cli._dashboard_reachable("http://127.0.0.1:9") is False

    def test_wait_returns_true_immediately_when_reachable(self, monkeypatch):
        monkeypatch.setattr(cli, "_dashboard_reachable", lambda url: True)
        assert cli._wait_for_dashboard("http://x", timeout=1.0) is True

    def test_wait_times_out_when_never_ready(self, monkeypatch):
        monkeypatch.setattr(cli, "_dashboard_reachable", lambda url: False)
        assert cli._wait_for_dashboard("http://x", timeout=0.2, interval=0.05) is False


class TestAppLifecycle:
    def test_spawn_uses_portable_no_browser(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            cli.subprocess, "Popen", lambda argv, **k: captured.update(argv=argv, kw=k)
        )
        cli._spawn_dashboard_app()
        assert captured["argv"] == [
            sys.executable,
            "-m",
            "domestique_app",
            "--mode",
            "portable",
            "--no-browser",
        ]
        # Detachment kwarg is platform-specific: start_new_session (POSIX
        # setsid) is a documented no-op on Windows, so it must not be relied
        # on there -- CREATE_NEW_PROCESS_GROUP is the real mechanism.
        if os.name == "nt":
            assert captured["kw"].get("creationflags") == cli.subprocess.CREATE_NEW_PROCESS_GROUP
            assert "start_new_session" not in captured["kw"]
        else:
            assert captured["kw"].get("start_new_session") is True
            assert "creationflags" not in captured["kw"]

    def test_ensure_running_skips_spawn_when_already_up(self, monkeypatch):
        monkeypatch.setattr(cli, "_dashboard_reachable", lambda url: True)
        spawned = []
        monkeypatch.setattr(cli, "_spawn_dashboard_app", lambda: spawned.append(True))
        assert cli._ensure_app_running("http://x") is True
        assert spawned == []

    def test_ensure_running_spawns_then_waits(self, monkeypatch):
        monkeypatch.setattr(cli, "_dashboard_reachable", lambda url: False)
        spawned = []
        monkeypatch.setattr(cli, "_spawn_dashboard_app", lambda: spawned.append(True))
        monkeypatch.setattr(cli, "_wait_for_dashboard", lambda url, timeout=30.0: True)
        assert cli._ensure_app_running("http://x") is True
        assert spawned == [True]

    def test_ensure_running_returns_false_when_never_ready(self, monkeypatch):
        monkeypatch.setattr(cli, "_dashboard_reachable", lambda url: False)
        monkeypatch.setattr(cli, "_spawn_dashboard_app", lambda: None)
        monkeypatch.setattr(cli, "_wait_for_dashboard", lambda url, timeout=30.0: False)
        assert cli._ensure_app_running("http://x") is False


class TestTurnOnAndCert:
    def test_post_browser_start_hits_endpoint(self, stub_dashboard):
        url, requests, _resp = stub_dashboard
        assert cli._post_browser_start(url) == {"ok": True}
        assert ("POST", "/api/browser-proxy/start") in requests

    def test_cert_warning_when_untrusted(self, monkeypatch, capsys):
        monkeypatch.setattr(
            cli, "_dashboard_call", lambda url, path, **k: {"generated": True, "trusted": False}
        )
        cli._warn_if_cert_untrusted("http://x")
        assert "isn't trusted yet" in capsys.readouterr().out

    def test_cert_no_warning_when_trusted(self, monkeypatch, capsys):
        monkeypatch.setattr(
            cli, "_dashboard_call", lambda url, path, **k: {"generated": True, "trusted": True}
        )
        cli._warn_if_cert_untrusted("http://x")
        assert capsys.readouterr().out == ""

    def test_cert_no_warning_when_status_unavailable(self, monkeypatch, capsys):
        monkeypatch.setattr(cli, "_dashboard_call", lambda url, path, **k: None)
        cli._warn_if_cert_untrusted("http://x")
        assert capsys.readouterr().out == ""


class TestOrchestrator:
    def _all_ok(self, monkeypatch, opened):
        monkeypatch.setattr(cli, "_ensure_browser_dependency", lambda **k: True)
        monkeypatch.setattr(cli, "_ensure_app_running", lambda url, **k: True)
        monkeypatch.setattr(cli, "_post_browser_start", lambda url: {"ok": True})
        monkeypatch.setattr(cli, "_warn_if_cert_untrusted", lambda url: None)
        monkeypatch.setattr(cli.webbrowser, "open", lambda u: opened.append(u))

    def test_happy_path_opens_dashboard_returns_0(self, monkeypatch, capsys):
        opened = []
        self._all_ok(monkeypatch, opened)
        rc = cli._cmd_browser_launch(
            "http://x", assume_yes=True, no_install=False, open_dashboard=True
        )
        assert rc == 0
        assert opened == ["http://x"]
        assert "protected" in capsys.readouterr().out.lower()

    def test_no_open_skips_browser(self, monkeypatch):
        opened = []
        self._all_ok(monkeypatch, opened)
        rc = cli._cmd_browser_launch(
            "http://x", assume_yes=True, no_install=False, open_dashboard=False
        )
        assert rc == 0
        assert opened == []

    def test_dependency_missing_returns_1_before_anything(self, monkeypatch):
        monkeypatch.setattr(cli, "_ensure_browser_dependency", lambda **k: False)
        spawned = []
        monkeypatch.setattr(cli, "_ensure_app_running", lambda url, **k: spawned.append(1) or True)
        rc = cli._cmd_browser_launch(
            "http://x", assume_yes=True, no_install=True, open_dashboard=True
        )
        assert rc == 1
        assert spawned == []

    def test_app_never_up_returns_1(self, monkeypatch, capsys):
        monkeypatch.setattr(cli, "_ensure_browser_dependency", lambda **k: True)
        monkeypatch.setattr(cli, "_ensure_app_running", lambda url, **k: False)
        rc = cli._cmd_browser_launch(
            "http://x", assume_yes=True, no_install=False, open_dashboard=True
        )
        assert rc == 1
        assert "didn't come up" in capsys.readouterr().out

    def test_turn_on_error_surfaces_detail_returns_1(self, monkeypatch, capsys):
        monkeypatch.setattr(cli, "_ensure_browser_dependency", lambda **k: True)
        monkeypatch.setattr(cli, "_ensure_app_running", lambda url, **k: True)
        monkeypatch.setattr(cli, "_post_browser_start", lambda url: {"error": "port in use"})
        rc = cli._cmd_browser_launch(
            "http://x", assume_yes=True, no_install=False, open_dashboard=True
        )
        assert rc == 1
        assert "port in use" in capsys.readouterr().out

    def test_already_on_reports_already_protected(self, monkeypatch, capsys):
        opened = []
        self._all_ok(monkeypatch, opened)
        monkeypatch.setattr(
            cli, "_post_browser_start", lambda url: {"ok": True, "already_running": True}
        )
        rc = cli._cmd_browser_launch(
            "http://x", assume_yes=True, no_install=False, open_dashboard=True
        )
        assert rc == 0
        assert "already" in capsys.readouterr().out.lower()


class TestCliWiring:
    def test_bare_browser_invokes_launcher(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(
            cli,
            "_cmd_browser_launch",
            lambda url, **k: seen.update(url=url, **k) or 0,
        )
        assert cli.main(["browser", "--url", "http://y", "--yes", "--no-open"]) == 0
        assert seen == {
            "url": "http://y",
            "assume_yes": True,
            "no_install": False,
            "open_dashboard": False,
        }

    def test_no_install_flag_passed_through(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(cli, "_cmd_browser_launch", lambda url, **k: seen.update(k) or 0)
        assert cli.main(["browser", "--no-install"]) == 0
        assert seen["no_install"] is True
        assert seen["open_dashboard"] is True

    def test_browser_on_still_routes_to_cmd_browser(self, monkeypatch):
        called = {}
        monkeypatch.setattr(
            cli, "_cmd_browser", lambda action, url: called.update(action=action) or 0
        )
        monkeypatch.setattr(cli, "_cmd_browser_launch", lambda *a, **k: pytest.fail("wrong path"))
        assert cli.main(["browser", "on", "--url", "http://y"]) == 0
        assert called == {"action": "on"}


class TestBannerHint:
    def test_start_banner_mentions_browser_command(self):
        out = cli._banner("127.0.0.1", 8000)
        assert "domestique browser" in out
