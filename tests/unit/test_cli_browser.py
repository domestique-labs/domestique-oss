"""Tests for `domestique browser on|off|status`.

Runs against a stub HTTP server standing in for the dashboard API -- the
real domestique_app/ package is never imported (architecture rule) and no real
services are started. Verifies the subcommand only ever touches the
browser-proxy endpoints (never the API-proxy /api/firewall/* state).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from domestique.cli import main


@pytest.fixture()
def stub_dashboard():
    """A dashboard-API stub recording every request path."""
    requests: list[tuple[str, str]] = []
    responses = {
        ("POST", "/api/browser-proxy/start"): (200, {"ok": True}),
        ("POST", "/api/browser-proxy/stop"): (200, {"ok": True}),
        (
            "GET",
            "/api/browser-proxy",
        ): (200, {"running": True, "setup_complete": True, "intercepted_domains": ["x.ai"]}),
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

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    yield url, requests, responses
    server.shutdown()
    server.server_close()


class TestBrowserSubcommand:
    def test_on_hits_only_browser_start(self, stub_dashboard, capsys):
        url, requests, _ = stub_dashboard
        assert main(["browser", "on", "--url", url]) == 0
        assert requests == [("POST", "/api/browser-proxy/start")]
        assert "turned on" in capsys.readouterr().out

    def test_off_hits_only_browser_stop(self, stub_dashboard, capsys):
        url, requests, _ = stub_dashboard
        assert main(["browser", "off", "--url", url]) == 0
        assert requests == [("POST", "/api/browser-proxy/stop")]
        assert "turned off" in capsys.readouterr().out

    def test_status_reports_running(self, stub_dashboard, capsys):
        url, requests, _ = stub_dashboard
        assert main(["browser", "status", "--url", url]) == 0
        assert requests == [("GET", "/api/browser-proxy")]
        out = capsys.readouterr().out
        assert "browser protection: on" in out

    def test_never_touches_api_proxy_endpoints(self, stub_dashboard):
        """Browser toggling is independent of the API proxy (proxy_enabled)."""
        url, requests, _ = stub_dashboard
        main(["browser", "on", "--url", url])
        main(["browser", "off", "--url", url])
        main(["browser", "status", "--url", url])
        assert all("/api/browser-proxy" in path for _, path in requests)
        assert not any("firewall" in path or path == "/api/config" for _, path in requests)

    def test_already_running_is_reported(self, stub_dashboard, capsys):
        url, _, responses = stub_dashboard
        responses[("POST", "/api/browser-proxy/start")] = (
            200,
            {"ok": True, "already_running": True},
        )
        assert main(["browser", "on", "--url", url]) == 0
        assert "already on" in capsys.readouterr().out

    def test_api_error_is_surfaced(self, stub_dashboard, capsys):
        url, _, responses = stub_dashboard
        responses[("POST", "/api/browser-proxy/start")] = (500, {"error": "mitmdump not found"})
        assert main(["browser", "on", "--url", url]) == 1
        out = capsys.readouterr().out
        assert "500" in out
        assert "mitmdump not found" in out


class TestBrowserUnreachable:
    UNREACHABLE = "http://127.0.0.1:9"  # discard port; nothing listens there

    def test_install_hint_when_app_not_installed(self, monkeypatch, capsys):
        monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
        assert main(["browser", "status", "--url", self.UNREACHABLE]) == 1
        out = capsys.readouterr().out
        assert "pipx inject domestique" in out
        assert "browser-proxy" in out

    def test_start_hint_when_app_installed_but_down(self, monkeypatch, capsys):
        monkeypatch.setattr("importlib.util.find_spec", lambda name: object())
        assert main(["browser", "on", "--url", self.UNREACHABLE]) == 1
        assert "python -m domestique_app" in capsys.readouterr().out
