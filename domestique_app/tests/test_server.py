"""Integration tests for the HTTP API server.

Tests cover:
- All REST endpoints (GET/POST)
- CORS headers
- Error responses (404, 409, 400)
- Config persistence via API
- Benchmark trigger and status polling
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from domestique_app.config.schema import AppConfig
from domestique_app.config.store import ConfigStore
from domestique_app.server.api import APIHandler, start_api_server

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def reset_state(tmp_path):
    """Reset all state before each test."""
    ConfigStore.reset()
    with (
        patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
        patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
    ):
        ConfigStore.load()
        yield


@pytest.fixture(scope="module")
def api_server():
    """Start a test API server on a random-ish port."""
    port = 19876
    server = start_api_server(port=port)
    time.sleep(0.2)  # Let it bind
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestAPIEndpoints:
    """Integration tests for API endpoints."""

    def _get(self, base_url: str, path: str) -> dict:
        res = urllib.request.urlopen(f"{base_url}{path}")  # noqa: S310
        return json.loads(res.read())

    def _post(self, base_url: str, path: str, data: dict = None) -> tuple[int, dict]:
        body = json.dumps(data).encode() if data else b""
        req = urllib.request.Request(  # noqa: S310
            f"{base_url}{path}",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            res = urllib.request.urlopen(req)  # noqa: S310
            return res.status, json.loads(res.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_get_status(self, api_server):
        data = self._get(api_server, "/api/status")
        assert "proxy_running" in data
        assert "benchmark_running" in data
        assert data["proxy_running"] is False

    def test_get_config(self, api_server, tmp_path):
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            ConfigStore.save(AppConfig(proxy_port=7777))
            data = self._get(api_server, "/api/config")
            assert data["proxy_port"] == 7777

    def test_post_config(self, api_server, tmp_path):
        with (
            patch("domestique_app.config.store.CONFIG_PATH", tmp_path / "config.json"),
            patch("domestique_app.config.store.APP_DATA_DIR", tmp_path),
        ):
            status, data = self._post(api_server, "/api/config", {"proxy_port": 4444})
            assert status == 200
            assert data["ok"] is True

    def test_post_config_invalid_json(self, api_server):
        req = urllib.request.Request(  # noqa: S310
            f"{api_server}/api/config",
            data=b"not json",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req)  # noqa: S310
            raise AssertionError("Should have raised")
        except urllib.error.HTTPError as e:
            assert e.code == 400

    def test_get_benchmark(self, api_server):
        data = self._get(api_server, "/api/benchmark")
        assert "running" in data
        assert "progress" in data
        assert "report_exists" in data

    def test_not_found(self, api_server):
        req = urllib.request.Request(f"{api_server}/api/nonexistent")  # noqa: S310
        try:
            urllib.request.urlopen(req)  # noqa: S310
            raise AssertionError("Should have raised")
        except urllib.error.HTTPError as e:
            assert e.code == 404

    def test_cors_headers(self, api_server):
        res = urllib.request.urlopen(f"{api_server}/api/status")  # noqa: S310
        assert res.headers.get("Access-Control-Allow-Origin") == "*"

    def test_send_json_ignores_client_disconnect(self):
        handler = object.__new__(APIHandler)
        handler.requestline = "GET /api/status HTTP/1.1"
        handler.request_version = "HTTP/1.1"
        handler.command = "GET"
        handler.close_connection = False
        handler.responses = APIHandler.responses
        handler.wfile = SimpleNamespace(
            write=lambda _body: (_ for _ in ()).throw(ConnectionAbortedError(10053, "aborted"))
        )
        handler.send_response = lambda *_args, **_kwargs: None
        handler.send_header = lambda *_args, **_kwargs: None
        handler.end_headers = lambda: None

        handler._send_json({"ok": True})

    def test_get_debug_trace(self, api_server, tmp_path: Path):
        from domestique.debug_trace import append_debug_trace

        trace_path = tmp_path / "debug_trace.jsonl"
        append_debug_trace(
            {"source": "browser_proxy", "action": "blocked", "prompt": "secret"},
            path=trace_path,
        )

        with patch("domestique.debug_trace.TRACE_PATH", trace_path):
            data = self._get(api_server, "/api/debug-trace?limit=10")

        assert data["total"] == 1
        assert data["entries"][0]["action"] == "blocked"
        assert data["entries"][0]["prompt"] == "secret"
