"""Tests for SIEM integration backends and dispatcher."""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock

import pytest

from domestique_app.services.audit import AuditAction, create_audit_event
from domestique_app.services.siem import (
    CEFBackend,
    FileBackend,
    SIEMDispatcher,
    SyslogBackend,
    WebhookBackend,
)


@pytest.fixture
def sample_event():
    return create_audit_event(
        action=AuditAction.BLOCK,
        destination="api.openai.com",
        method="POST",
        path="/v1/chat/completions",
        detectors=["SSN"],
        categories=["SSN"],
        latency_ms=2.5,
        content_length=100,
        content_preview="My SSN is 123-45-6789",
    )


class TestSyslogBackend:
    """Test RFC 5424 syslog output."""

    def test_format_contains_required_fields(self, sample_event):
        backend = SyslogBackend(host="127.0.0.1", port=9999)
        msg = backend._format_rfc5424(sample_event)

        assert "domestique" in msg
        assert "api.openai.com" in msg
        assert "block" in msg
        assert "SSN" in msg
        assert sample_event.request_id in msg

    def test_severity_mapping(self, sample_event):
        backend = SyslogBackend()
        msg = backend._format_rfc5424(sample_event)
        # Critical events get priority = facility*8 + severity = 16*8 + 2 = 130
        assert msg.startswith("<130>")

    def test_send_to_udp(self, sample_event):
        """Test actual UDP send to a local socket."""
        # Create a UDP listener
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.settimeout(2)

        backend = SyslogBackend(host="127.0.0.1", port=port, protocol="udp")
        assert backend.send(sample_event)

        data, _ = sock.recvfrom(4096)
        msg = data.decode("utf-8")
        assert "api.openai.com" in msg
        assert "block" in msg

        sock.close()
        backend.close()


class TestCEFBackend:
    """Test Common Event Format output."""

    def test_format_follows_cef_spec(self, sample_event):
        backend = CEFBackend()
        msg = backend._format_cef(sample_event)

        # CEF header format: CEF:version|vendor|product|version|id|name|severity|
        assert msg.startswith("CEF:0|Domestique|Firewall|1.0|")
        assert "block" in msg
        assert "Sensitive Data Blocked" in msg

    def test_extensions_present(self, sample_event):
        backend = CEFBackend()
        msg = backend._format_cef(sample_event)

        assert "dst=api.openai.com" in msg
        assert "requestMethod=POST" in msg
        assert "externalId=" in msg

    def test_severity_mapping(self, sample_event):
        backend = CEFBackend()
        msg = backend._format_cef(sample_event)
        # Critical -> severity 9
        assert "|9|" in msg


class TestWebhookBackend:
    """Test HTTP webhook output."""

    def test_send_posts_json(self, sample_event):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                body = self.rfile.read(length)
                received.append(json.loads(body))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass  # Suppress output

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        backend = WebhookBackend(url=f"http://127.0.0.1:{port}/events")
        assert backend.send(sample_event)
        thread.join(timeout=3)
        server.server_close()

        assert len(received) == 1
        assert received[0]["destination"] == "api.openai.com"
        assert received[0]["action"] == "block"

    def test_custom_headers_sent(self, sample_event):
        received_headers = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received_headers.update(dict(self.headers))
                self.send_response(200)
                self.end_headers()
                self.rfile.read(int(self.headers["Content-Length"]))

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        backend = WebhookBackend(
            url=f"http://127.0.0.1:{port}/events",
            headers={"X-API-Key": "secret123"},
        )
        backend.send(sample_event)
        thread.join(timeout=3)
        server.server_close()

        assert received_headers.get("X-Api-Key") == "secret123"

    def test_send_failure_returns_false(self, sample_event):
        backend = WebhookBackend(url="http://127.0.0.1:1/nonexistent", timeout=1)
        assert not backend.send(sample_event)


class TestFileBackend:
    """Test JSONL file output."""

    def test_writes_jsonl(self, sample_event, tmp_path):
        out = tmp_path / "events.jsonl"
        backend = FileBackend(path=out)
        assert backend.send(sample_event)
        backend.close()

        lines = out.read_text().strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["destination"] == "api.openai.com"

    def test_multiple_events_appended(self, tmp_path):
        out = tmp_path / "events.jsonl"
        backend = FileBackend(path=out)

        for i in range(5):
            event = create_audit_event(action=AuditAction.ALLOW, destination=f"host{i}.com")
            backend.send(event)

        backend.close()
        lines = out.read_text().strip().split("\n")
        assert len(lines) == 5


class TestSIEMDispatcher:
    """Test the SIEM event dispatcher."""

    def test_dispatch_to_multiple_backends(self, sample_event):
        backend1 = MagicMock()
        backend1.name = "mock1"
        backend1.send_batch.return_value = 1
        backend2 = MagicMock()
        backend2.name = "mock2"
        backend2.send_batch.return_value = 1

        dispatcher = SIEMDispatcher()
        dispatcher.FLUSH_INTERVAL = 0.1
        dispatcher.add_backend(backend1)
        dispatcher.add_backend(backend2)
        dispatcher.start()

        dispatcher.dispatch(sample_event)
        time.sleep(0.5)
        dispatcher.stop()

        backend1.send_batch.assert_called()
        backend2.send_batch.assert_called()

    def test_backend_failure_doesnt_crash(self, sample_event):
        backend = MagicMock()
        backend.name = "failing"
        backend.send_batch.side_effect = Exception("SIEM down")

        dispatcher = SIEMDispatcher()
        dispatcher.FLUSH_INTERVAL = 0.1
        dispatcher.add_backend(backend)
        dispatcher.start()

        dispatcher.dispatch(sample_event)
        time.sleep(0.3)
        dispatcher.stop()
        # No exception raised

    def test_stats_tracking(self, sample_event):
        backend = MagicMock()
        backend.name = "counter"
        backend.send_batch.return_value = 3

        dispatcher = SIEMDispatcher()
        dispatcher.FLUSH_INTERVAL = 0.1
        dispatcher.add_backend(backend)
        dispatcher.start()

        for _ in range(3):
            dispatcher.dispatch(sample_event)
        time.sleep(0.5)
        dispatcher.stop()

        assert dispatcher.stats["dispatched"] >= 3

    def test_backends_property(self):
        dispatcher = SIEMDispatcher()
        backend = MagicMock()
        backend.name = "test-backend"
        dispatcher.add_backend(backend)
        assert "test-backend" in dispatcher.backends

    def test_remove_backend(self):
        dispatcher = SIEMDispatcher()
        backend = MagicMock()
        backend.name = "removable"
        dispatcher.add_backend(backend)
        dispatcher.remove_backend("removable")
        assert "removable" not in dispatcher.backends
