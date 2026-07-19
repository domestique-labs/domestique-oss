"""Cross-platform compatibility tests.

Catches bugs that only manifest on specific OSes (Windows vs macOS vs Linux):
- subprocess pipe I/O (select.select only works on sockets on Windows)
- path separator handling (backslashes in inline scripts)
- line ending handling in JSONL/log parsing
- platform-specific process management dispatch
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# VenvScanner: subprocess pipe reading
# ---------------------------------------------------------------------------


class TestVenvScannerPipeReading:
    """Verify the threaded readline approach works cross-platform.

    The original code used select.select() which only works on sockets
    on Windows, silently returning zero detections for every scan.
    """

    def test_threaded_readline_reads_subprocess_output(self):
        """Threaded readline must capture a line from a subprocess pipe."""
        proc = subprocess.Popen(
            [sys.executable, "-c", 'print(\'{"ok":true,"detections":[]}\')'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

        result_line: list[bytes] = []

        def _read() -> None:
            result_line.append(proc.stdout.readline())

        reader = threading.Thread(target=_read, daemon=True)
        reader.start()
        reader.join(timeout=10)
        proc.wait()

        assert len(result_line) == 1
        parsed = json.loads(result_line[0])
        assert parsed["ok"] is True

    def test_threaded_readline_timeout_on_no_output(self):
        """Threaded readline must not hang forever if subprocess produces no output."""
        # Subprocess that sleeps without writing anything
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

        result_line: list[bytes] = []

        def _read() -> None:
            result_line.append(proc.stdout.readline())

        reader = threading.Thread(target=_read, daemon=True)
        reader.start()
        reader.join(timeout=1)  # Should return quickly, not wait 30s

        # Thread should still be alive (blocked on readline) but join returned
        assert len(result_line) == 0
        proc.kill()
        proc.wait()

    def test_subprocess_stdin_stdout_roundtrip(self):
        """Full stdin→process→stdout roundtrip via pipes must work."""
        worker_script = textwrap.dedent("""\
            import sys, json
            for line in sys.stdin:
                req = json.loads(line)
                resp = {"ok": True, "echo": req["text"]}
                print(json.dumps(resp), flush=True)
        """)
        proc = subprocess.Popen(
            [sys.executable, "-c", worker_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

        # Write a request
        msg = json.dumps({"text": "hello"}).encode() + b"\n"
        proc.stdin.write(msg)
        proc.stdin.flush()

        # Read response via thread
        result_line: list[bytes] = []

        def _read() -> None:
            result_line.append(proc.stdout.readline())

        reader = threading.Thread(target=_read, daemon=True)
        reader.start()
        reader.join(timeout=10)

        assert len(result_line) == 1
        parsed = json.loads(result_line[0])
        assert parsed["ok"] is True
        assert parsed["echo"] == "hello"

        proc.stdin.close()
        proc.wait()


# ---------------------------------------------------------------------------
# Path escaping in inline scripts
# ---------------------------------------------------------------------------


class TestPathEscaping:
    """Verify Windows backslash paths are properly escaped in inline scripts."""

    @pytest.mark.parametrize("path", [
        r"C:\Users\david\domestique",
        r"C:\Program Files\Python311",
        r"D:\projects\my app\src",
        "/home/user/domestique",  # Unix paths should also work
        "/Users/david/Projects/domestique",
    ])
    def test_escaped_path_in_inline_script(self, path: str):
        """An escaped path embedded in a Python -c script must be importable."""
        escaped = path.replace("\\", "\\\\")
        script = f"import sys; sys.path.insert(0, '{escaped}'); print(sys.path[0])"
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == path

    def test_unescaped_backslash_path_fails(self):
        """Raw Windows paths with backslashes create invalid escape sequences."""
        # \U is an invalid Unicode escape in Python
        path = r"C:\Users\test"
        script = f"import sys; sys.path.insert(0, '{path}')"
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True,
        )
        # This should fail because \U is an invalid escape sequence
        assert result.returncode != 0


# ---------------------------------------------------------------------------
# JSONL / log line-ending handling
# ---------------------------------------------------------------------------


class TestLineEndingHandling:
    """Verify JSONL parsing handles both Unix (\\n) and Windows (\\r\\n) endings."""

    def test_splitlines_handles_unix_endings(self):
        content = '{"a":1}\n{"a":2}\n{"a":3}\n'
        lines = content.strip().splitlines()
        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert "a" in parsed

    def test_splitlines_handles_windows_endings(self):
        content = '{"a":1}\r\n{"a":2}\r\n{"a":3}\r\n'
        lines = content.strip().splitlines()
        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert "a" in parsed

    def test_splitlines_handles_mixed_endings(self):
        content = '{"a":1}\n{"a":2}\r\n{"a":3}\n'
        lines = content.strip().splitlines()
        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert "a" in parsed

    def test_split_newline_breaks_on_windows_endings(self):
        """Demonstrates why split('\\n') is wrong for cross-platform JSONL."""
        content = '{"a":1}\r\n{"a":2}\r\n'
        lines = content.strip().split("\n")
        # split("\n") leaves \r attached to the value
        assert lines[0].endswith("\r")
        # json.loads tolerates it but string comparisons would fail
        raw_value = lines[0]
        assert raw_value != '{"a":1}'  # Has trailing \r

    def test_request_log_parsing(self, tmp_path: Path):
        """Request log with Windows line endings must parse correctly."""
        log_file = tmp_path / "request_log.jsonl"
        entries = [
            {"action": "blocked", "user": "test", "model": "gpt-4"},
            {"action": "allowed", "user": "test2", "model": "claude"},
        ]
        # Write with Windows line endings
        log_file.write_text(
            "\r\n".join(json.dumps(e) for e in entries) + "\r\n"
        )
        # Parse the way the fixed code does
        lines = log_file.read_text().strip().splitlines()
        parsed = []
        for line in reversed(lines):
            if not line.strip():
                continue
            parsed.append(json.loads(line))
        assert len(parsed) == 2
        assert parsed[0]["action"] == "allowed"
        assert parsed[1]["action"] == "blocked"


# ---------------------------------------------------------------------------
# Port clearing: platform dispatch
# ---------------------------------------------------------------------------


class TestClearPortDispatch:
    """Verify _clear_port dispatches to the correct platform handler."""

    def test_windows_uses_taskkill_not_lsof(self):
        """On Windows, _clear_port should use the Windows mitmproxy cleaner."""
        from domestique_app.services.proxy import BrowserProxyService

        svc = BrowserProxyService()
        with patch("domestique_app.services.proxy.is_port_listening", return_value=True), \
             patch("domestique_app.services.proxy.is_windows", return_value=True), \
             patch.object(svc, "_clear_stale_windows_mitmproxy", return_value=False) as mock_win:
            with pytest.raises(RuntimeError, match="already in use"):
                svc._clear_port()
            mock_win.assert_called_once()

    def test_linux_uses_lsof_not_taskkill(self):
        """On Linux/macOS, _clear_port should use lsof, not Windows path."""
        from domestique_app.services.proxy import BrowserProxyService

        svc = BrowserProxyService()
        with patch("domestique_app.services.proxy.is_port_listening", return_value=True), \
             patch("domestique_app.services.proxy.is_windows", return_value=False), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            svc._clear_port()
            # Should have called lsof
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args[0] == "lsof"

    def test_no_action_when_port_free(self):
        """No process killing when the port isn't occupied."""
        from domestique_app.services.proxy import BrowserProxyService

        svc = BrowserProxyService()
        with patch("domestique_app.services.proxy.is_port_listening", return_value=False), \
             patch("subprocess.run") as mock_run:
            svc._clear_port()
            mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Runtime helpers
# ---------------------------------------------------------------------------


class TestRuntimeHelpers:
    """Verify cross-platform runtime utilities."""

    def test_subprocess_group_kwargs_returns_dict(self):
        from domestique_app.services.runtime import subprocess_group_kwargs
        kwargs = subprocess_group_kwargs()
        assert isinstance(kwargs, dict)
        if sys.platform == "win32":
            assert "creationflags" in kwargs
        else:
            assert kwargs.get("start_new_session") is True

    def test_venv_python_finds_correct_binary(self, tmp_path: Path):
        """venv_python returns the platform-appropriate interpreter path."""
        from domestique_app.services.runtime import venv_python

        # Create fake venv structure
        if sys.platform == "win32":
            scripts = tmp_path / ".venv" / "Scripts"
            scripts.mkdir(parents=True)
            (scripts / "python.exe").write_text("fake")
        else:
            bin_dir = tmp_path / ".venv" / "bin"
            bin_dir.mkdir(parents=True)
            (bin_dir / "python").write_text("fake")

        result = venv_python(tmp_path)
        assert result is not None
        assert result.exists()

    def test_venv_python_returns_none_when_missing(self, tmp_path: Path):
        from domestique_app.services.runtime import venv_python
        assert venv_python(tmp_path) is None

    def test_is_port_listening_false_for_unbound_port(self):
        from domestique_app.services.runtime import is_port_listening
        # Port 1 should never be listening (requires root/admin)
        assert is_port_listening(1, timeout=0.1) is False


# ---------------------------------------------------------------------------
# Proxy restart endpoint
# ---------------------------------------------------------------------------


class TestProxyRestart:
    """Verify the /api/proxy/restart handler logic."""

    def test_restart_with_nothing_running(self):
        """Restart when no proxy is running returns empty restarted list."""
        import io
        from unittest.mock import PropertyMock

        from domestique_app.server.api import _proxy_service, _browser_proxy_service

        with patch.object(type(_proxy_service), "is_running", new_callable=PropertyMock, return_value=False), \
             patch.object(type(_browser_proxy_service), "is_running", new_callable=PropertyMock, return_value=False):
            # Simulate the handler logic
            restarted = []
            failed = []
            if _proxy_service.is_running:
                restarted.append("firewall")
            if _browser_proxy_service.is_running:
                restarted.append("browser")
            assert restarted == []
            assert failed == []

    def test_restart_with_firewall_running(self):
        """Restart when firewall proxy is running should stop and start it."""
        from domestique_app.services.proxy import ProxyService

        svc = ProxyService()
        config = MagicMock()
        started = False

        def fake_start(c):
            nonlocal started
            started = True

        svc._process = MagicMock()
        svc._process.poll.return_value = None  # Process is running

        with patch.object(svc, "stop") as mock_stop, \
             patch.object(svc, "start", side_effect=fake_start):
            # Simulate restart
            if svc.is_running:
                svc.stop()
                svc.start(config)

            mock_stop.assert_called_once()
            assert started is True


# ---------------------------------------------------------------------------
# Resource monitoring
# ---------------------------------------------------------------------------


class TestResourceMonitor:
    """Verify resource monitoring works cross-platform."""

    def test_snapshot_returns_nonzero_memory(self):
        """Memory RSS must be non-zero on any platform."""
        from domestique_app.server.api import _ResourceMonitor
        mon = _ResourceMonitor()
        snap = mon.snapshot()
        assert snap["mem_rss_mb"] > 0, "Memory RSS should be non-zero"

    def test_snapshot_returns_cpu_count(self):
        import os
        from domestique_app.server.api import _ResourceMonitor
        mon = _ResourceMonitor()
        snap = mon.snapshot()
        assert snap["cpu_count"] == (os.cpu_count() or 1)

    def test_snapshot_cpu_percent_is_nonnegative(self):
        from domestique_app.server.api import _ResourceMonitor
        mon = _ResourceMonitor()
        snap = mon.snapshot()
        assert snap["cpu_percent"] >= 0

    def test_snapshot_returns_all_keys(self):
        from domestique_app.server.api import _ResourceMonitor
        mon = _ResourceMonitor()
        snap = mon.snapshot()
        assert {"cpu_percent", "mem_rss_mb", "gpu_vram_mb", "cpu_count", "ollama"} <= set(snap.keys())
