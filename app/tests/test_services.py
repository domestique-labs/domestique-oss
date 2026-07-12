"""Unit tests for backend services (proxy, benchmark).

Tests cover:
- Proxy lifecycle (start, stop, state transitions)
- Benchmark service state machine
- Concurrent benchmark rejection
"""

from __future__ import annotations

import subprocess
import time
import threading
from unittest.mock import patch, MagicMock, mock_open

import pytest

from app.config.schema import AppConfig
from app.services.proxy import ProxyService, ProxyState
from app.services.benchmark import BenchmarkService


# --- Proxy Service Tests ---------------------------------------------


class TestProxyService:
    """Tests for ProxyService lifecycle management."""

    def test_initial_state(self):
        svc = ProxyService()
        assert svc.is_running is False
        assert svc.pid is None

    def test_get_state(self):
        svc = ProxyService()
        state = svc.get_state()
        assert isinstance(state, ProxyState)
        assert state.running is False
        assert state.pid is None

    @patch("subprocess.Popen")
    def test_start(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # Still running
        mock_proc.pid = 12345
        mock_popen.return_value = mock_proc

        svc = ProxyService()
        config = AppConfig(proxy_port=9000)

        with patch("builtins.open", mock_open()):
            svc.start(config)

        assert svc.is_running is True
        assert svc.pid == 12345
        mock_popen.assert_called_once()

        # Verify correct port in args
        call_args = mock_popen.call_args
        assert "--port" in call_args[0][0]
        assert "9000" in call_args[0][0]

    @patch("subprocess.Popen")
    def test_start_raises_if_already_running(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        svc = ProxyService()
        with patch("builtins.open", mock_open()):
            svc.start(AppConfig())

        with pytest.raises(RuntimeError, match="already running"):
            svc.start(AppConfig())

    @patch("subprocess.Popen")
    def test_stop(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 99
        mock_popen.return_value = mock_proc

        svc = ProxyService()
        with patch("builtins.open", mock_open()):
            svc.start(AppConfig())
            svc.stop()

        mock_proc.terminate.assert_called_once()
        assert svc.is_running is False

    def test_stop_when_not_running(self):
        """Stop is a no-op if proxy isn't running."""
        svc = ProxyService()
        svc.stop()  # Should not raise

    @patch("subprocess.Popen")
    def test_build_env_qwen3(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        config = AppConfig()
        config.detection_stack.qwen3_1_7b = True
        config.detection_stack.gemma4_e2b = False

        svc = ProxyService()
        with patch("builtins.open", mock_open()):
            svc.start(config)

        env = mock_popen.call_args[1]["env"]
        assert env["LLMGUARD_LOCAL_LLM_MODEL"] == "qwen3:1.7b"
        assert env["LLMGUARD_ENABLE_LOCAL_LLM"] == "true"

    @patch("subprocess.Popen")
    def test_build_env_gemma4(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        config = AppConfig()
        config.detection_stack.qwen3_1_7b = False
        config.detection_stack.gemma4_e2b = True

        svc = ProxyService()
        with patch("builtins.open", mock_open()):
            svc.start(config)

        env = mock_popen.call_args[1]["env"]
        assert env["LLMGUARD_LOCAL_LLM_MODEL"].startswith("gemma4:e2b")

    @patch("subprocess.Popen")
    def test_build_env_no_llm(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        config = AppConfig()
        config.detection_stack.qwen3_1_7b = False
        config.detection_stack.gemma4_e2b = False

        svc = ProxyService()
        with patch("builtins.open", mock_open()):
            svc.start(config)

        env = mock_popen.call_args[1]["env"]
        assert env["LLMGUARD_ENABLE_LOCAL_LLM"] == "false"

    @patch("subprocess.Popen")
    def test_build_env_legacy_cpu(self, mock_popen):
        """The legacy-cpu stack flag must resolve to the model the installer
        actually pulls (llama3.2:1b), not qwen3:1.7b (C4)."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        config = AppConfig()
        config.detection_stack.qwen3_1_7b = False
        config.detection_stack.gemma4_e2b = False
        config.detection_stack.legacy_cpu = True

        svc = ProxyService()
        with patch("builtins.open", mock_open()):
            svc.start(config)

        env = mock_popen.call_args[1]["env"]
        assert env["LLMGUARD_LOCAL_LLM_MODEL"] == "llama3.2:1b"
        assert env["LLMGUARD_ENABLE_LOCAL_LLM"] == "true"


# --- Benchmark Service Tests -----------------------------------------


class TestBenchmarkService:
    """Tests for BenchmarkService state management."""

    def test_initial_state(self):
        svc = BenchmarkService()
        assert svc.state.running is False
        assert svc.state.progress == ""
        assert svc.state.last_run is None

    @patch("subprocess.Popen")
    def test_start_returns_true(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])  # Empty output
        mock_proc.wait.return_value = 0
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        svc = BenchmarkService()
        with patch.object(svc, "_run"):
            result = svc.start()
            assert result is True
            assert svc.state.running is True

    def test_start_rejects_concurrent(self):
        svc = BenchmarkService()
        # Simulate already running
        svc._state.running = True
        result = svc.start()
        assert result is False

    def test_on_complete_callback(self):
        called = []
        svc = BenchmarkService(on_complete=lambda: called.append(True))

        # Simulate run completing
        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.stdout = iter(["Line 1\n", "Done\n"])
            mock_proc.wait.return_value = 0
            mock_proc.returncode = 0
            mock_popen.return_value = mock_proc

            # Patch the script existence check
            with patch("pathlib.Path.exists", return_value=True):
                svc._run()

        assert len(called) == 1
        assert svc.state.running is False
        assert "Complete" in svc.state.progress

    def test_run_handles_missing_script(self):
        svc = BenchmarkService()
        with patch("pathlib.Path.exists", return_value=False):
            svc._state.running = True
            svc._run()

        assert svc.state.running is False
        assert "not found" in svc.state.progress

    def test_run_handles_subprocess_error(self):
        svc = BenchmarkService()
        with patch("pathlib.Path.exists", return_value=True), \
             patch("subprocess.Popen", side_effect=OSError("exec failed")):
            svc._state.running = True
            svc._run()

        assert svc.state.running is False
        assert "Error" in svc.state.progress
