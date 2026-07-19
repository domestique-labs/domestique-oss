"""Benchmark runner service.

Executes the comprehensive evaluation script in a background thread,
streaming progress updates to any subscriber (API server, menu bar, etc).
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

if not (PROJECT_ROOT / "bench").exists():
    _search = PROJECT_ROOT
    while _search != _search.parent:
        if (_search / "bench").exists():
            PROJECT_ROOT = _search
            break
        _search = _search.parent


@dataclass
class BenchmarkState:
    """Observable state of a benchmark run."""

    running: bool = False
    progress: str = ""
    last_run: str | None = None
    report_exists: bool = False

    @property
    def report_path(self) -> Path:
        return PROJECT_ROOT / "reports" / "benchmark_report.html"


class BenchmarkService:
    """Manages benchmark execution lifecycle.

    Only one benchmark can run at a time. Progress is updated in real-time
    and can be polled by the API server or observed via callback.

    Example:
        svc = BenchmarkService()
        svc.start()
        while svc.state.running:
            print(svc.state.progress)
            time.sleep(1)
    """

    def __init__(self, on_complete: Callable[[], None] | None = None) -> None:
        """Initialize the benchmark service.

        Args:
            on_complete: Optional callback fired when benchmark finishes.
        """
        self._lock = threading.Lock()
        self._state = BenchmarkState()
        self._on_complete = on_complete

    @property
    def state(self) -> BenchmarkState:
        """Get current benchmark state (thread-safe read)."""
        report = PROJECT_ROOT / "reports" / "benchmark_report.html"
        self._state.report_exists = report.exists()
        return self._state

    def start(self) -> bool:
        """Start a benchmark run in the background.

        Returns:
            True if started, False if already running.
        """
        with self._lock:
            if self._state.running:
                return False
            self._state.running = True
            self._state.progress = "Initializing..."

        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        return True

    def open_report(self) -> bool:
        """Open the last benchmark report in the default browser.

        Returns:
            True if report exists and was opened.
        """
        report = PROJECT_ROOT / "reports" / "benchmark_report.html"
        if report.exists():
            webbrowser.open(f"file://{report}")
            return True
        return False

    def _run(self) -> None:
        """Execute the benchmark script (runs in background thread)."""
        script = PROJECT_ROOT / "bench" / "comprehensive_eval.py"
        if not script.exists():
            self._state.progress = "Error: bench/comprehensive_eval.py not found"
            self._state.running = False
            return

        try:
            proc = subprocess.Popen(  # noqa: S603
                [sys.executable, str(script)],
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            for line in proc.stdout:
                stripped = line.strip()
                if stripped and not stripped.startswith(" "):
                    self._state.progress = stripped[:120]

            proc.wait()

            if proc.returncode == 0:
                self._state.progress = "Complete ✓"
                self._state.last_run = time.strftime("%Y-%m-%d %H:%M:%S")
            else:
                self._state.progress = f"Failed (exit code {proc.returncode})"

        except Exception as e:
            self._state.progress = f"Error: {str(e)[:100]}"
        finally:
            self._state.running = False
            if self._on_complete:
                self._on_complete()
