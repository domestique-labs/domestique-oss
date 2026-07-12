"""NSApplication delegate - top-level macOS app lifecycle handler.

Coordinates between the status bar, main window, and backend services.
"""

from __future__ import annotations

import threading
import time
import webbrowser
from pathlib import Path

import objc
from AppKit import NSApp, NSObject
from Foundation import NSLog as _NSLog

def NSLog(msg):
    """NSLog wrapper that handles non-ASCII characters."""
    try:
        _NSLog(msg)
    except (UnicodeEncodeError, UnicodeDecodeError):
        _NSLog(msg.encode('ascii', 'replace').decode('ascii'))

from app.config.store import ConfigStore
from app.native.status_bar import StatusBar
from app.native.window import MainWindow
from app.services.proxy import ProxyService, BrowserProxyService
from app.services.benchmark import BenchmarkService
from app.services.watchdog import Watchdog, ProtectionState


class AppDelegate(NSObject):
    """macOS application delegate.

    Handles lifecycle events and wires together UI and services.
    """

    def applicationDidFinishLaunching_(self, notification) -> None:
        """Called by AppKit once the app is fully initialized."""
        self._proxy = ProxyService()
        self._benchmark = BenchmarkService(on_complete=self._on_benchmark_complete)
        self._shutting_down = False

        # Create UI components
        self._status_bar = StatusBar(delegate=self)

        # First-time setup: generate CA and trust it (BEFORE opening browser)
        # This runs on the main thread so the macOS password dialog can appear
        self._ensure_cert_trusted()

        # Open dashboard
        webbrowser.open("http://127.0.0.1:9876/")

        # Initialize watchdog for proxy health monitoring
        self._watchdog = Watchdog(
            restart_proxy=self._restart_proxy_for_watchdog,
            on_state_change=self._on_watchdog_state_change,
        )

        # Auto-start firewall protection (always-on by default)
        threading.Thread(target=self._start_protection, daemon=True).start()

        # Start state sync loop (keeps menu bar in sync with actual proxy state)
        threading.Thread(target=self._state_sync_loop, daemon=True).start()

    def _ensure_cert_trusted(self) -> None:
        """Generate CA if needed and trust it (no admin password required)."""
        try:
            from app.server.api import get_browser_proxy_service
            from app.services.cert_manager import is_cert_trusted, install_and_trust

            svc = get_browser_proxy_service()
            if not svc.is_setup:
                NSLog("LLMGuard: first-time setup - generating CA")
                svc.setup()

            if not is_cert_trusted():
                NSLog("LLMGuard: installing and trusting certificate")
                success = install_and_trust()
                if success:
                    NSLog("LLMGuard: certificate trusted")
                else:
                    NSLog("LLMGuard: certificate trust deferred to dashboard")
        except Exception as e:
            NSLog(f"LLMGuard: cert setup error: {e}")

    def applicationShouldHandleReopen_hasVisibleWindows_(self, app, has_visible) -> bool:
        """Re-open dashboard in browser when user clicks Dock icon."""
        webbrowser.open("http://127.0.0.1:9876/")
        return True

    def applicationWillTerminate_(self, notification) -> None:
        """Clean shutdown - stop all proxies and watchdog."""
        self._shutting_down = True
        # Stop watchdog first to prevent it from restarting things
        self._watchdog.stop()
        try:
            from app.server.api import get_browser_proxy_service
            svc = get_browser_proxy_service()
            if svc.is_running:
                svc.stop()
        except Exception:
            pass
        self._proxy.stop()

    # --- Actions (called by StatusBar and Dashboard) -----------------

    @objc.IBAction
    def toggleFirewall_(self, sender) -> None:
        """Toggle protection on/off - syncs menu bar + dashboard state."""
        from app.server.api import get_browser_proxy_service
        svc = get_browser_proxy_service()

        if svc.is_running:
            self._stop_protection()
        else:
            threading.Thread(target=self._start_protection, daemon=True).start()

    @objc.IBAction
    def showWindow_(self, sender) -> None:
        """Open the dashboard in the default browser."""
        webbrowser.open("http://127.0.0.1:9876/")

    @objc.IBAction
    def runBenchmark_(self, sender) -> None:
        """Trigger a benchmark run."""
        self._benchmark.start()

    @objc.IBAction
    def viewReport_(self, sender) -> None:
        """Open the last benchmark report."""
        self._benchmark.open_report()

    # --- Internal ----------------------------------------------------

    def _start_protection(self) -> None:
        """Start browser proxy with model pre-warming.

        Waits for cert to be trusted before starting the proxy.
        """
        try:
            from app.server.api import get_browser_proxy_service
            from app.services.cert_manager import is_cert_trusted
            import json
            import urllib.request
            import app.server.api as _api

            _api._startup_state["phase"] = "starting"
            _api._startup_state["detail"] = "Initializing..."

            svc = get_browser_proxy_service()

            _api._startup_state["phase"] = "starting"
            _api._startup_state["detail"] = "Initializing..."

            # Read config directly from JSON file
            cfg_path = Path.home() / ".llmguard" / "config.json"
            stack = {}
            try:
                cfg = json.loads(cfg_path.read_text())
                stack = cfg.get("detection_stack", {})
            except Exception:
                pass

            import platform as _plat
            _apple = _plat.system() == "Darwin" and _plat.machine() == "arm64"

            models_to_warm = []
            if stack.get("gemma4_e2b", False):
                models_to_warm.append("gemma4:e2b-mlx" if _apple else "gemma4:e2b")
            if stack.get("qwen3_1_7b", False):
                models_to_warm.append("qwen3:1.7b")
            if stack.get("legacy_cpu", False):
                models_to_warm.append("llama3.2:1b")

            for model in models_to_warm:
                # Check if already loaded
                try:
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    ps_resp = opener.open("http://localhost:11434/api/ps", timeout=3)
                    loaded = [m["name"] for m in json.loads(ps_resp.read()).get("models", [])]
                    if model in loaded:
                        NSLog(f"LLMGuard: {model} already in memory - skipping warmup")
                        continue
                except Exception:
                    pass

                NSLog(f"LLMGuard: loading {model} into memory...")
                _api._startup_state["phase"] = "warming"
                _api._startup_state["detail"] = f"Loading {model}..."
                try:
                    data = json.dumps({
                        "model": model,
                        "messages": [{"role": "user", "content": "warmup"}],
                        "stream": False, "options": {"num_predict": 1, "num_ctx": 8192},
                        "keep_alive": "24h",
                    }).encode()
                    req = urllib.request.Request("http://localhost:11434/api/chat",
                                                data=data, headers={"Content-Type": "application/json"})
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    opener.open(req, timeout=120)
                    NSLog(f"LLMGuard: {model} ready")
                except Exception as e:
                    NSLog(f"LLMGuard: {model} warmup failed: {e}")

            if not svc.is_running:
                svc.start()

            # Pre-warm the venv scanner subprocess
            _api._startup_state["detail"] = "Warming up detectors..."
            try:
                from app.server.api import _venv_scanner
                _venv_scanner.scan("warmup test@example.com SSN 123-45-6789")
            except Exception as e:
                NSLog(f"LLMGuard: detector warmup failed: {e}")

            self._watchdog.reset_backoff()
            self._watchdog.start()

            _api._startup_state["phase"] = "ready"
            _api._startup_state["detail"] = ""
            NSLog("LLMGuard: protection active")

            try:
                self._sync_ui(active=True)
            except Exception:
                pass  # UI sync is non-critical

        except Exception as e:
            err_msg = str(e).encode('ascii', 'replace').decode('ascii')
            NSLog(f"LLMGuard: failed to start: {err_msg}")
            try:
                import app.server.api as _api2
                _api2._startup_state["phase"] = "error"
                _api2._startup_state["detail"] = err_msg
            except Exception:
                pass
            self._sync_ui(active=False)

    def _stop_protection(self) -> None:
        """Stop browser proxy and sync UI state."""
        try:
            from app.server.api import get_browser_proxy_service
            svc = get_browser_proxy_service()
            if svc.is_running:
                svc.stop()
            NSLog("LLMGuard: protection stopped")
        except Exception as e:
            NSLog(f"LLMGuard: error stopping protection: {e}")
        self._sync_ui(active=False)

    def _sync_ui(self, active: bool) -> None:
        """Update menu bar icon and persist state (thread-safe)."""
        self._status_bar.set_active(active)
        config = ConfigStore.current()
        config.browser_interception = active
        ConfigStore.save(config)

    def _state_sync_loop(self) -> None:
        """Periodically sync menu bar state with actual proxy state.

        This ensures the menu bar always reflects reality, even if the
        proxy is toggled via the dashboard API or crashes unexpectedly.
        Runs every 2 seconds.
        """
        last_state = None
        while not self._shutting_down:
            try:
                from app.server.api import get_browser_proxy_service
                svc = get_browser_proxy_service()
                current_state = svc.is_running
                if current_state != last_state:
                    self._status_bar.set_active(current_state)
                    last_state = current_state
            except Exception:
                pass
            time.sleep(2)

    def _on_benchmark_complete(self) -> None:
        """Called when a benchmark finishes (from background thread)."""
        self._benchmark.open_report()

    # --- Watchdog Integration ----------------------------------------

    def _restart_proxy_for_watchdog(self) -> bool:
        """Called by watchdog to restart the proxy. Returns True on success."""
        try:
            from app.server.api import get_browser_proxy_service
            svc = get_browser_proxy_service()
            if svc.is_running:
                svc.stop()
            svc.start()
            return svc.is_running
        except Exception as e:
            NSLog(f"LLMGuard: watchdog restart failed: {e}")
            return False

    def _on_watchdog_state_change(self, state: ProtectionState) -> None:
        """Called by watchdog when protection state changes."""
        if state == ProtectionState.ACTIVE:
            self._sync_ui(active=True)
        elif state == ProtectionState.FAILED:
            self._sync_ui(active=False)
            NSLog("LLMGuard: protection FAILED - manual restart needed")
        elif state == ProtectionState.DEGRADED:
            NSLog("LLMGuard: protection degraded - attempting recovery")
