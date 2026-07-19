"""Local HTTP API server for dashboard ↔ backend communication.

Runs on 127.0.0.1:9876 (localhost only, no external exposure).
Provides a RESTful interface for:

    GET  /api/config          Read current configuration
    POST /api/config          Update configuration
    GET  /api/status          System status summary
    POST /api/benchmark       Trigger benchmark run
    GET  /api/benchmark       Poll benchmark progress
    POST /api/firewall/start  Start the proxy
    POST /api/firewall/stop   Stop the proxy

All responses are JSON. CORS headers allow the embedded WKWebView
(file:// origin) to call these endpoints.
"""

from __future__ import annotations

import contextlib
import errno
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING

from domestique_app.config.store import ConfigStore
from domestique_app.services.benchmark import BenchmarkService
from domestique_app.services.proxy import BrowserProxyService, ProxyService

if TYPE_CHECKING:
    from app.services.approval import PendingApproval

# Singleton services (shared across all requests)
_proxy_service = ProxyService()
_browser_proxy_service = BrowserProxyService()
_benchmark_service = BenchmarkService()

# Constants for detecting client-disconnect errors across platforms.
_CLIENT_DISCONNECT_WINERRORS = {10053, 10054}
_CLIENT_DISCONNECT_ERRNOS = {
    errno.ECONNABORTED,
    errno.ECONNRESET,
    errno.EPIPE,
}

# Workshop benchmark state (shared across threads)
_workshop_bench = {
    "running": False,
    "dataset_source": "",
    "total_samples": 0,
    "processed": 0,
    "current_sample": "",
    "results": [],
    "report": None,
    "error": None,
}

# Startup state
_startup_state = {"phase": "starting", "detail": ""}

# Global detector pipeline - built eagerly, rebuilt on config change


class _VenvScanner:
    """Runs the detection pipeline in the project .venv subprocess.

    The py2app bundle excludes torch/GLiNER/transformers to keep the
    bundle small.  The .venv has everything installed, so we shell out
    to it for scans and benchmarks.  A single long-lived subprocess
    is kept alive and fed JSON lines on stdin.
    """

    def __init__(self) -> None:
        self._proc = None
        self._lock = threading.Lock()

    @staticmethod
    def _venv_python() -> str | None:
        """Find the venv python binary."""
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent.parent
        if not (root / ".venv").exists():
            s = root
            while s != s.parent:
                if (s / ".venv").exists():
                    root = s
                    break
                s = s.parent
        for candidate in [
            root / ".venv" / "bin" / "python3",
            root / ".venv" / "bin" / "python",
            root / ".venv" / "Scripts" / "python.exe",
        ]:
            if candidate.exists():
                return str(candidate)
        return None

    def _ensure_proc(self) -> None:
        """Start or restart the worker subprocess if needed."""
        if self._proc is not None and self._proc.poll() is None:
            return
        vpy = self._venv_python()
        if not vpy:
            return
        from pathlib import Path

        root = Path(vpy).parent.parent  # .venv/bin/python -> .venv -> project root
        if not (root / "domestique_app").exists():
            root = root.parent  # .venv -> project root
        # Inline worker script: reads JSON lines from stdin, writes JSON lines to stdout.
        # Eagerly builds the pipeline on startup so the first real scan is fast.
        root_literal = repr(str(root))
        worker = (
            "import sys, json, asyncio, os, logging\n"
            f"sys.path.insert(0, {root_literal})\n"
            "os.environ['HF_HUB_OFFLINE'] = '1'\n"
            "logging.basicConfig(stream=sys.stderr)\n"
            "import structlog; structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))\n"  # noqa: E501
            "from domestique_app.services.pipeline_config import load_config_dict, config_hash, settings_from_config\n"  # noqa: E501
            "from domestique.detectors.registry import create_detector_pipeline\n"
            "cfg = load_config_dict()\n"
            "cfg_hash = config_hash(cfg)\n"
            "settings = settings_from_config(cfg)\n"
            "pipeline = create_detector_pipeline(settings)\n"
            "print(json.dumps({'ok':True,'detections':[],'warmup':True}), flush=True)\n"
            "for line in sys.stdin:\n"
            "    try:\n"
            "        req = json.loads(line)\n"
            "        cfg = load_config_dict()\n"
            "        h = config_hash(cfg)\n"
            "        if h != cfg_hash:\n"
            "            settings = settings_from_config(cfg)\n"
            "            pipeline = create_detector_pipeline(settings)\n"
            "            cfg_hash = h\n"
            "        loop = asyncio.new_event_loop()\n"
            "        result = loop.run_until_complete(pipeline.inspect(req['text']))\n"
            "        loop.close()\n"
            "        dets = [{'detector':f.detector,'category':f.category,'confidence':f.confidence}\n"  # noqa: E501
            "                for f in result.findings if f.category != 'detector_error']\n"
            "        print(json.dumps({'ok':True,'detections':dets}), flush=True)\n"
            "    except Exception as e:\n"
            "        print(json.dumps({'ok':False,'error':str(e)}), flush=True)\n"
        )
        import subprocess

        self._proc = subprocess.Popen(  # noqa: S603
            [vpy, "-c", worker],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=str(root),
        )
        # Consume the warmup line emitted after eager pipeline construction.
        warmup_line: list[bytes] = []

        def _read_warmup() -> None:
            warmup_line.append(self._proc.stdout.readline())

        t = threading.Thread(target=_read_warmup, daemon=True)
        t.start()
        t.join(timeout=120)  # GLiNER can be slow to load

    def scan(self, text: str, timeout: float = 60.0) -> list[dict]:
        """Scan text and return list of detection dicts."""
        with self._lock:
            self._ensure_proc()
            if self._proc is None or self._proc.poll() is not None:
                return []  # venv not available, degrade gracefully
            import json

            try:
                self._proc.stdin.write(json.dumps({"text": text}).encode() + b"\n")
                self._proc.stdin.flush()
                # Read one line of response using a thread (select.select
                # does not work on pipes on Windows).
                result_line: list[bytes] = []

                def _read() -> None:
                    result_line.append(self._proc.stdout.readline())

                reader = threading.Thread(target=_read, daemon=True)
                reader.start()
                reader.join(timeout)
                if not result_line:
                    # Timeout: kill the subprocess to avoid desync
                    # (stale reader thread could consume the next response)
                    with contextlib.suppress(Exception):
                        self._proc.kill()
                    self._proc = None
                    return []
                resp = json.loads(result_line[0])
                if resp.get("ok"):
                    return resp.get("detections", [])
                return []
            except Exception:
                # Kill broken subprocess, will restart on next call
                with contextlib.suppress(Exception):
                    self._proc.stdin.close()
                self._proc = None
                return []


_venv_scanner = _VenvScanner()


class _ResourceMonitor:
    """Tracks Domestique process CPU and memory usage (not system-wide).

    Uses cross-platform APIs:
    - CPU: time.process_time() (user + system, all platforms)
    - Memory: resource module (macOS/Linux), kernel32 via ctypes (Windows)
    - GPU: Ollama /api/ps endpoint (all platforms)
    """

    def __init__(self) -> None:
        import os
        import time

        self._last_time = time.monotonic()
        self._last_cpu = time.process_time()
        self._cpu_pct = 0.0
        self._ncpu = os.cpu_count() or 1

    def snapshot(self) -> dict:
        import sys
        import time

        # CPU: delta of process CPU time vs wall clock
        now = time.monotonic()
        cpu_now = time.process_time()
        wall = now - self._last_time
        if wall > 0.1:
            self._cpu_pct = (cpu_now - self._last_cpu) / wall * 100
            self._last_time = now
            self._last_cpu = cpu_now

        # Memory: RSS of this process
        if sys.platform == "win32":
            mem_mb = self._get_rss_windows()
        else:
            mem_mb = self._get_rss_unix()

        # Ollama: model VRAM, process memory, loaded models
        ollama = self._get_ollama_stats()

        return {
            "cpu_percent": round(max(self._cpu_pct, 0), 1),
            "mem_rss_mb": round(mem_mb, 1),
            "gpu_vram_mb": round(ollama["vram_mb"], 1),
            "cpu_count": self._ncpu,
            "ollama": ollama,
        }

    @staticmethod
    def _get_rss_unix() -> float:
        """Get RSS in MB on macOS/Linux via the resource module."""
        try:
            import platform
            import resource as _res

            rss = _res.getrusage(_res.RUSAGE_SELF).ru_maxrss
            # macOS reports bytes, Linux reports KB
            if platform.system() == "Darwin":
                return rss / 1024 / 1024
            return rss / 1024
        except Exception:
            return 0.0

    @staticmethod
    def _get_rss_windows() -> float:
        """Get working set (RSS equivalent) in MB on Windows via ctypes."""
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):  # noqa: N801
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            GetProcessMemoryInfo = ctypes.windll.psapi.GetProcessMemoryInfo  # noqa: N806
            GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                wintypes.DWORD,
            ]
            GetProcessMemoryInfo.restype = wintypes.BOOL

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(counters)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return counters.WorkingSetSize / 1024 / 1024
        except Exception:  # noqa: S110
            pass
        return 0.0

    @staticmethod
    def _get_ollama_stats() -> dict:
        """Get Ollama resource consumption: loaded models, VRAM, process memory."""
        import subprocess
        import sys
        import urllib.request

        result = {
            "running": False,
            "vram_mb": 0.0,
            "mem_mb": 0.0,
            "models": [],
        }

        # Query Ollama API for loaded models and VRAM
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            resp = opener.open(
                urllib.request.Request("http://localhost:11434/api/ps"),
                timeout=1,
            )
            ps = json.loads(resp.read())
            result["running"] = True
            for m in ps.get("models", []):
                vram = m.get("size_vram", 0) / 1024 / 1024
                total = m.get("size", 0) / 1024 / 1024
                result["vram_mb"] += vram
                result["models"].append(
                    {
                        "name": m.get("name", "unknown"),
                        "size_mb": round(total, 1),
                        "vram_mb": round(vram, 1),
                        "quantization": m.get("details", {}).get("quantization_level", ""),
                        "context_length": m.get("context_length", 0),
                        "expires_at": m.get("expires_at", ""),
                    }
                )
        except Exception:
            return result

        # Get Ollama process memory (sum of all ollama processes)
        try:
            if sys.platform == "win32":
                r = subprocess.run(
                    [  # noqa: S607
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        "Get-Process -Name 'ollama*' -ErrorAction SilentlyContinue | "
                        "Measure-Object -Property WorkingSet64 -Sum | "
                        "Select-Object -ExpandProperty Sum",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if r.returncode == 0 and r.stdout.strip():
                    result["mem_mb"] = round(int(r.stdout.strip()) / 1024 / 1024, 1)
            else:
                # macOS/Linux: use ps to sum RSS of ollama processes
                r = subprocess.run(
                    ["pgrep", "-f", "ollama"],  # noqa: S607
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if r.returncode == 0:
                    pids = r.stdout.strip().split("\n")
                    total_rss = 0
                    for pid in pids:
                        pr = subprocess.run(  # noqa: S603
                            ["ps", "-o", "rss=", "-p", pid.strip()],  # noqa: S607
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if pr.returncode == 0 and pr.stdout.strip():
                            total_rss += int(pr.stdout.strip())
                    result["mem_mb"] = round(total_rss / 1024, 1)
        except Exception:  # noqa: S110
            pass

        return result


_resource_monitor = _ResourceMonitor()


def get_proxy_service() -> ProxyService:
    """Access the shared proxy service instance."""
    return _proxy_service


def get_browser_proxy_service() -> BrowserProxyService:
    """Access the shared browser proxy service instance."""
    return _browser_proxy_service


def get_benchmark_service() -> BenchmarkService:
    """Access the shared benchmark service instance."""
    return _benchmark_service


class APIHandler(BaseHTTPRequestHandler):
    """HTTP request handler implementing the dashboard REST API.

    Stateless - all state lives in the service singletons above.
    Each request is handled independently.
    """

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Suppress default stderr logging."""
        pass

    # --- Response helpers --------------------------------------------

    def _serve_dashboard(self) -> None:
        """Serve the dashboard HTML page."""
        dashboard_path = Path(__file__).parent.parent / "assets" / "dashboard.html"
        if dashboard_path.exists():
            content = dashboard_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(content)
        else:
            self._send_json({"error": "dashboard.html not found"}, 404)

    def _send_json(self, data: dict, status: int = 200) -> None:
        """Send a JSON response with CORS headers."""
        body = json.dumps(data).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(body)
        except OSError as e:
            if self._is_client_disconnect(e):
                return
            raise

    @staticmethod
    def _is_client_disconnect(error: OSError) -> bool:
        """Return True when a browser closed/canceled the request."""
        return (
            isinstance(error, (BrokenPipeError, ConnectionAbortedError, ConnectionResetError))
            or getattr(error, "errno", None) in _CLIENT_DISCONNECT_ERRNOS
            or getattr(error, "winerror", None) in _CLIENT_DISCONNECT_WINERRORS
        )

    def _send_cors_headers(self) -> None:
        """Add CORS headers permitting cross-origin requests from file://."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, X-CSRF-Token",
        )

    def _read_body(self) -> bytes:
        """Read the request body."""
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    # --- HTTP methods ------------------------------------------------

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests."""
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_HEAD(self) -> None:
        """Handle HEAD requests (used by health checks)."""
        self.send_response(200)
        self.end_headers()

    def do_GET(self) -> None:
        """Route GET requests."""
        if self.path == "/" or self.path == "/dashboard":
            self._serve_dashboard()
            return

        if self.path == "/api/config":
            config = ConfigStore.current()
            self._send_json(config.to_dict())

        elif self.path == "/api/status":
            from domestique_app.services.cert_manager import get_cert_status

            cert = get_cert_status()
            self._send_json(
                {
                    "proxy_running": _proxy_service.is_running,
                    "proxy_pid": _proxy_service.pid,
                    "browser_proxy_running": _browser_proxy_service.is_running,
                    "browser_proxy_setup": _browser_proxy_service.is_setup,
                    "benchmark_running": _benchmark_service.state.running,
                    "benchmark_progress": _benchmark_service.state.progress,
                    "startup_phase": _startup_state["phase"],
                    "startup_detail": _startup_state["detail"],
                    "cert_generated": cert["generated"],
                    "cert_trusted": cert["trusted"],
                }
            )

        elif self.path == "/api/cert-status":
            from domestique_app.services.cert_manager import get_cert_status

            self._send_json(get_cert_status())

        elif self.path == "/api/resources":
            self._send_json(_resource_monitor.snapshot())

        elif self.path == "/api/benchmark":
            state = _benchmark_service.state
            self._send_json(
                {
                    "running": state.running,
                    "progress": state.progress,
                    "last_run": state.last_run,
                    "report_exists": state.report_exists,
                }
            )

        elif self.path == "/api/browser-proxy":
            from domestique_app.services.interceptor import get_intercepted_domains

            # Read live stats from the mitm addon
            stats_file = Path.home() / ".domestique" / "browser_stats.json"
            # `light_profile_active`: whether the addon auto-downgraded to
            # regex-only detection because it detected low-resource hardware
            # (see app/services/mitm_addon.py::_light_profile_active). This
            # is the only user-facing surface for that decision -- otherwise
            # it's only ever logged to browser_proxy.log.
            stats = {
                "inspected": 0,
                "blocked": 0,
                "redacted": 0,
                "allowed": 0,
                # Response-side leak alerts (async, non-blocking scan of the
                # LLM's *reply* -- see mitm_addon.py::_report_response_leak).
                # Counted separately from the request-side counters because a
                # response alert can never block/redact; it surfaces a leak
                # after the reply already streamed to the browser.
                "response_alerts": 0,
                # Response bodies that could not be decoded (e.g. an
                # unsupported Content-Encoding) so the background scan never
                # inspected them -- a silent-DLP-gap indicator, surfaced so
                # it's never mistaken for "scanned, clean". See
                # mitm_addon.py::_report_unscannable_response.
                "response_scan_errors": 0,
                "light_profile_active": False,
            }
            try:
                if stats_file.exists():
                    stats.update(json.loads(stats_file.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                pass
            self._send_json(
                {
                    "running": _browser_proxy_service.is_running,
                    "setup_complete": _browser_proxy_service.is_setup,
                    "intercepted_domains": get_intercepted_domains(),
                    "stats": stats,
                    "light_profile_active": stats.get("light_profile_active", False),
                }
            )

        elif self.path == "/proxy.pac":
            # Serve PAC file via HTTP (Safari ignores file:// PAC in some cases)
            pac_path = Path.home() / ".domestique" / "proxy.pac"
            if pac_path.exists():
                content = pac_path.read_bytes()
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                except OSError as e:
                    if self._is_client_disconnect(e):
                        return
                    raise
            else:
                self._send_json({"error": "PAC not generated"}, 404)

        elif self.path.startswith("/api/request-log"):
            # Serve the request log (supports ?limit=N&filter=blocked)
            self._handle_request_log()

        elif self.path.startswith("/api/debug-trace"):
            # Serve the raw prompt decision trace (supports ?limit=N&filter=blocked)
            self._handle_debug_trace()

        elif self.path == "/api/health":
            # Full health check including interception chain verification
            from domestique_app.services.watchdog import verify_interception_chain

            results = verify_interception_chain()
            self._send_json(results)

        elif self.path == "/api/approvals":
            self._handle_list_approvals()

        elif self.path.startswith("/api/approvals/"):
            # GET /api/approvals/{id} - poll approval status
            approval_id = self.path.split("/api/approvals/")[1].rstrip("/")
            if "/" not in approval_id:
                self._handle_get_approval(approval_id)
            else:
                self._send_json({"error": "not found"}, 404)

        elif self.path == "/api/approval-token":
            # Serve CSRF token for dashboard to use in approval actions
            from domestique_app.services.approval import get_approval_manager

            mgr = get_approval_manager()
            self._send_json({"token": mgr.csrf_token})

        elif self.path == "/api/classifier-prompt/default":
            # Serve the built-in default classifier prompt
            from domestique.detectors.local_llm import _CLASSIFIER_SYSTEM_PROMPT

            self._send_json({"prompt": _CLASSIFIER_SYSTEM_PROMPT})

        elif self.path == "/api/builtin-patterns":
            from domestique.detectors.secrets import _PATTERNS

            self._send_json(
                {
                    "patterns": [
                        {"name": p.name, "regex": p.regex, "confidence": p.confidence}
                        for p in _PATTERNS
                    ]
                }
            )

        elif self.path == "/api/gliner-config":
            config = ConfigStore.current()
            self._send_json(
                {
                    "labels": getattr(
                        config,
                        "gliner_labels",
                        [
                            "person",
                            "email",
                            "phone_number",
                            "address",
                            "date_of_birth",
                            "social_security_number",
                            "credit_card",
                            "password",
                            "ip_address",
                        ],
                    ),
                    "threshold": getattr(config, "gliner_threshold", 0.5),
                }
            )

        elif self.path == "/api/benchmark-report":
            report_path = Path(__file__).parent.parent.parent / "reports" / "benchmark_report.html"
            if report_path.exists():
                content = report_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self._send_json(
                    {"error": "No benchmark report found. Run the benchmark first."}, 404
                )

        elif self.path == "/api/custom-patterns":
            config = ConfigStore.current()
            self._send_json({"patterns": config.custom_patterns})

        elif self.path == "/api/domains":
            config = ConfigStore.current()
            self._send_json(
                {
                    "monitored": config.monitored_domains,
                    "allowed": config.allowed_domains,
                }
            )

        elif self.path == "/api/policy-rules":
            config = ConfigStore.current()
            self._send_json({"rules": config.policy_rules})

        elif self.path == "/api/scan":
            # GET with no body returns scan capabilities info
            self._send_json(
                {
                    "tiers": ["regex", "ner", "llm"],
                    "categories": [
                        "CREDENTIALS",
                        "CUSTOMER_DATA",
                        "PROPRIETARY_CODE",
                        "INTERNAL_COMMS",
                        "BUSINESS_STRATEGY",
                    ],
                }
            )

        elif self.path == "/api/workshop/benchmark":
            self._handle_benchmark_status()

        elif self.path == "/api/workshop/datasets":
            self._handle_list_datasets()

        elif self.path == "/api/workshop/dataset":
            self._handle_get_dataset()

        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        """Route POST requests."""
        if self.path == "/api/config":
            self._handle_config_update()

        elif self.path == "/api/benchmark":
            started = _benchmark_service.start()
            if started:
                self._send_json({"ok": True, "message": "benchmark started"})
            else:
                self._send_json({"error": "already running"}, 409)

        elif self.path == "/api/firewall/start":
            self._handle_proxy_start()

        elif self.path == "/api/firewall/stop":
            _proxy_service.stop()
            config = ConfigStore.current()
            config.proxy_enabled = False
            ConfigStore.save(config)
            self._send_json({"ok": True})

        elif self.path == "/api/proxy/restart":
            self._handle_proxy_restart()

        elif self.path == "/api/browser-proxy/setup":
            results = _browser_proxy_service.setup()
            self._send_json(results)

        elif self.path == "/api/cert/install":
            from domestique_app.services.cert_manager import get_cert_status, install_and_trust

            success = install_and_trust()
            status = get_cert_status()
            self._send_json({"ok": success, "status": status})

        elif self.path == "/api/browser-proxy/start":
            if _browser_proxy_service.is_running:
                self._send_json({"ok": True, "already_running": True})
                return
            try:
                # Auto-setup if not done yet
                if not _browser_proxy_service.is_setup:
                    _browser_proxy_service.setup()
                _browser_proxy_service.start()
                config = ConfigStore.current()
                config.browser_interception = True
                config.browser_interception_configured = True
                ConfigStore.save(config)
                self._send_json({"ok": True})
            except RuntimeError as e:
                self._send_json({"error": str(e)}, 500)

        elif self.path == "/api/browser-proxy/stop":
            _browser_proxy_service.stop()
            config = ConfigStore.current()
            config.browser_interception = False
            config.browser_interception_configured = True
            ConfigStore.save(config)
            self._send_json({"ok": True})

        elif self.path == "/api/approvals":
            # POST /api/approvals - addon submits a new pending approval
            self._handle_submit_approval()

        elif self.path.startswith("/api/approvals/") and self.path.endswith("/approve"):
            approval_id = self.path.split("/api/approvals/")[1].replace("/approve", "")
            self._handle_approval_decision(approval_id, "approved")

        elif self.path.startswith("/api/approvals/") and self.path.endswith("/deny"):
            approval_id = self.path.split("/api/approvals/")[1].replace("/deny", "")
            self._handle_approval_decision(approval_id, "denied")

        elif self.path == "/api/custom-patterns":
            self._handle_custom_patterns_update()

        elif self.path == "/api/domains":
            self._handle_domains_update()

        elif self.path == "/api/policy-rules":
            self._handle_policy_rules_update()

        elif self.path == "/api/scan":
            self._handle_scan_request()

        elif self.path == "/api/workshop/benchmark":
            self._handle_run_benchmark()

        elif self.path == "/api/workshop/dataset":
            self._handle_upload_dataset()

        elif self.path == "/api/workshop/dataset/load":
            self._handle_load_dataset_from_path()

        else:
            self._send_json({"error": "not found"}, 404)

    # --- POST handlers -----------------------------------------------

    def _handle_config_update(self) -> None:
        """Parse and save a configuration update."""
        try:
            data = json.loads(self._read_body())
            ConfigStore.save_dict(data)
            # The venv scanner auto-detects config changes via config_hash,
            # so no explicit invalidation needed.
            self._send_json({"ok": True})
        except (json.JSONDecodeError, TypeError) as e:
            self._send_json({"error": f"invalid json: {e}"}, 400)

    def _handle_request_log(self) -> None:
        """Serve the request log with optional filtering.

        Query params:
            limit: Max entries to return (default 100)
            filter: Filter by action (blocked, allowed, redacted, pass)
        """
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        limit = int(params.get("limit", ["100"])[0])
        action_filter = params.get("filter", [None])[0]

        log_file = Path.home() / ".domestique" / "request_log.jsonl"
        entries = []
        try:
            if log_file.exists():
                lines = log_file.read_text(encoding="utf-8").strip().splitlines()
                for line in reversed(lines):  # Most recent first
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        if action_filter and entry.get("action") != action_filter:
                            continue
                        entries.append(entry)
                        if len(entries) >= limit:
                            break
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass

        self._send_json({"entries": entries, "total": len(entries)})

    def _handle_debug_trace(self) -> None:
        """Serve the raw prompt decision trace with optional filtering."""
        from urllib.parse import parse_qs, urlparse

        from domestique.debug_trace import read_debug_trace

        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        limit = int(params.get("limit", ["100"])[0])
        action_filter = params.get("filter", [None])[0]

        entries = read_debug_trace(limit=limit, action_filter=action_filter)
        self._send_json({"entries": entries, "total": len(entries)})

    def _handle_proxy_start(self) -> None:
        """Start the firewall proxy."""
        if _proxy_service.is_running:
            self._send_json({"error": "already running"}, 409)
            return

        config = ConfigStore.current()
        try:
            _proxy_service.start(config)
            config.proxy_enabled = True
            ConfigStore.save(config)
            self._send_json({"ok": True, "pid": _proxy_service.pid})
        except RuntimeError as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_proxy_restart(self) -> None:
        """Restart whichever proxies are currently running.

        Preserves the intended enabled/disabled state — if no proxy was
        running, nothing is started (config is still saved by the caller).
        Returns structured results so the dashboard can report partial
        failures (e.g. firewall OK, browser proxy failed).
        """
        restarted: list[str] = []
        failed: list[dict[str, str]] = []
        config = ConfigStore.current()

        fw_was_running = _proxy_service.is_running
        bp_was_running = _browser_proxy_service.is_running

        if fw_was_running:
            _proxy_service.stop()
            try:
                _proxy_service.start(config)
                restarted.append("firewall")
            except Exception as exc:
                failed.append({"proxy": "firewall", "error": str(exc)})

        if bp_was_running:
            _browser_proxy_service.stop()
            try:
                _browser_proxy_service.start()
                restarted.append("browser")
            except Exception as exc:
                failed.append({"proxy": "browser", "error": str(exc)})

        self._send_json(
            {
                "ok": len(failed) == 0,
                "restarted": restarted,
                "failed": failed,
            }
        )

    # --- Approval handlers -------------------------------------------

    def _handle_list_approvals(self) -> None:
        """List pending and recent approvals."""
        from domestique_app.services.approval import get_approval_manager

        mgr = get_approval_manager()
        pending = [a.to_dict() for a in mgr.list_pending()]
        recent = [a.to_dict() for a in mgr.list_recent(limit=20)]
        self._send_json(
            {
                "pending": pending,
                "recent": recent,
                "pending_count": len(pending),
            }
        )

    def _handle_get_approval(self, approval_id: str) -> None:
        """Get status of a single approval (used by addon polling)."""
        from domestique_app.services.approval import get_approval_manager

        mgr = get_approval_manager()
        approval = mgr.get(approval_id)
        if approval is None:
            self._send_json({"error": "not found"}, 404)
            return
        self._send_json(approval.to_dict())

    def _handle_submit_approval(self) -> None:
        """Submit a new pending approval (called by mitm addon)."""
        from domestique_app.services.approval import get_approval_manager

        try:
            data = json.loads(self._read_body())
            mgr = get_approval_manager()

            config = ConfigStore.current()
            timeout = config.approval_timeout_seconds

            approval = mgr.submit(
                host=data.get("host", "unknown"),
                path=data.get("path", "/"),
                findings=data.get("findings", []),
                content_preview=data.get("content_preview", ""),
                timeout_seconds=timeout,
            )

            # Trigger a best-effort desktop notification
            self._notify_approval_needed(approval)

            self._send_json(
                {
                    "ok": True,
                    "id": approval.id,
                    "timeout_seconds": timeout,
                }
            )
        except (json.JSONDecodeError, TypeError) as e:
            self._send_json({"error": f"invalid request: {e}"}, 400)

    def _handle_approval_decision(self, approval_id: str, decision: str) -> None:
        """Process an approve/deny decision from the dashboard."""
        from domestique_app.services.approval import ApprovalStatus, get_approval_manager

        # Validate CSRF token
        csrf = self.headers.get("X-CSRF-Token", "")
        mgr = get_approval_manager()
        if csrf != mgr.csrf_token:
            self._send_json({"error": "invalid CSRF token"}, 403)
            return

        status = ApprovalStatus.APPROVED if decision == "approved" else ApprovalStatus.DENIED

        try:
            approval = mgr.decide(approval_id, status)
            if approval is None:
                self._send_json({"error": "not found"}, 404)
                return
            self._send_json({"ok": True, "status": approval.status.value})
        except ValueError as e:
            self._send_json({"error": str(e)}, 409)

    def _notify_approval_needed(self, approval: PendingApproval) -> None:
        """Send a desktop notification for a pending approval."""
        try:
            from domestique_app.services.notifications import notify

            categories = ", ".join(approval.findings[:3])
            title = "Domestique: Approval Needed"
            msg = f"{categories} detected in request to {approval.host}"
            notify(title, msg)
        except Exception:  # noqa: S110
            pass  # Non-critical

    # --- Customization handlers --------------------------------------

    def _handle_custom_patterns_update(self) -> None:
        """Add, update, or replace custom regex patterns."""
        import re as re_module

        try:
            data = json.loads(self._read_body())
            patterns = data.get("patterns", [])
            # Validate each pattern
            for p in patterns:
                if not isinstance(p, dict):
                    self._send_json({"error": "each pattern must be an object"}, 400)
                    return
                required = {"name", "regex", "confidence", "category"}
                if not required.issubset(p.keys()):
                    self._send_json(
                        {"error": f"pattern missing fields: {required - set(p.keys())}"}, 400
                    )
                    return
                try:
                    re_module.compile(p["regex"])
                except re_module.error as e:
                    self._send_json({"error": f"invalid regex '{p['name']}': {e}"}, 400)
                    return
                if not (0.0 <= p["confidence"] <= 1.0):
                    self._send_json(
                        {"error": f"confidence must be 0.0-1.0 for '{p['name']}'"}, 400
                    )
                    return
            ConfigStore.save_dict({"custom_patterns": patterns})
            self._send_json({"ok": True, "count": len(patterns)})
        except (json.JSONDecodeError, TypeError) as e:
            self._send_json({"error": f"invalid json: {e}"}, 400)

    def _handle_domains_update(self) -> None:
        """Update monitored and allowed domain lists."""
        try:
            data = json.loads(self._read_body())
            update = {}
            if "monitored" in data:
                if not isinstance(data["monitored"], list):
                    self._send_json({"error": "monitored must be a list"}, 400)
                    return
                update["monitored_domains"] = [
                    d.strip().lower() for d in data["monitored"] if d.strip()
                ]
            if "allowed" in data:
                if not isinstance(data["allowed"], list):
                    self._send_json({"error": "allowed must be a list"}, 400)
                    return
                update["allowed_domains"] = [
                    d.strip().lower() for d in data["allowed"] if d.strip()
                ]
            ConfigStore.save_dict(update)
            self._send_json({"ok": True})
        except (json.JSONDecodeError, TypeError) as e:
            self._send_json({"error": f"invalid json: {e}"}, 400)

    def _handle_policy_rules_update(self) -> None:
        """Update per-category policy rules."""
        try:
            data = json.loads(self._read_body())
            rules = data.get("rules", [])
            valid_actions = {"block", "approve", "log"}
            for rule in rules:
                if not isinstance(rule, dict):
                    self._send_json({"error": "each rule must be an object"}, 400)
                    return
                if "category" not in rule or "action" not in rule:
                    self._send_json({"error": "rule requires 'category' and 'action'"}, 400)
                    return
                if rule["action"] not in valid_actions:
                    self._send_json({"error": f"action must be one of {valid_actions}"}, 400)
                    return
                if "min_confidence" in rule:  # noqa: SIM102
                    if not (0.0 <= rule["min_confidence"] <= 1.0):
                        self._send_json({"error": "min_confidence must be 0.0-1.0"}, 400)
                        return
            ConfigStore.save_dict({"policy_rules": rules})
            self._send_json({"ok": True, "count": len(rules)})
        except (json.JSONDecodeError, TypeError) as e:
            self._send_json({"error": f"invalid json: {e}"}, 400)

    def _handle_scan_request(self) -> None:
        """Scan text using the venv-hosted detection pipeline."""
        try:
            data = json.loads(self._read_body())
            text = data.get("text", "")
            if not text:
                self._send_json({"error": "text field required"}, 400)
                return

            import time

            total_start = time.perf_counter()
            detections = _venv_scanner.scan(text)
            total_ms = round((time.perf_counter() - total_start) * 1000, 2)

            # Also run custom patterns from config
            from domestique_app.config.store import ConfigStore

            cfg = ConfigStore.current().to_dict()
            custom_patterns = cfg.get("custom_patterns", [])
            if custom_patterns:
                import re as re_module

                for pat in custom_patterns:
                    try:
                        compiled = re_module.compile(pat["regex"])
                        for _m in compiled.finditer(text):
                            detections.append(
                                {
                                    "detector": f"custom:{pat['name']}",
                                    "category": pat["category"],
                                    "confidence": pat["confidence"],
                                }
                            )
                    except Exception:  # noqa: S110
                        pass

            self._send_json(
                {
                    "detections": detections,
                    "total_latency_ms": total_ms,
                    "text_length": len(text),
                }
            )
        except (json.JSONDecodeError, TypeError) as e:
            self._send_json({"error": f"invalid json: {e}"}, 400)

    # --- Workshop benchmark handlers ---------------------------------

    def _handle_list_datasets(self) -> None:
        """Return all available benchmark datasets."""
        results = []
        # Built-in datasets in workshop/prompt_competition/
        project_root = Path(__file__).parent.parent.parent
        if not (project_root / "workshop").exists():
            s = project_root
            while s != s.parent:
                if (s / "workshop").exists():
                    project_root = s
                    break
                s = s.parent
        ds_dir = project_root / "workshop" / "prompt_competition"
        if ds_dir.exists():
            for f in sorted(ds_dir.glob("dataset*.json")):
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    samples = data.get("samples", [])
                    from collections import Counter

                    dist = dict(Counter(s["expected"] for s in samples))
                    results.append(
                        {
                            "path": str(f),
                            "name": data.get("name", f.stem),
                            "samples": len(samples),
                            "distribution": dist,
                        }
                    )
                except Exception:  # noqa: S110
                    pass
        # Custom uploaded dataset
        custom = Path.home() / ".domestique" / "workshop" / "custom_dataset.json"
        if custom.exists():
            try:
                data = json.loads(custom.read_text(encoding="utf-8"))
                samples = data.get("samples", [])
                from collections import Counter

                dist = dict(Counter(s["expected"] for s in samples))
                results.append(
                    {
                        "path": str(custom),
                        "name": "Custom (uploaded)",
                        "samples": len(samples),
                        "distribution": dist,
                    }
                )
            except Exception:  # noqa: S110
                pass
        self._send_json({"datasets": results})

    def _handle_get_dataset(self) -> None:
        """Return the current workshop dataset (built-in or custom)."""
        dataset_path = self._get_active_dataset_path()
        try:
            data = json.loads(dataset_path.read_text(encoding="utf-8"))
            self._send_json(
                {
                    "ok": True,
                    "source": str(dataset_path),
                    "sample_count": len(data.get("samples", [])),
                    "metadata": data.get("metadata", {}),
                    "samples": data.get("samples", []),
                }
            )
        except (OSError, json.JSONDecodeError) as e:
            self._send_json({"error": f"failed to load dataset: {e}"}, 500)

    def _handle_upload_dataset(self) -> None:
        """Upload a custom JSONL or JSON dataset for benchmarking."""
        try:
            body = self._read_body().decode("utf-8")
            data = json.loads(body)

            # Accept either {"samples": [...]} or raw list of samples
            if isinstance(data, list):
                samples = data
            elif isinstance(data, dict) and "samples" in data:
                samples = data["samples"]
            elif isinstance(data, dict) and "lines" in data:
                # JSONL content passed as string
                lines = data["lines"].strip().splitlines()
                samples = []
                for line in lines:
                    if line.strip():
                        samples.append(json.loads(line))
            else:
                self._send_json(
                    {"error": "expected {samples: [...]} or [{...}, ...] or {lines: '...'}"}, 400
                )
                return

            # Validate samples
            for i, s in enumerate(samples):
                if "text" not in s:
                    self._send_json({"error": f"sample {i} missing 'text' field"}, 400)
                    return
                if "expected" not in s:
                    self._send_json({"error": f"sample {i} missing 'expected' field"}, 400)
                    return
                if "id" not in s:
                    s["id"] = i + 1
                if "difficulty" not in s:
                    s["difficulty"] = "medium"

            # Save custom dataset
            custom_dir = Path.home() / ".domestique" / "workshop"
            custom_dir.mkdir(parents=True, exist_ok=True)
            custom_path = custom_dir / "custom_dataset.json"
            custom_data = {
                "metadata": {
                    "name": "Custom Workshop Dataset",
                    "version": "custom",
                    "sample_count": len(samples),
                    "categories": list(set(s["expected"] for s in samples)),
                },
                "samples": samples,
            }
            custom_path.write_text(json.dumps(custom_data, indent=2))

            self._send_json(
                {
                    "ok": True,
                    "sample_count": len(samples),
                    "categories": custom_data["metadata"]["categories"],
                    "path": str(custom_path),
                }
            )
        except json.JSONDecodeError as e:
            self._send_json({"error": f"invalid JSON: {e}"}, 400)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_load_dataset_from_path(self) -> None:
        """Load a dataset from a local file path and save as custom dataset."""
        try:
            data = json.loads(self._read_body())
            file_path = Path(data.get("path", ""))

            if not file_path.exists():
                self._send_json({"error": f"file not found: {file_path}"}, 404)
                return

            content = file_path.read_text(encoding="utf-8")

            # Parse as JSON or JSONL
            try:
                parsed = json.loads(content)
                if isinstance(parsed, dict) and "samples" in parsed:
                    samples = parsed["samples"]
                    metadata = parsed.get("metadata", {})
                elif isinstance(parsed, list):
                    samples = parsed
                    metadata = {}
                else:
                    self._send_json({"error": "expected {samples: [...]} or [...]"}, 400)
                    return
            except json.JSONDecodeError:
                # Try JSONL
                samples = []
                for line in content.strip().splitlines():
                    if line.strip():
                        samples.append(json.loads(line))
                metadata = {}

            # Validate
            for i, s in enumerate(samples):
                if "text" not in s:
                    self._send_json({"error": f"sample {i} missing 'text'"}, 400)
                    return
                if "expected" not in s:
                    self._send_json({"error": f"sample {i} missing 'expected'"}, 400)
                    return

            # Save as custom dataset
            custom_dir = Path.home() / ".domestique" / "workshop"
            custom_dir.mkdir(parents=True, exist_ok=True)
            custom_path = custom_dir / "custom_dataset.json"
            custom_data = {
                "metadata": metadata
                or {
                    "name": f"Loaded from {file_path.name}",
                    "version": "custom",
                    "sample_count": len(samples),
                    "categories": list(set(s["expected"] for s in samples)),
                },
                "samples": samples,
            }
            custom_path.write_text(json.dumps(custom_data, indent=2))

            self._send_json(
                {
                    "ok": True,
                    "sample_count": len(samples),
                    "source": str(file_path),
                    "categories": list(set(s["expected"] for s in samples)),
                }
            )
        except json.JSONDecodeError as e:
            self._send_json({"error": f"invalid JSON in file: {e}"}, 400)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_benchmark_status(self) -> None:
        """Return benchmark progress or last results."""
        if _workshop_bench["running"]:
            self._send_json(
                {
                    "ok": True,
                    "running": True,
                    "dataset_source": _workshop_bench["dataset_source"],
                    "total_samples": _workshop_bench["total_samples"],
                    "processed": _workshop_bench["processed"],
                    "current_sample": _workshop_bench["current_sample"],
                }
            )
            return
        if _workshop_bench.get("error"):
            self._send_json({"ok": False, "error": _workshop_bench["error"]})
            return
        if _workshop_bench["report"]:
            self._send_json({"ok": True, "running": False, "report": _workshop_bench["report"]})
            return
        results_path = Path.home() / ".domestique" / "workshop" / "last_benchmark.json"
        if results_path.exists():
            try:
                data = json.loads(results_path.read_text(encoding="utf-8"))
                self._send_json({"ok": True, "results": data})
            except (json.JSONDecodeError, OSError):
                self._send_json({"ok": True, "results": None})
        else:
            self._send_json({"ok": True, "results": None})

    def _handle_run_benchmark(self) -> None:
        """Launch benchmark in background thread, return immediately."""
        if _workshop_bench["running"]:
            self._send_json({"error": "benchmark already running"}, 409)
            return

        try:
            body_data = (
                json.loads(self._read_body())
                if int(self.headers.get("Content-Length", 0)) > 0
                else {}
            )
        except json.JSONDecodeError:
            body_data = {}

        # Load samples from selected dataset paths (or fallback to active)
        dataset_paths = body_data.get("dataset_paths", [])
        samples = []
        source_names = []
        if dataset_paths:
            for p in dataset_paths:
                try:
                    data = json.loads(Path(p).read_text(encoding="utf-8"))
                    ds_samples = data.get("samples", [])
                    samples.extend(ds_samples)
                    source_names.append(data.get("name", Path(p).stem))
                except Exception:  # noqa: S110
                    pass
        if not samples:
            dataset_path = self._get_active_dataset_path(
                prefer_custom=body_data.get("use_custom_dataset", False)
            )
            try:
                data = json.loads(dataset_path.read_text(encoding="utf-8"))
                samples = data.get("samples", [])
                source_names = [dataset_path.name]
            except (OSError, json.JSONDecodeError) as e:
                self._send_json({"error": f"failed to load dataset: {e}"}, 500)
                return

        if not samples:
            self._send_json({"error": "no samples in selected datasets"}, 400)
            return

        source_label = " + ".join(source_names) if source_names else "unknown"

        # Reset state and launch
        _workshop_bench.update(
            {
                "running": True,
                "dataset_source": source_label,
                "total_samples": len(samples),
                "processed": 0,
                "current_sample": "",
                "results": [],
                "report": None,
                "error": None,
            }
        )

        def _run() -> None:
            import time

            try:
                results = []

                for i, sample in enumerate(samples):
                    text = sample["text"]
                    expected = sample["expected"]
                    _workshop_bench["processed"] = i
                    _workshop_bench["current_sample"] = text[:60]

                    start_t = time.perf_counter()
                    detections = _venv_scanner.scan(text)
                    latency_ms = round((time.perf_counter() - start_t) * 1000, 1)

                    if detections:
                        llm_dets = [
                            d for d in detections if d["detector"] == "local_llm_classifier"
                        ]
                        if llm_dets:
                            best = max(llm_dets, key=lambda d: d["confidence"])
                        else:
                            best = max(detections, key=lambda d: d["confidence"])
                        predicted, confidence = best["category"], best["confidence"]
                    else:
                        predicted, confidence = "NONE", 1.0

                    predicted_norm = self._normalize_category(predicted)

                    results.append(
                        {
                            "id": sample.get("id"),
                            "text_preview": text[:80],
                            "expected": expected,
                            "predicted": predicted_norm,
                            "predicted_raw": predicted,
                            "confidence": confidence,
                            "correct": predicted_norm == expected,
                            "latency_ms": latency_ms,
                            "difficulty": sample.get("difficulty", "medium"),
                            "detection_count": len(detections),
                        }
                    )

                _workshop_bench["processed"] = len(samples)

                metrics = self._compute_metrics(results)
                report = {
                    "timestamp": __import__("datetime").datetime.now().isoformat(),
                    "dataset_source": source_label,
                    "total_samples": len(results),
                    "metrics": metrics,
                    "results": results,
                }
                results_dir = Path.home() / ".domestique" / "workshop"
                results_dir.mkdir(parents=True, exist_ok=True)
                (results_dir / "last_benchmark.json").write_text(json.dumps(report, indent=2))
                _workshop_bench["report"] = report
            except Exception as e:
                import traceback

                _workshop_bench["error"] = f"{e}\n{traceback.format_exc()}"
            finally:
                _workshop_bench["running"] = False

        threading.Thread(target=_run, daemon=True, name="workshop-bench").start()
        self._send_json(
            {"ok": True, "message": "benchmark started", "total_samples": len(samples)}
        )

    _CATEGORY_MAP = {
        # LLM classifier prefixed categories
        "llm_classified:proprietary_code": "PROPRIETARY_CODE",
        "llm_classified:business_strategy": "BUSINESS_STRATEGY",
        "llm_classified:customer_data": "CUSTOMER_DATA",
        "llm_classified:internal_comms": "INTERNAL_COMMS",
        "llm_classified:credentials": "CREDENTIALS",
        "llm_classified:none": "NONE",
        # Regex detector categories
        "us_ssn": "CUSTOMER_DATA",
        "credit_card": "CUSTOMER_DATA",
        "email_address": "CUSTOMER_DATA",
        "phone_number": "CUSTOMER_DATA",
        "private_key": "CREDENTIALS",
        "aws_access_key": "CREDENTIALS",
        "aws_secret_key": "CREDENTIALS",
        "connection_string": "CREDENTIALS",
        "github_token": "CREDENTIALS",
        "github_fine_grained": "CREDENTIALS",
        "anthropic_key": "CREDENTIALS",
        "openai_key": "CREDENTIALS",
        "slack_token": "CREDENTIALS",
        "jwt": "CREDENTIALS",
        "generic_api_key": "CREDENTIALS",
        "password_literal": "CREDENTIALS",
        # Semantic detector categories
        "encoded_content_base64": "CREDENTIALS",
        "encoded_content_hex": "CREDENTIALS",
        "high_entropy_string": "CREDENTIALS",
        # GLiNER PII categories
        "pii:person": "CUSTOMER_DATA",
        "pii:email": "CUSTOMER_DATA",
        "pii:phone_number": "CUSTOMER_DATA",
        "pii:social_security_number": "CUSTOMER_DATA",
        "pii:credit_card": "CUSTOMER_DATA",
        "pii:date_of_birth": "CUSTOMER_DATA",
        "pii:address": "CUSTOMER_DATA",
        "pii:ip_address": "CUSTOMER_DATA",
        "pii:password": "CREDENTIALS",
        # Presidio categories
        "person": "CUSTOMER_DATA",
    }

    def _normalize_category(self, raw: str) -> str:
        """Map detector-specific category names to dataset-level labels."""
        if raw in self._CATEGORY_MAP:
            return self._CATEGORY_MAP[raw]
        # Try lowercase match
        lower = raw.lower()
        for key, val in self._CATEGORY_MAP.items():
            if key == lower:
                return val
        # If it's already a standard label, keep it
        standard = {
            "PROPRIETARY_CODE",
            "BUSINESS_STRATEGY",
            "CUSTOMER_DATA",
            "INTERNAL_COMMS",
            "CREDENTIALS",
            "NONE",
        }
        if raw in standard:
            return raw
        # Any detection that isn't NONE means something was found
        if raw != "NONE":
            return "CREDENTIALS"  # conservative fallback
        return "NONE"

    def _compute_metrics(self, results: list) -> dict:
        """Compute precision, recall, F1, accuracy from benchmark results."""
        categories = list(
            set(r["expected"] for r in results) | set(r["predicted"] for r in results)
        )
        categories = [c for c in categories if c != "NONE"] + ["NONE"]

        total = len(results)
        correct = sum(1 for r in results if r["correct"])
        accuracy = round(correct / total * 100, 1) if total else 0

        # Binary: sensitive vs NONE
        tp = sum(1 for r in results if r["expected"] != "NONE" and r["predicted"] != "NONE")
        fp = sum(1 for r in results if r["expected"] == "NONE" and r["predicted"] != "NONE")
        fn = sum(1 for r in results if r["expected"] != "NONE" and r["predicted"] == "NONE")
        tn = sum(1 for r in results if r["expected"] == "NONE" and r["predicted"] == "NONE")

        precision = round(tp / (tp + fp) * 100, 1) if (tp + fp) > 0 else 0
        recall = round(tp / (tp + fn) * 100, 1) if (tp + fn) > 0 else 0
        f1 = (
            round(2 * precision * recall / (precision + recall), 1)
            if (precision + recall) > 0
            else 0
        )

        # Per-category metrics
        per_category = {}
        for cat in categories:
            cat_tp = sum(1 for r in results if r["expected"] == cat and r["predicted"] == cat)
            cat_fp = sum(1 for r in results if r["expected"] != cat and r["predicted"] == cat)
            cat_fn = sum(1 for r in results if r["expected"] == cat and r["predicted"] != cat)
            cat_prec = round(cat_tp / (cat_tp + cat_fp) * 100, 1) if (cat_tp + cat_fp) > 0 else 0
            cat_rec = round(cat_tp / (cat_tp + cat_fn) * 100, 1) if (cat_tp + cat_fn) > 0 else 0
            cat_f1 = (
                round(2 * cat_prec * cat_rec / (cat_prec + cat_rec), 1)
                if (cat_prec + cat_rec) > 0
                else 0
            )
            per_category[cat] = {
                "precision": cat_prec,
                "recall": cat_rec,
                "f1": cat_f1,
                "support": sum(1 for r in results if r["expected"] == cat),
            }

        # Latency stats
        latencies = [r["latency_ms"] for r in results]
        avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else 0
        p95_latency = round(sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0, 1)

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "per_category": per_category,
            "avg_latency_ms": avg_latency,
            "p95_latency_ms": p95_latency,
            "total": total,
            "correct": correct,
        }

    def _get_active_dataset_path(self, prefer_custom: bool = False) -> Path:
        """Return path to the active dataset (custom if exists, else built-in)."""
        custom_path = Path.home() / ".domestique" / "workshop" / "custom_dataset.json"
        # Resolve project root (handles py2app bundle where __file__ is inside .app)
        project_root = Path(__file__).parent.parent.parent
        if not (project_root / "workshop").exists():
            _search = project_root
            while _search != _search.parent:
                if (_search / "workshop").exists():
                    project_root = _search
                    break
                _search = _search.parent
        builtin_path = project_root / "workshop" / "prompt_competition" / "dataset.json"

        if prefer_custom and custom_path.exists():
            return custom_path
        if custom_path.exists():
            return custom_path
        return builtin_path


from socketserver import ThreadingMixIn  # noqa: E402


class _LocalHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTPServer that skips getfqdn() in server_bind.

    ThreadingMixIn handles each request in a new thread so slow endpoints
    (e.g. GLiNER loading, LLM calls) don't block the entire server.
    """

    daemon_threads = True

    def server_bind(self) -> None:
        self.socket.setsockopt(
            __import__("socket").SOL_SOCKET, __import__("socket").SO_REUSEADDR, 1
        )
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()
        self.server_name = "localhost"
        self.server_port = self.server_address[1]


def start_api_server(port: int = 9876) -> HTTPServer:
    """Start the API server on a background daemon thread.

    Args:
        port: Port to bind (default 9876, localhost only).

    Returns:
        The HTTPServer instance (can be used to call .shutdown()).
    """
    server = _LocalHTTPServer(("127.0.0.1", port), APIHandler)
    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
        name="api-server",
    )
    thread.start()
    return server
