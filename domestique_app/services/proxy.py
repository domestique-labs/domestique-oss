"""Firewall proxy lifecycle management.

Manages two proxy modes:
1. **API Proxy** (uvicorn) - Intercepts programmatic LLM SDK calls (port 8000)
2. **Browser Proxy** (mitmproxy) - Intercepts browser HTTPS traffic (port 8080)

Both can run independently or together for full coverage.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from domestique_app.config.store import APP_DATA_DIR
from domestique_app.services.runtime import (
    is_macos,
    is_port_listening,
    is_windows,
    subprocess_group_kwargs,
)

if TYPE_CHECKING:
    from domestique_app.config.schema import AppConfig

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# When running inside a py2app bundle, __file__ points into
# .app/Contents/Resources/lib/... which is NOT the project root.
# Walk up from the bundle location until we find a directory with .venv.
if not (PROJECT_ROOT / ".venv").exists():
    _search = PROJECT_ROOT
    while _search != _search.parent:
        if (_search / ".venv").exists():
            PROJECT_ROOT = _search
            break
        _search = _search.parent


@dataclass
class ProxyState:
    """Current state of the firewall proxy process."""

    pid: int | None = None
    port: int = 8000
    running: bool = False


class ProxyService:
    """Manages the firewall proxy subprocess lifecycle.

    The proxy is a uvicorn process running the FastAPI inspection proxy.
    This service handles start, stop, and status checks.

    Example:
        svc = ProxyService()
        svc.start(config)
        assert svc.is_running()
        svc.stop()
    """

    def __init__(self) -> None:
        self._process: subprocess.Popen | None = None
        self._log_file = None

    @property
    def is_running(self) -> bool:
        """Check if the proxy process is alive."""
        if self._process is None:
            return False
        return self._process.poll() is None

    @property
    def pid(self) -> int | None:
        """PID of the running proxy process, or None."""
        if self.is_running:
            return self._process.pid
        return None

    def start(self, config: AppConfig) -> None:
        """Start the firewall proxy process.

        Args:
            config: Application configuration specifying port, detectors, etc.

        Raises:
            RuntimeError: If the proxy is already running.
        """
        if self.is_running:
            raise RuntimeError("Proxy is already running")

        env = self._build_env(config)
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._log_file = open(APP_DATA_DIR / "firewall.log", "a")  # noqa: SIM115

        self._process = subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-m",
                "uvicorn",
                "domestique.app:create_app",
                "--factory",
                "--host",
                config.proxy_host,
                "--port",
                str(config.proxy_port),
            ],
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the firewall proxy gracefully.

        Sends SIGTERM and waits up to `timeout` seconds before SIGKILL.

        Args:
            timeout: Seconds to wait for graceful shutdown.
        """
        if self._process is None:
            return

        self._process.terminate()
        try:
            self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=2)

        self._process = None
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    def get_state(self) -> ProxyState:
        """Get a snapshot of the current proxy state."""
        return ProxyState(
            pid=self.pid,
            port=8000,  # Could read from config
            running=self.is_running,
        )

    @staticmethod
    def _build_env(config: AppConfig) -> dict:
        """Build environment variables for the proxy process."""
        env = os.environ.copy()
        env["DOMESTIQUE_PORT"] = str(config.proxy_port)
        env["DOMESTIQUE_FAIL_MODE"] = config.fail_mode

        stack = config.detection_stack
        has_llm = stack.qwen3_1_7b or stack.gemma4_e2b or stack.legacy_cpu
        env["DOMESTIQUE_ENABLE_LOCAL_LLM"] = str(has_llm).lower()
        env["DOMESTIQUE_ENABLE_SECRET_DETECTION"] = str(stack.regex).lower()

        # Select the LLM model based on priority
        if stack.gemma4_e2b:
            from domestique.detectors.local_llm import _resolve_gemma_model

            env["DOMESTIQUE_LOCAL_LLM_MODEL"] = _resolve_gemma_model()
        elif stack.qwen3_1_7b:
            env["DOMESTIQUE_LOCAL_LLM_MODEL"] = "qwen3:1.7b"
        elif stack.legacy_cpu:
            env["DOMESTIQUE_LOCAL_LLM_MODEL"] = "llama3.2:1b"

        return env


def _refresh_mitm_confdir(ca_cert_path: Path, ca_key_path: Path, confdir: Path) -> bool:
    """Copy the Domestique CA into mitmproxy's confdir if missing or stale.

    mitmdump reads its CA exclusively from ``confdir/mitmproxy-ca.pem`` /
    ``mitmproxy-ca-cert.pem`` -- it has no idea our own
    ``~/.domestique/ca/domestique-ca.{pem,key}`` even exists. This used to copy
    only once ever (``if not mitm_cert.exists(): ...``), so if the source
    CA was ever rotated, regenerated, or restored from a backup without
    also clearing ``ca/mitmproxy/``, mitmdump kept signing with the STALE
    copy while ``cert_manager``/the dashboard both read the NEW CA and
    happily reported it as generated+trusted -- an undiagnosable cert
    mismatch (audit I7, hit in practice restoring a ``ca.bak``).

    Chosen approach: re-copy whenever the destination is missing OR older
    (mtime) than the source CA, rather than unconditionally clearing/
    rewriting the confdir on every ``start()`` call. This is cheap, keeps
    the fix localized to the one place that already reads these paths (no
    new coupling to ``interceptor.generate_ca()``, which doesn't know
    mitmproxy's confdir layout and shouldn't have to), and correctly
    handles the two real triggers: CA regeneration (``generate_ca()``
    rewrites the source files with a fresh mtime) and a typical backup
    restore (``cp``/``Copy-Item`` without explicitly preserving
    timestamps sets the restored file's mtime to "now"). It is NOT a
    100%-airtight guarantee: a restore that deliberately preserves an
    OLDER mtime than the existing stale confdir copy would not be caught
    by this check; a content-hash comparison would close that gap at the
    cost of hashing both files on every proxy start for a scenario that
    hasn't been observed in practice.

    Returns:
        True if a (re)copy happened, False if the confdir copy was
        already up to date.
    """
    confdir.mkdir(parents=True, exist_ok=True)
    mitm_cert = confdir / "mitmproxy-ca-cert.pem"
    mitm_key = confdir / "mitmproxy-ca.pem"

    source_mtime = ca_cert_path.stat().st_mtime
    stale = (
        not mitm_cert.exists() or not mitm_key.exists() or mitm_cert.stat().st_mtime < source_mtime
    )
    if not stale:
        return False

    # mitmproxy wants combined key+cert in mitmproxy-ca.pem
    combined = ca_key_path.read_text() + "\n" + ca_cert_path.read_text()
    mitm_key.write_text(combined)
    # And the cert alone
    mitm_cert.write_text(ca_cert_path.read_text())
    return True


class BrowserProxyService:
    """Manages the mitmproxy-based HTTPS interception proxy.

    This proxy intercepts browser traffic to known LLM endpoints (ChatGPT,
    Gemini, Claude, etc.) using a PAC file + system proxy configuration.

    Lifecycle:
        1. setup() - Generate CA, install to keychain, create PAC file
        2. start() - Launch mitmdump with our inspection addon
        3. stop()  - Kill mitmdump, disable system proxy

    Example:
        svc = BrowserProxyService()
        svc.setup()  # One-time setup
        svc.start()  # Start intercepting
        # ... browser traffic is now inspected ...
        svc.stop()   # Stop and clean up
    """

    PROXY_PORT = 8080

    def __init__(self) -> None:
        self._process: subprocess.Popen | None = None
        self._setup_complete = False

    @property
    def is_running(self) -> bool:
        """Check if the browser proxy is alive."""
        if self._process is None:
            return False
        return self._process.poll() is None

    @property
    def is_setup(self) -> bool:
        """Check if CA cert is generated and installed."""
        from domestique_app.services.interceptor import CA_CERT_PATH, is_ca_installed

        return CA_CERT_PATH.exists() and is_ca_installed()

    def setup(self) -> dict:
        """One-time setup: generate CA, install to keychain, create PAC.

        Returns:
            Status dict with setup results.
        """
        from domestique_app.services.interceptor import (
            generate_ca,
            generate_pac_file,
            install_ca_to_keychain,
            is_ca_installed,
        )

        results = {}

        # Generate CA certificate
        cert_path, key_path = generate_ca()
        results["ca_generated"] = cert_path.exists()

        # Always verify CA is in keychain (reinstall if missing)
        if not is_ca_installed():
            results["ca_installed"] = install_ca_to_keychain(cert_path)
        else:
            # Double-check trust by verifying the cert can be found
            results["ca_installed"] = True

        # Generate PAC file
        pac_path = generate_pac_file()
        results["pac_generated"] = pac_path.exists()

        self._setup_complete = all(results.values())
        results["ready"] = self._setup_complete
        return results

    def start(self) -> None:
        """Start the mitmproxy HTTPS interception proxy.

        Launches mitmdump with our custom addon and enables the system proxy.
        Handles port conflicts by killing stale processes.

        Raises:
            RuntimeError: If setup hasn't been completed or proxy is running.
        """
        if self.is_running:
            raise RuntimeError("Browser proxy is already running")

        from domestique_app.services.interceptor import (
            CA_CERT_PATH,
            CA_DIR,
            CA_KEY_PATH,
            enable_system_proxy,
        )

        if not CA_CERT_PATH.exists():
            raise RuntimeError("CA not generated - run setup() first")

        # Handle port conflicts: kill any stale process on our port
        self._clear_port()

        # mitmproxy expects its CA files in a specific format in confdir.
        # We copy our CA into the mitmproxy confdir structure, refreshing
        # it whenever the source CA is newer than the copy already there
        # (audit I7 -- see _refresh_mitm_confdir's docstring for why).
        mitmproxy_confdir = CA_DIR / "mitmproxy"
        _refresh_mitm_confdir(CA_CERT_PATH, CA_KEY_PATH, mitmproxy_confdir)

        addon_path = Path(__file__).parent / "mitm_addon.py"
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        log_file = open(APP_DATA_DIR / "browser_proxy.log", "a")  # noqa: SIM115

        # Find mitmdump - prefer the project venv (reliable, avoids py2app
        # PATH contamination on macOS), then PATH, then alongside the running
        # interpreter (covers Windows ``Scripts\mitmdump.exe`` layouts).
        import shutil

        venv_candidates = [
            PROJECT_ROOT / ".venv" / "bin" / "mitmdump",
            PROJECT_ROOT / ".venv" / "Scripts" / "mitmdump.exe",
        ]
        mitmdump_bin = None
        for candidate in venv_candidates:
            if candidate.exists():
                mitmdump_bin = str(candidate)
                break
        if not mitmdump_bin:
            mitmdump_bin = shutil.which("mitmdump")
        if not mitmdump_bin:
            sibling_candidates = [
                Path(sys.executable).parent / "mitmdump",
                Path(sys.executable).parent / "mitmdump.exe",
                Path(sys.executable).parent / "Scripts" / "mitmdump.exe",
            ]
            for candidate in sibling_candidates:
                if candidate.exists():
                    mitmdump_bin = str(candidate)
                    break
        if not mitmdump_bin:
            raise RuntimeError(
                "mitmdump not found on PATH, in the project .venv, or next to "
                "the Python executable. Install the browser proxy dependencies first."
            )

        # Build the subprocess environment + command. On macOS we run inside a
        # py2app bundle that pollutes PYTHONPATH/PYTHONHOME/PATH for children,
        # so we construct a clean env and spawn mitmdump via the venv's python3.
        # On Windows / Linux we inherit os.environ and launch mitmdump directly.
        if is_macos():
            venv_bin = str(PROJECT_ROOT / ".venv" / "bin")
            venv_python = str(PROJECT_ROOT / ".venv" / "bin" / "python3")
            env = {
                "PATH": venv_bin + ":/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
                "HOME": os.environ.get("HOME", ""),
                "USER": os.environ.get("USER", ""),
                "LANG": os.environ.get("LANG", "en_US.UTF-8"),
                "PYTHONPATH": str(PROJECT_ROOT),
                "TERM": "xterm-256color",
                "VIRTUAL_ENV": str(PROJECT_ROOT / ".venv"),
                "HF_HUB_OFFLINE": "1",
            }
            for key in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"):
                if key in os.environ:
                    env[key] = os.environ[key]
            cmd = [
                venv_python,
                str(mitmdump_bin),
                "--listen-port",
                str(self.PROXY_PORT),
                "--set",
                f"confdir={mitmproxy_confdir}",
                "-s",
                str(addon_path),
                "--quiet",
            ]
        else:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(PROJECT_ROOT)
            cmd = [
                str(mitmdump_bin),
                "--listen-port",
                str(self.PROXY_PORT),
                "--set",
                f"confdir={mitmproxy_confdir}",
                "-s",
                str(addon_path),
                "--quiet",
            ]

        self._process = subprocess.Popen(  # noqa: S603
            cmd,
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            **subprocess_group_kwargs(),
        )

        # Wait for proxy to be ready (accept connections on the port).
        # On a cold first-run the addon imports the full detection stack
        # (torch/transformers/etc.), which can take well over 4s -- especially
        # when it races the initial model warmup/GPU benchmark on a constrained
        # machine. Poll generously (up to ~30s) and only fail if mitmdump
        # actually dies; a slow-but-alive process must not be killed prematurely.
        import time

        readiness_timeout_s = 30
        attempts = readiness_timeout_s * 5  # 0.2s per attempt
        hinted = False
        for attempt in range(attempts):
            time.sleep(0.2)
            proc = self._process  # snapshot; stop() may set _process=None concurrently
            if proc is None or proc.poll() is not None:
                log_path = APP_DATA_DIR / "browser_proxy.log"
                err = ""
                try:
                    err = log_path.read_text().split("\n")[-3:]
                    err = "\n".join(err)
                except Exception:  # noqa: S110
                    pass
                self._process = None
                raise RuntimeError(f"mitmdump exited immediately: {err}")
            if is_port_listening(self.PROXY_PORT):
                break
            if not hinted and attempt >= 20:  # ~4s in, still coming up
                hinted = True
                print(
                    "  … browser proxy still starting "
                    "(loading detection models, may take ~30s on first run)",
                    flush=True,
                )
        else:
            # Alive but never bound within the timeout -- now it's a real failure.
            proc = self._process
            if proc is not None:
                proc.terminate()
            self._process = None
            raise RuntimeError(f"mitmdump started but not listening after {readiness_timeout_s}s")

        # Enable system proxy to route LLM traffic through us
        enable_system_proxy(port=self.PROXY_PORT)

        # Verify interception in background (don't block the API response)
        import threading

        threading.Thread(target=self._verify_interception, daemon=True).start()

    def _verify_interception(self) -> None:
        """Verify the proxy is actually intercepting HTTPS traffic.

        Sends a test request through the proxy to confirm it's working.
        Logs a warning if verification fails but doesn't raise.
        """
        import logging
        import urllib.request

        logger = logging.getLogger(__name__)

        try:
            proxy_handler = urllib.request.ProxyHandler(
                {
                    "https": f"http://127.0.0.1:{self.PROXY_PORT}",
                }
            )
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(
                proxy_handler,
                urllib.request.HTTPSHandler(context=ctx),
            )
            req = urllib.request.Request(
                "https://api.openai.com/v1/health",
                method="GET",
            )
            opener.open(req, timeout=3)
            logger.info("Proxy interception verified")
        except urllib.error.HTTPError:
            # Any HTTP error means the proxy IS intercepting (even 403/404)
            logger.info("Proxy interception verified (HTTP error = intercepting)")
        except Exception as e:
            logger.warning(f"Proxy interception verification failed: {e}")

    def _clear_port(self) -> None:
        """Kill any stale process occupying our proxy port."""
        import time

        if not is_port_listening(self.PROXY_PORT):
            return
        if is_windows():
            if self._clear_stale_windows_mitmproxy():
                time.sleep(1)
                if not is_port_listening(self.PROXY_PORT):
                    return
            raise RuntimeError(
                f"Port {self.PROXY_PORT} is already in use. Stop the process "
                "using that port, then try again."
            )
        # macOS and Linux: use lsof to find and kill the listener
        try:
            result = subprocess.run(  # noqa: S603
                ["lsof", "-ti", f":{self.PROXY_PORT}", "-sTCP:LISTEN"],  # noqa: S607
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                for pid_str in result.stdout.strip().split("\n"):
                    pid = int(pid_str.strip())
                    os.kill(pid, signal.SIGTERM)
                time.sleep(1)
        except (ValueError, OSError, subprocess.SubprocessError):
            pass

    def _clear_stale_windows_mitmproxy(self) -> bool:
        """Stop stale Domestique mitmproxy processes left behind on Windows."""
        from domestique_app.services.runtime import is_windows

        if not is_windows():
            return False

        pids = self._find_windows_mitmproxy_pids()
        for pid in pids:
            subprocess.run(  # noqa: S603
                ["taskkill", "/PID", str(pid), "/T", "/F"],  # noqa: S607
                capture_output=True,
                text=True,
            )
        return bool(pids)

    def _find_windows_mitmproxy_pids(self) -> list[int]:
        """Find Windows processes from this checkout that own or target the proxy port."""
        root = str(PROJECT_ROOT).replace("'", "''")
        script = textwrap.dedent(
            f"""
            $root = '{root}'
            $current = $PID
            $listenerPids = @(
                Get-NetTCPConnection -LocalPort {self.PROXY_PORT} -State Listen `
                    -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty OwningProcess -Unique
            )
            Get-CimInstance Win32_Process |
                Where-Object {{
                    $_.ProcessId -ne $current -and
                    $_.CommandLine -and
                    $_.CommandLine.Contains($root) -and
                    ($_.CommandLine.Contains('mitmdump') -or
                        $_.CommandLine.Contains('mitm_addon.py')) -and
                    (($listenerPids -contains $_.ProcessId) -or
                        $_.CommandLine.Contains('--listen-port {self.PROXY_PORT}'))
                }} |
                Select-Object -ExpandProperty ProcessId
            """
        )
        try:
            result = subprocess.run(  # noqa: S603
                ["powershell", "-NoProfile", "-Command", script],  # noqa: S607
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.SubprocessError):
            return []

        pids = []
        for line in result.stdout.splitlines():
            try:
                pids.append(int(line.strip()))
            except ValueError:
                continue
        return sorted(set(pids))

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the browser proxy and disable system proxy settings.

        Args:
            timeout: Seconds to wait for graceful shutdown.
        """
        from domestique_app.services.interceptor import disable_system_proxy

        # Disable system proxy first (so traffic stops flowing to us)
        disable_system_proxy()

        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2)
            self._process = None
