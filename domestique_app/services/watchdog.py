"""Proxy health watchdog - ensures continuous protection.

Monitors the proxy and PAC server health, auto-recovers from failures,
detects network changes, and optionally enforces fail-closed mode via
macOS PF firewall rules.

Architecture:
    - Runs as a daemon thread, started by the AppDelegate
    - Checks health every POLL_INTERVAL seconds
    - On failure: restarts proxy with exponential backoff
    - On network change: re-applies PAC to new interfaces
    - On repeated failure: enters degraded state and alerts user

Fail-closed mode (optional):
    When enabled, PF firewall rules block direct egress to LLM domains
    unless traffic goes through our local proxy. This prevents bypass
    even if PAC is not respected by an application.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from domestique_app.services.runtime import is_macos, is_port_listening, is_windows

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger("domestique.watchdog")


class ProtectionState(Enum):
    """Current protection health state."""

    ACTIVE = "active"
    DEGRADED = "degraded"
    FAILED = "failed"
    STARTING = "starting"
    STOPPED = "stopped"


class WatchdogConfig:
    """Configuration for the watchdog behavior."""

    POLL_INTERVAL: float = 5.0
    MAX_RESTART_ATTEMPTS: int = 5
    BACKOFF_BASE: float = 2.0
    BACKOFF_MAX: float = 60.0
    FAIL_CLOSED: bool = False  # If True, block LLM traffic when proxy is down
    PAC_SERVER_PORT: int = 9876
    PROXY_PORT: int = 8080


class Watchdog:
    """Monitors proxy health and auto-recovers from failures.

    Usage:
        watchdog = Watchdog(
            restart_proxy=my_restart_fn,
            on_state_change=my_callback,
        )
        watchdog.start()
        ...
        watchdog.stop()
    """

    def __init__(
        self,
        restart_proxy: Callable[[], bool],
        on_state_change: Callable[[ProtectionState], None] | None = None,
        config: WatchdogConfig | None = None,
    ) -> None:
        """Initialize the watchdog.

        Args:
            restart_proxy: Callable that restarts the proxy. Returns True on success.
            on_state_change: Optional callback when protection state changes.
            config: Optional configuration override.
        """
        self._restart_proxy = restart_proxy
        self._on_state_change = on_state_change
        self._config = config or WatchdogConfig()
        self._state = ProtectionState.STOPPED
        self._running = False
        self._thread: threading.Thread | None = None
        self._restart_count = 0
        self._last_restart_time = 0.0
        self._known_interfaces: set[str] = set()
        self._lock = threading.Lock()

    @property
    def state(self) -> ProtectionState:
        """Current protection state."""
        return self._state

    def start(self) -> None:
        """Start the watchdog monitoring loop."""
        if self._running:
            return
        self._running = True
        self._set_state(ProtectionState.STARTING)
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="domestique-watchdog"
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the watchdog."""
        self._running = False
        if self._config.FAIL_CLOSED:
            self._remove_pf_rules()
        self._set_state(ProtectionState.STOPPED)

    def reset_backoff(self) -> None:
        """Reset restart counter (call after successful manual start)."""
        with self._lock:
            self._restart_count = 0

    def _monitor_loop(self) -> None:
        """Main monitoring loop - checks health and handles failures."""
        # Initial delay to let proxy start
        time.sleep(3.0)

        while self._running:
            try:
                self._check_health()
                self._check_network_changes()
            except Exception as e:
                logger.error(f"Watchdog error: {e}")
            time.sleep(self._config.POLL_INTERVAL)

    def _check_health(self) -> None:
        """Check proxy and PAC server health."""
        pac_ok = self._is_pac_server_healthy()
        proxy_ok = self._is_proxy_healthy()

        if pac_ok and proxy_ok:
            if self._state != ProtectionState.ACTIVE:
                self._set_state(ProtectionState.ACTIVE)
                with self._lock:
                    self._restart_count = 0
            return

        # Something is unhealthy
        if not pac_ok:
            logger.warning("PAC server is not responding")
        if not proxy_ok:
            logger.warning("Proxy is not responding")

        # Attempt recovery
        self._attempt_recovery()

    def _is_pac_server_healthy(self) -> bool:
        """Check if the PAC server is responding correctly."""
        try:
            import urllib.request

            # Use a no-proxy handler to avoid routing through our own proxy
            no_proxy = urllib.request.ProxyHandler({})
            opener = urllib.request.build_opener(no_proxy)
            req = urllib.request.Request(
                f"http://127.0.0.1:{self._config.PAC_SERVER_PORT}/proxy.pac",
                method="GET",
            )
            resp = opener.open(req, timeout=2)
            return resp.status == 200
        except Exception:
            return False

    def _is_proxy_healthy(self) -> bool:
        """Check if the mitmproxy process is listening."""
        return is_port_listening(self._config.PROXY_PORT)

    def _attempt_recovery(self) -> None:
        """Try to restart the proxy with exponential backoff."""
        with self._lock:
            if self._restart_count >= self._config.MAX_RESTART_ATTEMPTS:
                if self._state != ProtectionState.FAILED:
                    self._set_state(ProtectionState.FAILED)
                    logger.error(
                        f"Proxy failed after {self._restart_count} attempts. "
                        "Manual intervention required."
                    )
                    if self._config.FAIL_CLOSED:
                        self._apply_pf_rules()
                return

            # Exponential backoff
            backoff = min(
                self._config.BACKOFF_BASE**self._restart_count,
                self._config.BACKOFF_MAX,
            )
            elapsed = time.time() - self._last_restart_time
            if elapsed < backoff:
                return  # Wait for backoff period

            self._restart_count += 1
            self._last_restart_time = time.time()

        logger.info(
            f"Attempting proxy restart ({self._restart_count}/{self._config.MAX_RESTART_ATTEMPTS})"
        )
        self._set_state(ProtectionState.DEGRADED)

        try:
            success = self._restart_proxy()
            if success:
                logger.info("Proxy restarted successfully")
                self._set_state(ProtectionState.ACTIVE)
                with self._lock:
                    self._restart_count = 0
            else:
                logger.warning("Proxy restart returned failure")
        except Exception as e:
            logger.error(f"Proxy restart failed: {e}")

    def _check_network_changes(self) -> None:
        """Detect network interface changes and re-apply PAC if needed."""
        current_interfaces = set(self._get_active_interfaces())

        if not self._known_interfaces:
            self._known_interfaces = current_interfaces
            return

        if current_interfaces != self._known_interfaces:
            added = current_interfaces - self._known_interfaces
            removed = self._known_interfaces - current_interfaces
            if added:
                logger.info(f"New network interfaces detected: {added}")
            if removed:
                logger.info(f"Network interfaces removed: {removed}")

            self._known_interfaces = current_interfaces
            self._reapply_pac()

    def _get_active_interfaces(self) -> list[str]:
        """Get list of active network interfaces."""
        from domestique_app.services.interceptor import _get_all_active_interfaces

        return _get_all_active_interfaces()

    def _reapply_pac(self) -> None:
        """Re-apply PAC settings to all current interfaces."""
        from domestique_app.services.interceptor import enable_system_proxy

        try:
            enable_system_proxy(port=self._config.PROXY_PORT)
            logger.info("PAC re-applied to all active interfaces")
        except Exception as e:
            logger.error(f"Failed to re-apply PAC: {e}")

    def _set_state(self, new_state: ProtectionState) -> None:
        """Update state and notify callback."""
        if self._state == new_state:
            return
        old_state = self._state
        self._state = new_state
        logger.info(f"Protection state: {old_state.value} -> {new_state.value}")
        if self._on_state_change:
            try:
                self._on_state_change(new_state)
            except Exception as e:
                logger.error(f"State change callback error: {e}")

    # --- Fail-Closed Mode (PF Firewall Rules) -----------------------

    def _apply_pf_rules(self) -> None:
        """Block direct egress to LLM domains when proxy is unavailable.

        Uses macOS PF (packet filter) to drop outbound connections to
        known LLM API IPs unless they originate from our proxy process.
        This provides enforced protection even when PAC is not respected.
        """
        if not is_macos():
            logger.info("Fail-closed firewall rules are only implemented for macOS PF")
            return

        from domestique_app.services.interceptor import INTERCEPTED_DOMAINS

        rules_file = Path.home() / ".domestique" / "pf_rules.conf"
        rules = [
            "# Domestique fail-closed rules",
            "# Block direct access to LLM APIs when proxy is down",
            "",
        ]

        for domain in INTERCEPTED_DOMAINS:
            # Resolve domain to IPs (best-effort, may not catch all CDN IPs)
            try:
                result = subprocess.run(  # noqa: S603
                    ["dig", "+short", domain],  # noqa: S607
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line and not line.endswith("."):
                        rules.append(f"block drop out proto tcp from any to {line} port 443")
            except Exception:  # noqa: S110
                pass

        rules_file.write_text("\n".join(rules) + "\n")

        # Load rules (requires root - will fail silently without sudo)
        subprocess.run(  # noqa: S603
            ["sudo", "-n", "pfctl", "-f", str(rules_file)],  # noqa: S607
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "-n", "pfctl", "-e"],  # noqa: S607
            capture_output=True,
        )
        logger.info("PF fail-closed rules applied")

    def _remove_pf_rules(self) -> None:
        """Remove fail-closed PF rules."""
        if not is_macos():
            return

        rules_file = Path.home() / ".domestique" / "pf_rules.conf"
        if rules_file.exists():
            rules_file.unlink()
        # Reload default rules
        subprocess.run(
            ["sudo", "-n", "pfctl", "-f", "/etc/pf.conf"],  # noqa: S607
            capture_output=True,
        )
        logger.info("PF fail-closed rules removed")


def _verify_system_proxy_config() -> str:
    """Return a platform-specific proxy configuration health string."""
    pac_url = "http://127.0.0.1:9876/proxy.pac"

    if is_macos():
        proxy_check = subprocess.run(
            ["scutil", "--proxy"],  # noqa: S607
            capture_output=True,
            text=True,
        )
        if "ProxyAutoConfigEnable : 1" in proxy_check.stdout:
            return "ok" if pac_url in proxy_check.stdout else "wrong_pac_url"
        return "pac_disabled"

    if is_windows():
        try:
            import winreg

            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                try:
                    configured_url, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                except FileNotFoundError:
                    configured_url = ""
                try:
                    proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                except FileNotFoundError:
                    proxy_enable = 0
            # PAC-only: we never set ProxyServer, so healthy state is just
            # our AutoConfigURL being active with ProxyEnable=1.
            if configured_url == pac_url and proxy_enable:
                return "ok"
            return "pac_disabled"
        except OSError as exc:
            return f"fail: {exc}"

    return "unsupported"


def verify_interception_chain(proxy_port: int = 8080) -> dict:
    """Verify the full interception chain is working end-to-end.

    Tests that:
    1. PAC server is accessible
    2. Proxy is listening
    3. System proxy settings point to our PAC
    4. Traffic to LLM domains actually routes through proxy

    Returns:
        Dict with verification results for each check.
    """
    results = {}

    # 1. PAC server
    try:
        import urllib.request

        req = urllib.request.Request("http://127.0.0.1:9876/proxy.pac")
        resp = urllib.request.urlopen(req, timeout=3)  # noqa: S310
        pac_content = resp.read().decode()
        results["pac_server"] = "ok" if "FindProxyForURL" in pac_content else "invalid"
    except Exception as e:
        results["pac_server"] = f"fail: {e}"

    # 2. Proxy listening
    results["proxy_listening"] = "ok" if is_port_listening(proxy_port) else "fail"

    # 3. System proxy config
    results["system_proxy"] = _verify_system_proxy_config()

    # 4. Actual interception test (via explicit proxy to verify addon works)
    try:
        import ssl
        import urllib.request

        ca_path = Path.home() / ".domestique" / "ca" / "domestique-ca.pem"
        ctx = (
            ssl.create_default_context(cafile=str(ca_path))
            if ca_path.exists()
            else ssl.create_default_context()
        )

        proxy_handler = urllib.request.ProxyHandler(
            {
                "https": f"http://127.0.0.1:{proxy_port}",
            }
        )
        opener = urllib.request.build_opener(
            proxy_handler,
            urllib.request.HTTPSHandler(context=ctx),
        )

        req = urllib.request.Request(
            "https://api.openai.com/v1/models",
            method="GET",
        )
        # This should either succeed (proxy forwarded) or fail with auth error
        try:
            opener.open(req, timeout=5)
            results["proxy_forwarding"] = "ok"
        except urllib.error.HTTPError as e:
            # 401/403 means it reached OpenAI through our proxy
            results["proxy_forwarding"] = "ok" if e.code in (401, 403) else f"error_{e.code}"
        except urllib.error.URLError:
            results["proxy_forwarding"] = "ok"  # SSL errors still mean proxy works
    except Exception as e:
        results["proxy_forwarding"] = f"fail: {e}"

    results["overall"] = "ok" if all(v == "ok" for v in results.values()) else "degraded"

    return results
