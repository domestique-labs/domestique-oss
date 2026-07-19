"""Best-effort desktop notifications."""

from __future__ import annotations

import logging
import subprocess
import threading
from typing import TYPE_CHECKING

from domestique_app.services.runtime import is_macos, is_windows

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger("domestique.notifications")


def notify(title: str, message: str) -> None:
    """Send a non-critical local notification when the platform supports it."""
    if is_macos():
        _notify_macos(title, message)
    elif is_windows():
        _notify_windows(title, message)


def _notify_macos(title: str, message: str) -> None:
    script = f'display notification "{_escape_osascript(message)}" with title "{_escape_osascript(title)}"'  # noqa: E501
    subprocess.Popen(  # noqa: S603
        ["osascript", "-e", script],  # noqa: S607
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _notify_windows(title: str, message: str) -> None:
    # Windows toast APIs require app registration. Keep this dependency-free by
    # using a hidden PowerShell balloon tip when available and otherwise no-op.
    ps = (
        "Add-Type -AssemblyName System.Windows.Forms; "
        "$n = New-Object System.Windows.Forms.NotifyIcon; "
        "$n.Icon = [System.Drawing.SystemIcons]::Information; "
        "$n.Visible = $true; "
        f"$n.ShowBalloonTip(5000, '{_escape_powershell(title)}', "
        f"'{_escape_powershell(message)}', "
        "[System.Windows.Forms.ToolTipIcon]::Info); "
        "Start-Sleep -Seconds 6; "
        "$n.Dispose()"
    )
    subprocess.Popen(  # noqa: S603
        ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],  # noqa: S607
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _escape_osascript(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _escape_powershell(value: str) -> str:
    return value.replace("'", "''")


class NotificationCoalescer:
    """Coalesces desktop "blocked" notifications per host over a short window.

    A single user action in the browser (e.g. sending a ChatGPT message) can
    trigger many separate proxied requests - the message itself plus
    background autocomplete/title-generation calls. If each blocked request
    fired its own toast, one prompt could pop up half a dozen notifications.

    Instead, the first blocked request to a host opens a coalescing window.
    Every blocked request to that same host during the window is counted
    silently. When the window elapses, exactly one notification is emitted
    summarizing how many requests to that host were blocked (the specific
    category/reason is intentionally omitted from the toast for privacy -
    only the host and the count are shown).
    """

    def __init__(
        self,
        window_seconds: float = 5.0,
        notify_fn: Callable[[str, str], None] = notify,
        timer_factory: Callable[..., threading.Timer] = threading.Timer,
    ) -> None:
        self._window_seconds = window_seconds
        self._notify_fn = notify_fn
        self._timer_factory = timer_factory
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}

    def record_block(self, host: str) -> None:
        """Record that a request to `host` was blocked.

        Starts a new coalescing window for `host` if one isn't already
        open; otherwise just increments the pending count. Non-fatal by
        design - callers should not need to guard this further, but it
        also never raises for scheduling failures.
        """
        with self._lock:
            is_new_window = host not in self._counts
            self._counts[host] = self._counts.get(host, 0) + 1
            if not is_new_window:
                return
        try:
            timer = self._timer_factory(self._window_seconds, self._flush, args=(host,))
            timer.daemon = True
            timer.start()
        except Exception:
            # Scheduling failed - flush immediately rather than losing the
            # notification entirely.
            logger.debug("Failed to schedule coalesced notification", exc_info=True)
            self._flush(host)

    def _flush(self, host: str) -> None:
        with self._lock:
            count = self._counts.pop(host, 0)
        if count <= 0:
            return
        message = (
            f"Blocked a leak to {host}" if count == 1 else f"Blocked {count} requests to {host}"
        )
        try:
            self._notify_fn("Domestique", message)
        except Exception:
            # A notification failure must never affect the block itself.
            logger.debug("Desktop notification failed", exc_info=True)


_default_coalescer: NotificationCoalescer | None = None
_default_coalescer_lock = threading.Lock()


def get_default_coalescer() -> NotificationCoalescer:
    """Return the process-wide coalescer used by notify_block()."""
    global _default_coalescer
    if _default_coalescer is None:
        with _default_coalescer_lock:
            if _default_coalescer is None:
                _default_coalescer = NotificationCoalescer()
    return _default_coalescer


def notify_block(host: str) -> None:
    """Record a blocked request for a coalesced desktop notification.

    This is the entry point block-path callers should use instead of
    calling notify() directly, so bursts of blocks (e.g. one prompt
    fanning out into several inspected requests) collapse into a single
    toast. Never raises.
    """
    try:
        get_default_coalescer().record_block(host)
    except Exception:
        logger.debug("notify_block failed", exc_info=True)
