"""Best-effort desktop notifications."""

from __future__ import annotations

import subprocess

from app.services.runtime import is_macos, is_windows


def notify(title: str, message: str) -> None:
    """Send a non-critical local notification when the platform supports it."""
    if is_macos():
        _notify_macos(title, message)
    elif is_windows():
        _notify_windows(title, message)


def _notify_macos(title: str, message: str) -> None:
    script = f'display notification "{_escape_osascript(message)}" with title "{_escape_osascript(title)}"'
    subprocess.Popen(
        ["osascript", "-e", script],
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
    subprocess.Popen(
        ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _escape_osascript(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _escape_powershell(value: str) -> str:
    return value.replace("'", "''")
