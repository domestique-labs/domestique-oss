# Domestique Codebase Context

Last updated: 2026-05-26

## What This Project Is

Domestique is a Python LLM data-loss-prevention proxy. It has two related surfaces:

- `domestique/`: the core FastAPI inspection proxy, detector registry, policy engine, audit logging, SDK helpers, and upstream forwarding.
- `domestique_app/`: the desktop control app, local dashboard API, dashboard HTML, proxy lifecycle management, browser HTTPS interception, benchmark runner, and platform integration.

The original desktop app was macOS-first. It imported AppKit at module import time, used LaunchAgents, `networksetup`, `security`, `lsof`, `scutil`, and PF firewall rules directly. That made `python -m domestique_app` fail immediately on Windows with `ModuleNotFoundError: No module named 'AppKit'`.

## Important Entry Points

- `python -m domestique_app`: launches the desktop app. It now auto-selects native AppKit mode on macOS and portable browser-dashboard mode on Windows/Linux.
- `python -m domestique_app --mode portable`: forces the portable dashboard mode on any OS.
- `python -m domestique_app --no-browser`: starts the local dashboard API without opening a browser.
- `run.ps1`: PowerShell wrapper for Windows.
- `run.bat`: Windows launcher for Command Prompt, Explorer, and double-click use.
- `run.sh`: shell wrapper for macOS/Linux.
- `domestique.app:create_app`: FastAPI app factory used by the API inspection proxy.

## Runtime Architecture

1. `domestique_app.main` loads persisted config via `ConfigStore`.
2. `domestique_app.server.api.start_api_server()` starts a localhost API on `127.0.0.1:9876`.
3. The dashboard at `domestique_app/assets/dashboard.html` calls that API.
4. `ProxyService` starts the API proxy with `uvicorn domestique.app:create_app --factory`.
5. `BrowserProxyService` starts `mitmdump` with `domestique_app/services/mitm_addon.py`, generates a PAC file, installs/trusts a local CA where supported, and points the OS proxy at the local MITM proxy.

## Configuration And Data

- App config: `~/.domestique/config.json`
- Firewall logs: `~/.domestique/firewall.log`
- Browser proxy logs: `~/.domestique/browser_proxy.log`
- Browser stats: `~/.domestique/browser_stats.json`
- Browser request log: `~/.domestique/request_log.jsonl`
- Raw prompt decision trace: `~/.domestique/debug_trace.jsonl`
- Local CA: `~/.domestique/ca/`
- PAC file: `~/.domestique/proxy.pac`

The path is intentionally simple and works on Windows, macOS, and Linux. A future polish pass could move this to native per-OS app-data locations.

## Debugging Request Decisions

The app now writes two local request trails:

- `~/.domestique/request_log.jsonl`: compact browser-interception log shown in the dashboard. For inspected LLM requests it includes the action, reasons, preview, and full sent prompt.
- `~/.domestique/debug_trace.jsonl`: raw decision trace for both the FastAPI proxy and browser MITM proxy. It records passed, allowed, redacted, blocked, approved, invalid JSON, and no-content cases, including raw prompts, redacted prompts when applicable, detector findings, latency, endpoint, host, method, model, and request id.

The dashboard API also exposes the raw trace locally:

```powershell
Invoke-RestMethod "http://127.0.0.1:9876/api/debug-trace?limit=20"
Invoke-RestMethod "http://127.0.0.1:9876/api/debug-trace?filter=blocked"
```

These files intentionally contain raw prompt text and may contain secrets or PII. Do not share or commit them.

## Windows Runbook

From the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m domestique_app
```

To run without opening a browser:

```powershell
.\run.ps1 -NoBrowser
```

If Windows asks which app should open `run.ps1`, you are launching it as a
document instead of through PowerShell. Use the batch wrapper instead:

```bat
run.bat
run.bat -NoBrowser
```

To install optional browser interception and file-scanning dependencies:

```powershell
python -m pip install -e ".[desktop]"
```

Browser interception on Windows uses current-user certificate/proxy settings:

- CA trust: `certutil -user -addstore Root <cert>`
- Proxy settings: `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
- Previous proxy values are backed up to `~/.domestique/windows_proxy_backup.json` and restored when interception is disabled.

## Cross-Platform Changes Made

- `domestique_app/main.py` no longer imports AppKit at module import time.
- `domestique_app/main.py` now has native and portable launch modes.
- `domestique_app/__main__.py` exposes a small CLI: `--mode`, `--api-port`, and `--no-browser`.
- `run.ps1` was added for Windows.
- `run.bat` was added for Command Prompt, Explorer, and double-click launches.
- `run.sh` now delegates to `python -m domestique_app` instead of sourcing a hard-coded Unix venv path.
- `domestique_app/services/runtime.py` centralizes OS checks, port checks, venv interpreter discovery, and child-process group kwargs.
- `domestique_app/services/notifications.py` provides best-effort macOS/Windows notifications with no required dependency.
- `domestique_app/services/proxy.py` uses socket-based port readiness checks and Windows-safe `subprocess.Popen` kwargs.
- `domestique_app/services/interceptor.py` now has Windows CA trust and Windows current-user proxy support, while preserving guarded macOS behavior.
- `domestique_app/services/watchdog.py` uses socket-based health checks and avoids macOS-only PF/scutil logic off macOS.
- `domestique_app/services/autolaunch.py` supports Windows Run key auto-launch while preserving macOS LaunchAgent behavior.
- `pyproject.toml` now separates optional extras for `browser-proxy`, `file-scanning`, `macos-native`, and `desktop`.
- `litellm` is constrained to `>=1.80,<1.81` because the newest 1.x wheel currently fails to install on this Windows path due to a long packaged fixture path.
- `pydantic` is constrained to `<2.12` so the optional `mitmproxy>=12,<13` stack can share a compatible `typing-extensions` range with the core app.

## Known Platform Boundaries

- Native AppKit menu bar/window mode is still macOS-only by design.
- Windows and Linux use the portable browser-dashboard mode.
- Browser interception requires `mitmproxy` and OpenSSL. If OpenSSL is not on PATH, CA generation will explain the missing requirement.
- OCR via Apple Vision remains macOS-only; other platforms fall back to Tesseract if `pytesseract`, Pillow, and the external Tesseract binary are installed.
- Linux system proxy integration is currently a safe no-op. The API/dashboard still runs.

## Useful Verification Commands

```powershell
python -m compileall domestique_app domestique
python -m domestique_app --help
python -m domestique_app --no-browser
```

Once `python -m domestique_app --no-browser` is running, verify:

```powershell
Invoke-RestMethod http://127.0.0.1:9876/api/status
```

Expected initial status has all proxies stopped:

```json
{
  "proxy_running": false,
  "proxy_pid": null,
  "browser_proxy_running": false,
  "browser_proxy_setup": false
}
```

## Troubleshooting Ports

If startup reports `Port 8080 is already in use`, check the listener:

```powershell
Get-NetTCPConnection -LocalPort 8080 -State Listen
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'mitmdump|mitm_addon' }
```

The Windows browser-proxy startup now attempts to clean up stale Domestique-owned
`mitmdump` processes automatically before failing.
