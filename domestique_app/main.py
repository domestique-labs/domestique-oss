"""Application launcher for native and portable desktop modes.

On macOS, Domestique uses the existing AppKit shell. On Windows and Linux, it
starts the same local API server and opens the dashboard in the default browser.
"""

from __future__ import annotations

import argparse
import atexit
import contextlib
import signal
import sys
import time
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

from domestique_app.config.store import ConfigStore
from domestique_app.server.api import start_api_server
from domestique.branding import LOGO, supports_unicode

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import FrameType
    from urllib.request import OpenerDirector

    from app.services.tray import SystemTray

DASHBOARD_PATH = Path(__file__).parent / "assets" / "dashboard.html"
DEFAULT_API_PORT = 9876


def _render_app_banner(api_port: int) -> str:
    """Compose the ``python -m domestique_app`` splash banner (logo + status block).

    Mirrors the ``domestique start`` banner in ``domestique/cli.py`` but with
    dashboard copy. Unicode glyphs are gated on :func:`supports_unicode` with
    ASCII fallbacks so a cp1252 console renders cleanly.
    """
    api_url = f"http://127.0.0.1:{api_port}"
    if supports_unicode():
        rule, active, check = "─" * 60, "►", "✔"
    else:
        rule, active, check = "-" * 60, ">", "+"
    return (
        LOGO
        + "  [OSS DASHBOARD]\n"
        + rule
        + "\n"
        + f"  [{active}] Domestique API running at {api_url}\n"
        + f"  [{check}] Dashboard: {api_url}/\n"
        + rule
        + "\n"
        + "  Press Ctrl+C to stop.\n"
    )


def launch(
    *,
    mode: str = "auto",
    api_port: int = DEFAULT_API_PORT,
    open_dashboard: bool = True,
) -> None:
    """Launch Domestique.

    Args:
        mode: ``auto``, ``native``, or ``portable``. ``auto`` uses the native
            AppKit UI on macOS and the browser dashboard elsewhere.
        api_port: Local dashboard API port.
        open_dashboard: Whether to open the dashboard after startup.
    """
    selected_mode = _resolve_mode(mode)
    if selected_mode == "native":
        _launch_macos(api_port=api_port)
        return

    _launch_portable(api_port=api_port, open_dashboard=open_dashboard)


def _configure_console_utf8() -> None:
    """Make console output UTF-8 safe on every platform.

    Windows consoles default to cp1252 and raise UnicodeEncodeError on the status
    glyphs Domestique prints (e.g. the certificate-setup messages). The macOS launch
    path already did this; doing it here in ``main()`` also covers the portable
    Windows/Linux path, which otherwise crashes on first-run output.
    """
    import os

    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            with contextlib.suppress(Exception):
                stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> None:
    """CLI entry point used by ``python -m domestique_app``."""
    _configure_console_utf8()
    parser = argparse.ArgumentParser(description="Launch Domestique")
    parser.add_argument(
        "--mode",
        choices=("auto", "native", "portable"),
        default="auto",
        help="Startup mode. Defaults to native on macOS and portable elsewhere.",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=DEFAULT_API_PORT,
        help=f"Dashboard API port. Defaults to {DEFAULT_API_PORT}.",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Start the local API without opening the dashboard.",
    )
    args = parser.parse_args(argv)
    try:
        launch(
            mode=args.mode,
            api_port=args.api_port,
            open_dashboard=not args.no_browser,
        )
    except RuntimeError as exc:
        # Mode-resolution errors (native off-macOS, native without pyobjc)
        # are user-facing configuration problems, not bugs — no traceback.
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _native_available() -> bool:
    """Whether the optional AppKit (pyobjc) dependency is importable.

    Note: a truthy spec means the module is *findable*, not that a later
    import cannot fail (e.g. a broken pyobjc install) — that narrower case
    still raises at import time, exactly as it did before this probe.
    """
    import importlib.util

    try:
        return importlib.util.find_spec("AppKit") is not None
    except (ImportError, ValueError):
        # find_spec itself can raise in edge states (module stubbed into
        # sys.modules with __spec__ unset, broken meta-path finder). The
        # probe exists for graceful degradation, so degrade.
        return False


def _resolve_mode(mode: str) -> str:
    if mode == "auto":
        if sys.platform != "darwin":
            return "portable"
        if _native_available():
            return "native"
        print(
            "AppKit (pyobjc) not installed — falling back to portable mode.\n"
            '  For the native menu-bar app: pip install -e ".[macos-native]"'
        )
        return "portable"
    if mode == "native":
        if sys.platform != "darwin":
            raise RuntimeError("Native mode is only available on macOS.")
        if not _native_available():
            raise RuntimeError(
                "Native mode requires AppKit (pyobjc). "
                'Install with: pip install -e ".[macos-native]"'
            )
    return mode


def _launch_macos(*, api_port: int) -> None:
    """Launch the AppKit desktop UI.

    Imports are intentionally lazy so Windows and Linux can import domestique_app.main.
    """
    import os
    import socket

    from AppKit import (
        NSApplication,
        NSApplicationActivationPolicyAccessory,
        NSApplicationActivationPolicyRegular,
        NSImage,
    )
    from Foundation import NSBundle, NSProcessInfo

    from domestique_app.native.app_delegate import AppDelegate

    # Fix ASCII codec errors in py2app bundle.
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream in (sys.stdout, sys.stderr):
        if stream and hasattr(stream, "reconfigure"):
            with contextlib.suppress(Exception):
                stream.reconfigure(encoding="utf-8", errors="replace")

    print(_render_app_banner(api_port), flush=True)

    ConfigStore.load()
    start_api_server(port=api_port)

    # Wait for the API server to accept connections before constructing the UI.
    for _ in range(10):
        try:
            sock = socket.create_connection(("127.0.0.1", api_port), timeout=1)
            sock.close()
            break
        except OSError:
            time.sleep(0.1)

    NSProcessInfo.processInfo().setProcessName_("Domestique")

    ns_app = NSApplication.sharedApplication()
    ns_app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)

    bundle = NSBundle.mainBundle()
    info = bundle.localizedInfoDictionary() or bundle.infoDictionary()
    if info:
        info["CFBundleName"] = "Domestique"
        info["CFBundleDisplayName"] = "Domestique"
        info["CFBundleIdentifier"] = "com.domestique.app"

    icon_path = Path(__file__).parent / "assets" / "images" / "logo-512.png"
    if not icon_path.exists():
        icon_path = Path(__file__).parent / "assets" / "icon.png"
    icon = None
    if icon_path.exists():
        icon = NSImage.alloc().initWithContentsOfFile_(str(icon_path))
        icon.setName_("AppIcon")

    # Set icon before switching to Regular policy
    if icon:
        ns_app.setApplicationIconImage_(icon)

    delegate = AppDelegate.new()
    ns_app.setDelegate_(delegate)

    ns_app.setActivationPolicy_(NSApplicationActivationPolicyRegular)

    # Re-apply icon after the activation-policy switch (it can clear the icon).
    if icon:
        ns_app.setApplicationIconImage_(icon)

    ns_app.activateIgnoringOtherApps_(True)
    ns_app.run()


def _ensure_cert_generated_portable() -> None:
    """Generate + trust the CA before the portable dashboard opens.

    Portable mode (Windows/Linux) has no equivalent of the macOS
    ``AppDelegate._ensure_cert_trusted()`` bootstrap step, so a fresh
    install's CA was never generated and the dashboard's cert-install gate
    had nothing to install (audit finding C1). Fixing generation alone
    left a twin gap (audit finding C7): the CA was created but never
    installed into the OS trust store, so every intercepted HTTPS site
    threw ``ERR_CERT_AUTHORITY_INVALID``. This function now mirrors
    ``AppDelegate._ensure_cert_trusted()`` end-to-end: generate, then
    trust.

    ``BrowserProxyService.setup()`` -> ``interceptor.generate_ca()`` is
    idempotent: it returns immediately without touching the files if a CA
    already exists (see ``generate_ca()``'s early-return when
    ``CA_CERT_PATH``/``CA_KEY_PATH`` are both present), so calling this
    unconditionally on every launch never regenerates or overwrites an
    existing CA.

    Trust is likewise gated on ``cert_manager.is_cert_trusted()`` so an
    already-trusted CA is never redundantly reinstalled. On Windows this
    is ``certutil -user -addstore Root`` -- scoped to
    ``HKCU\\Software\\Microsoft\\SystemCertificates``, so no admin
    privileges are needed, exactly like macOS's user-keychain trust
    import. Trust failures are logged but never fatal: startup must keep
    going, and the dashboard's own "Install Certificate" button /
    ``fix-cert.ps1``/``fix-cert.sh`` remain available as a fallback.

    Linux has no automatic trust-store implementation at all yet (that's
    audit finding C2, out of scope here): ``cert_manager.install_and_trust()``
    only handles ``darwin``/``win32`` and returns ``False`` for anything
    else without attempting anything, and ``cert_manager.is_cert_trusted()``
    hardcodes ``True`` for Linux as a "best effort" stand-in rather than a
    real check. Left alone, that combination would make this function look
    like a no-op success on Linux while nothing was actually trusted. We
    special-case Linux below to print an honest "trust not verified /
    manual step needed" message instead of silently claiming success.
    """
    try:
        from domestique_app.server.api import get_browser_proxy_service

        svc = get_browser_proxy_service()
        if not svc.is_setup:
            print("▶ First-time setup: generating certificate authority...")
            svc.setup()
    except Exception as exc:
        print(f"  ⚠ Certificate setup failed: {exc}")
        return

    try:
        from domestique_app.services import cert_manager

        if not cert_manager.is_cert_trusted():
            print(
                "▶ Trusting certificate authority "
                "(adds to OS trust store; no admin needed on Windows)..."
            )
            if cert_manager.install_and_trust():
                print(
                    "  ✓ Certificate trusted — HTTPS interception will work without browser warnings."  # noqa: E501
                )
            elif sys.platform.startswith("linux"):
                print("  ⚠ Automatic trust isn't implemented on Linux yet (manual trust needed).")
                print("    Browsers will show cert warnings for intercepted sites until you run")
                print("    fix-cert.sh, or install the CA into your browser/NSS store manually.")
            else:
                print("  ⚠ Certificate trust did not complete automatically.")
                print("    Use the dashboard's 'Install Certificate' button, or run")
                print("    fix-cert.ps1 / fix-cert.sh, to finish setup manually.")
        elif sys.platform.startswith("linux"):
            # is_cert_trusted() is a hardcoded best-effort True on Linux --
            # it does not actually check any trust store (audit C2). Make
            # that limitation visible instead of silently implying the CA
            # is verified-trusted the same way it is on Windows/macOS.
            print("  i Certificate generated. Linux trust verification is best-effort only;")
            print("    if browsers show cert warnings, run fix-cert.sh (manual trust needed).")
    except Exception as exc:
        # Trust failures must never crash startup -- the dashboard's own
        # cert gate / Install Certificate button remains a working fallback.
        print(f"  ⚠ Certificate trust step failed: {exc}")


def _launch_portable(*, api_port: int, open_dashboard: bool) -> NoReturn:
    """Launch the portable browser-dashboard experience."""
    ConfigStore.load()
    server = start_api_server(port=api_port)
    atexit.register(_cleanup_services)

    # Portable mode has no AppKit warmup path; mark startup complete so the
    # dashboard exits its "starting" state instead of spinning forever.
    import domestique_app.server.api as _api

    _api._startup_state["phase"] = "ready"
    _api._startup_state["detail"] = ""

    # Splash banner FIRST, as one atomic print: the background workers below
    # (Ollama bootstrap in particular) write to the same terminal — the
    # first-run `ollama pull` progress bar owns it for minutes — so the
    # banner must be fully flushed before any of them start.
    print(_render_app_banner(api_port), flush=True)

    # First-time setup: generate the CA (BEFORE opening the browser). This
    # mirrors AppDelegate._ensure_cert_trusted() on macOS. Without this,
    # portable mode (Windows/Linux) never generates a CA on a fresh install,
    # so the dashboard's cert-install gate has nothing to install and the
    # user is stuck at the gate forever.
    _ensure_cert_generated_portable()

    # Ensure Ollama is available and the configured model is ready.
    import threading

    threading.Thread(target=_ensure_ollama, daemon=True).start()

    # Auto-start proxies that were enabled in the saved config.
    threading.Thread(target=_auto_start_proxies, daemon=True).start()

    if open_dashboard:
        webbrowser.open(f"http://127.0.0.1:{api_port}/")

    # System tray icon (portable mode, any OS) — mirrors the macOS StatusBar.
    tray = _start_system_tray(api_port)

    def _shutdown(_signum: int | None = None, _frame: FrameType | None = None) -> None:
        if tray:
            tray.stop()
        _cleanup_services()
        server.shutdown()
        server.server_close()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _shutdown)

    # Keep the tray icon state in sync with proxy status.
    if tray:
        threading.Thread(
            target=_tray_sync_loop,
            args=(tray,),
            daemon=True,
        ).start()

    try:
        while True:
            time.sleep(3600)
    finally:
        if tray:
            tray.stop()
        _cleanup_services()
        server.shutdown()
        server.server_close()


def _detect_accelerator() -> dict:
    """Detect the best available accelerator for local LLM inference.

    Returns a dict with keys:
        type: "apple_silicon" | "cuda" | "rocm" | "cpu"
        name: Human-readable name (e.g. "Apple M3 Pro", "NVIDIA RTX 4090")
        vram_gb: Available VRAM in GB (0 for CPU, unified RAM for Apple Silicon)
        env: Dict of environment variables to set for optimal Ollama performance
    """
    import platform
    import shutil
    import subprocess

    # Apple Silicon — uses Metal via Ollama, MLX for specific model variants
    if platform.system() == "Darwin" and platform.machine() in ("arm64", "aarch64"):
        try:
            r = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=5,
            )
            ram_gb = round(int(r.stdout.strip()) / (1024**3), 1)
        except Exception:
            ram_gb = 8.0
        chip = "Apple Silicon"
        try:
            r = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=5,
            )
            chip = r.stdout.strip() or chip
        except Exception:  # noqa: S110
            pass
        return {
            "type": "apple_silicon",
            "name": chip,
            "vram_gb": ram_gb,  # Unified memory
            "env": {
                "OLLAMA_FLASH_ATTENTION": "1",
                "OLLAMA_KEEP_ALIVE": "30m",
            },
        }

    # NVIDIA CUDA GPU
    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi:
        try:
            r = subprocess.run(  # noqa: S603
                [
                    nvidia_smi,
                    "--query-gpu=name,memory.total,memory.free",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            line = r.stdout.strip().split("\n")[0]
            parts = [s.strip() for s in line.split(",")]
            name, total_mib, free_mib = parts[0], int(parts[1]), int(parts[2])
            return {
                "type": "cuda",
                "name": name,
                "vram_gb": round(total_mib / 1024, 1),
                "free_vram_gb": round(free_mib / 1024, 1),
                "env": {
                    "OLLAMA_FLASH_ATTENTION": "1",
                    "OLLAMA_KEEP_ALIVE": "30m",
                },
            }
        except Exception:  # noqa: S110
            pass

    # AMD ROCm GPU
    rocm_smi = shutil.which("rocm-smi")
    if rocm_smi:
        try:
            r = subprocess.run(  # noqa: S603
                [rocm_smi, "--showmeminfo", "vram", "--csv"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in r.stdout.strip().splitlines()[1:]:
                parts = line.split(",")
                if len(parts) >= 2:
                    total_bytes = int(parts[0])
                    return {
                        "type": "rocm",
                        "name": "AMD GPU (ROCm)",
                        "vram_gb": round(total_bytes / (1024**3), 1),
                        "env": {
                            "OLLAMA_FLASH_ATTENTION": "1",
                            "OLLAMA_KEEP_ALIVE": "30m",
                        },
                    }
        except Exception:  # noqa: S110
            pass

    # CPU fallback
    return {
        "type": "cpu",
        "name": platform.processor() or "CPU",
        "vram_gb": 0,
        "env": {
            "OLLAMA_KEEP_ALIVE": "30m",
        },
    }


def _wait_for_command(
    name: str,
    attempts: int = 5,
    delay_seconds: float = 1.0,
    which: Callable[[str], str | None] | None = None,
    sleep: Callable[[float], object] = time.sleep,
) -> str | None:
    """Poll ``which(name)`` a few times, sleeping between attempts.

    Windows' winget can return before the installed binary's directory is
    fully registered/visible on ``PATH``, so a single immediate check can
    give a false negative. This gives the OS a few seconds to catch up
    before we declare the install a failure. Returns the resolved path (or
    ``None`` if it never shows up).
    """
    import shutil as _shutil

    which = which or _shutil.which
    for attempt in range(attempts):
        found = which(name)
        if found:
            return found
        if attempt < attempts - 1:
            sleep(delay_seconds)
    return None


# Approximate `ollama pull` download sizes, keyed by the models
# _ensure_ollama() can select. Only used for the user-facing heads-up
# before the pull; keep in sync with the model choices above/below.
_MODEL_PULL_SIZES = {
    "qwen3:1.7b": "~1.4 GB",
    "llama3.2:1b": "~1.3 GB",
    "gemma4:e2b": "~3 GB",
    "gemma4:e2b-mlx": "~3 GB",
}


def _pull_notice(model: str) -> str:
    """One-line heads-up printed before `ollama pull` takes over the terminal."""
    size = _MODEL_PULL_SIZES.get(model, "a few GB")
    marker, dash = ("▶", "—") if supports_unicode() else (">", "-")
    return (
        f"{marker} Pulling model {model} "
        f"({size}, one-time {dash} progress below; may take several minutes)..."
    )


def _ensure_ollama() -> None:
    """Ensure Ollama is installed, running optimally, and the model is warm.

    Steps:
    1. Detect available accelerator (Apple Silicon / CUDA / ROCm / CPU)
    2. Install Ollama if missing (winget on Windows, brew on macOS)
    3. Start Ollama with optimal env vars for the detected hardware
    4. Pull the required model if missing
    5. Pre-warm the model to eliminate cold-start latency
    """
    import json
    import os
    import shutil
    import subprocess
    import urllib.error
    import urllib.request

    config = ConfigStore.current()
    stack = config.detection_stack

    # Determine which model is needed
    model = None
    if stack.gemma4_e2b:
        from domestique.detectors.local_llm import _resolve_gemma_model

        model = _resolve_gemma_model()
    elif stack.qwen3_1_7b:
        model = "qwen3:1.7b"
    elif stack.legacy_cpu:
        model = "llama3.2:1b"
    if not model:
        return

    # Detect hardware
    hw = _detect_accelerator()
    print(f"▶ Detected: {hw['name']} ({hw['type']}, {hw['vram_gb']} GB)")

    ollama_bin = shutil.which("ollama")

    # Install Ollama if missing
    if not ollama_bin:
        if os.name == "nt":
            print("▶ Ollama not found — installing via winget...")
            try:
                subprocess.run(
                    [  # noqa: S607
                        "winget",
                        "install",
                        "Ollama.Ollama",
                        "--accept-source-agreements",
                        "--accept-package-agreements",
                    ],
                    capture_output=True,
                    timeout=300,
                )
                # Refresh PATH after install
                user_path = subprocess.run(
                    [  # noqa: S607
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        "[Environment]::GetEnvironmentVariable('Path','User')",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                ).stdout.strip()
                os.environ["PATH"] = os.environ.get("PATH", "") + ";" + user_path
                # winget's post-install PATH registration can lag a moment
                # behind the process returning, so poll briefly before
                # giving up.
                ollama_bin = _wait_for_command("ollama")
            except Exception as exc:
                print(f"  ⚠ Ollama install failed: {exc}")
        elif sys.platform == "darwin":
            brew = shutil.which("brew")
            if brew:
                print("▶ Ollama not found — installing via brew...")
                try:
                    subprocess.run([brew, "install", "ollama"], capture_output=True, timeout=300)  # noqa: S603
                    ollama_bin = shutil.which("ollama")
                except Exception as exc:
                    print(f"  ⚠ Ollama install failed: {exc}")
        if ollama_bin:
            print("  ✓ Ollama installed")
        else:
            print("  ⚠ Install Ollama manually: https://ollama.com/download")
            return

    # Apply optimal env vars for this hardware before starting Ollama
    for key, val in hw["env"].items():
        os.environ.setdefault(key, val)

    # Ensure Ollama server is responding
    def _ollama_alive() -> bool:
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            opener.open(urllib.request.Request("http://localhost:11434/"), timeout=2)
            return True
        except Exception:
            return False

    if not _ollama_alive():
        print("▶ Starting Ollama server...")
        try:
            if os.name == "nt":
                subprocess.Popen(  # noqa: S603
                    [ollama_bin, "serve"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(  # noqa: S603
                    [ollama_bin, "serve"],
                    start_new_session=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            for _ in range(20):
                time.sleep(0.5)
                if _ollama_alive():
                    break
        except Exception as exc:
            print(f"  ⚠ Could not start Ollama: {exc}")
            return

    # Check if model is already pulled
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        resp = opener.open(
            urllib.request.Request("http://localhost:11434/api/tags"),
            timeout=5,
        )
        tags = json.loads(resp.read())
        pulled = {m["name"] for m in tags.get("models", [])}
    except Exception:
        pulled = set()

    if model not in pulled and not any(m.startswith(model.split(":")[0]) for m in pulled):
        # Heads-up BEFORE handing the terminal to `ollama pull`: its live
        # progress bar owns the console for the whole (one-time) download,
        # so set expectations first. Deliberately NOT capturing output —
        # the user should see download progress.
        print(_pull_notice(model), flush=True)
        try:
            subprocess.run([ollama_bin, "pull", model], timeout=600)  # noqa: S603
            print(f"  ✓ {model} ready")
        except Exception as exc:
            print(f"  ⚠ Model pull failed: {exc}")
            return

    # Benchmark CPU vs GPU inference and pick the optimal backend.
    # Inference throughput matters more than model load time for proxy
    # workloads where the number of calls is large. When performance
    # is within a negligible margin, prefer CPU (more energy-efficient).
    _benchmark_and_warm(model, hw, opener)


def _ollama_infer(
    opener: OpenerDirector, model: str, text: str, num_predict: int = 5
) -> dict | None:
    """Run a single Ollama inference and return timing metadata."""
    import json
    import urllib.request

    payload = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": text}],
            "stream": False,
            "think": False,
            "keep_alive": "30m",
            "options": {"num_predict": num_predict, "num_ctx": 4096, "temperature": 0, "top_k": 1},
        }
    ).encode()
    req = urllib.request.Request(
        "http://localhost:11434/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = opener.open(req, timeout=120)
        return json.loads(resp.read())
    except Exception:
        return None


def _benchmark_and_warm(model: str, hw: dict, opener: OpenerDirector) -> None:
    """Benchmark inference, choose optimal backend, and pre-warm the model.

    On systems with a discrete GPU, runs 3 quick inferences on the current
    backend, then unloads the model, forces CPU, runs 3 more, and compares
    median eval+prompt_eval time. Picks whichever is faster — or CPU when
    the difference is negligible (< 15%) since CPU is more energy-efficient.

    Apple Silicon always uses Metal (unified memory — no CPU vs GPU split).
    """
    import json
    import os
    import urllib.request

    # Apple Silicon: always use Metal, no CPU/GPU split to benchmark
    if hw["type"] == "apple_silicon":
        print(f"▶ Pre-warming {model} on Metal (Apple Silicon)...")
        _ollama_infer(opener, model, "hi", num_predict=1)
        print(f"  ✓ {model} loaded and warm (Metal)")
        return

    # CPU-only systems: just warm up
    if hw["type"] == "cpu":
        print(f"▶ Pre-warming {model} on CPU...")
        _ollama_infer(opener, model, "hi", num_predict=1)
        print(f"  ✓ {model} loaded and warm (CPU)")
        return

    # GPU systems (CUDA / ROCm): benchmark GPU vs CPU
    print(f"▶ Benchmarking {model} on {hw['name']} vs CPU...")

    def _median(values: list[float]) -> float:
        s = sorted(values)
        n = len(s)
        if n % 2 == 1:
            return s[n // 2]
        return (s[n // 2 - 1] + s[n // 2]) / 2

    def _bench_runs(label: str, n: int = 3) -> float:
        # Warm-up call (loads model, builds KV cache)
        _ollama_infer(opener, model, "warmup", num_predict=1)
        times = []
        for _ in range(n):
            r = _ollama_infer(opener, model, "Classify: My SSN is 123-45-6789", num_predict=10)
            if r:
                pe = r.get("prompt_eval_duration", 0) / 1e6
                ev = r.get("eval_duration", 0) / 1e6
                times.append(pe + ev)
        med = _median(times) if times else 99999
        print(f"    {label}: {med:.0f}ms median ({len(times)} runs)")
        return med

    # Benchmark on current backend (GPU)
    gpu_ms = _bench_runs(hw["name"])

    # Unload model from GPU, force CPU-only, benchmark again
    try:
        payload = json.dumps({"model": model, "keep_alive": 0}).encode()
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        opener.open(req, timeout=10)
    except Exception:  # noqa: S110
        pass
    time.sleep(1)

    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    cpu_ms = _bench_runs("CPU")

    # Decide: prefer CPU if faster or within 15% (more energy-efficient)
    threshold = 1.15  # CPU must be > 15% slower to justify GPU
    if cpu_ms <= gpu_ms * threshold:
        chosen = "cpu"
        print(f"  → Using CPU ({cpu_ms:.0f}ms ≤ {gpu_ms:.0f}ms × {threshold})")
    else:
        chosen = hw["type"]
        # Re-enable GPU
        del os.environ["CUDA_VISIBLE_DEVICES"]
        print(f"  → Using {hw['name']} ({gpu_ms:.0f}ms < {cpu_ms:.0f}ms)")

    # Final warm-up on the chosen backend
    # Unload first to ensure clean load on chosen backend
    try:
        payload = json.dumps({"model": model, "keep_alive": 0}).encode()
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        opener.open(req, timeout=10)
    except Exception:  # noqa: S110
        pass
    time.sleep(1)

    _ollama_infer(opener, model, "hi", num_predict=1)
    print(f"  ✓ {model} warm on {chosen}")


def _tray_available() -> bool:
    """Whether the optional tray dependencies (pystray + Pillow) are findable."""
    import importlib.util

    try:
        return (
            importlib.util.find_spec("pystray") is not None
            and importlib.util.find_spec("PIL") is not None
        )
    except (ImportError, ValueError):
        return False


def _start_system_tray(api_port: int) -> SystemTray | None:
    """Start the system tray icon in portable mode. Returns the tray or None.

    ``SystemTray`` imports pystray lazily *inside its background thread*, so a
    missing optional dep surfaced as an unhandled thread traceback long after
    startup. Probing availability here degrades the missing-dep case to no
    tray icon with an install hint. (A present-but-broken install can still
    fail at import time inside the thread — the probe only covers findability.)
    """
    if not _tray_available():
        print('  Tray icon disabled (optional) — enable with: pip install -e ".[desktop]"')
        return None
    try:
        from domestique_app.services.tray import SystemTray
    except ImportError:
        return None

    from domestique_app.server.api import (
        get_browser_proxy_service,
        get_proxy_service,
    )

    # Two independent toggles: the API proxy (proxy_enabled) and browser
    # protection (browser_interception) are separate services with separate
    # config flags — toggling one must never touch the other's state.
    def _toggle_api_proxy() -> None:
        proxy = get_proxy_service()
        config = ConfigStore.current()
        if proxy.is_running:
            proxy.stop()
            config.proxy_enabled = False
            ConfigStore.save(config)
        else:
            try:
                proxy.start(config)
                config.proxy_enabled = True
                ConfigStore.save(config)
            except Exception:  # noqa: S110
                pass

    def _toggle_browser() -> None:
        bp = get_browser_proxy_service()
        config = ConfigStore.current()
        if bp.is_running:
            bp.stop()
            config.browser_interception = False
            config.browser_interception_configured = True
            ConfigStore.save(config)
        else:
            try:
                if not bp.is_setup:
                    bp.setup()
                bp.start()
                config.browser_interception = True
                config.browser_interception_configured = True
                ConfigStore.save(config)
            except Exception:  # noqa: S110
                pass

    def _quit() -> None:
        import os

        _cleanup_services()
        os._exit(0)

    tray = SystemTray(
        on_toggle_api=_toggle_api_proxy,
        on_toggle_browser=_toggle_browser,
        on_quit=_quit,
        dashboard_url=f"http://127.0.0.1:{api_port}",
    )
    tray.start()
    return tray


def _tray_sync_loop(tray: SystemTray) -> None:
    """Poll proxy status and keep the tray icon in sync."""
    from domestique_app.server.api import get_browser_proxy_service, get_proxy_service

    while True:
        with contextlib.suppress(Exception):
            tray.set_states(
                api_active=get_proxy_service().is_running,
                browser_active=get_browser_proxy_service().is_running,
            )
        time.sleep(3)


def _auto_start_proxies() -> None:
    """Start proxies that were enabled in the saved configuration.

    Respects the user's last-known state so protection resumes
    automatically after an app restart without manual re-enabling.
    """
    from domestique_app.server.api import get_browser_proxy_service, get_proxy_service

    config = ConfigStore.current()

    if config.proxy_enabled:
        proxy = get_proxy_service()
        if not proxy.is_running:
            try:
                proxy.start(config)
                print("▶ Firewall proxy auto-started (port %d)" % config.proxy_port)  # noqa: UP031
            except Exception as exc:
                print(f"  ⚠ Firewall proxy auto-start failed: {exc}")

    # First-run: browser interception has never been explicitly configured
    # (see AppConfig.browser_interception_configured). Auto-enable it once
    # so the "paste a secret -> see it blocked" browser demo actually
    # works out of the box on portable mode, matching macOS's always-on
    # default (audit C6). This relies on the CA already being generated
    # and trusted by _ensure_cert_generated_portable() -- which
    # _launch_portable calls synchronously, before this function's thread
    # is even started -- otherwise the user would just trade "nothing
    # happens" for ERR_CERT_AUTHORITY_INVALID on every intercepted site.
    # Once a user (or this bootstrap) has explicitly set the flag, it is
    # marked configured and this block never fires again -- an explicit
    # "off" is always respected on subsequent launches.
    if not config.browser_interception_configured:
        config.browser_interception = True
        config.browser_interception_configured = True
        ConfigStore.save(config)

    if config.browser_interception:
        bp = get_browser_proxy_service()
        if not bp.is_running:
            try:
                if not bp.is_setup:
                    bp.setup()
                bp.start()
                print("▶ Browser proxy auto-started (port %d)" % bp.PROXY_PORT)  # noqa: UP031
            except Exception as exc:
                print(f"  ⚠ Browser proxy auto-start failed: {exc}")


def _cleanup_services() -> None:
    """Stop background services started through the dashboard API."""
    try:
        from domestique_app.server.api import get_browser_proxy_service, get_proxy_service

        browser_proxy = get_browser_proxy_service()
        if browser_proxy.is_running:
            browser_proxy.stop()

        proxy = get_proxy_service()
        if proxy.is_running:
            proxy.stop()
    except Exception:  # noqa: S110
        pass


if __name__ == "__main__":
    main()
