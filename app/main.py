"""Application launcher for native and portable desktop modes.

On macOS, LLMGuard uses the existing AppKit shell. On Windows and Linux, it
starts the same local API server and opens the dashboard in the default browser.
"""

from __future__ import annotations

import argparse
import atexit
import signal
import sys
import time
import webbrowser
from pathlib import Path
from typing import NoReturn

from app.config.store import ConfigStore
from app.server.api import start_api_server


DASHBOARD_PATH = Path(__file__).parent / "assets" / "dashboard.html"
DEFAULT_API_PORT = 9876


def launch(
    *,
    mode: str = "auto",
    api_port: int = DEFAULT_API_PORT,
    open_dashboard: bool = True,
) -> None:
    """Launch LLMGuard.

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
    glyphs LLMGuard prints (e.g. the certificate-setup messages). The macOS launch
    path already did this; doing it here in ``main()`` also covers the portable
    Windows/Linux path, which otherwise crashes on first-run output.
    """
    import os

    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def main(argv: list[str] | None = None) -> None:
    """CLI entry point used by ``python -m app``."""
    _configure_console_utf8()
    parser = argparse.ArgumentParser(description="Launch LLMGuard")
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
    launch(
        mode=args.mode,
        api_port=args.api_port,
        open_dashboard=not args.no_browser,
    )


def _resolve_mode(mode: str) -> str:
    if mode == "auto":
        return "native" if sys.platform == "darwin" else "portable"
    if mode == "native" and sys.platform != "darwin":
        raise RuntimeError("Native mode is only available on macOS.")
    return mode


def _launch_macos(*, api_port: int) -> None:
    """Launch the AppKit desktop UI.

    Imports are intentionally lazy so Windows and Linux can import app.main.
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

    from app.native.app_delegate import AppDelegate

    # Fix ASCII codec errors in py2app bundle.
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream in (sys.stdout, sys.stderr):
        if stream and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

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

    NSProcessInfo.processInfo().setProcessName_("LLMGuard")

    ns_app = NSApplication.sharedApplication()
    ns_app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)

    bundle = NSBundle.mainBundle()
    info = bundle.localizedInfoDictionary() or bundle.infoDictionary()
    if info:
        info["CFBundleName"] = "LLMGuard"
        info["CFBundleDisplayName"] = "LLMGuard"
        info["CFBundleIdentifier"] = "com.llmguard.app"

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
    """Generate the CA (if missing) before the portable dashboard opens.

    Portable mode (Windows/Linux) has no equivalent of the macOS
    ``AppDelegate._ensure_cert_trusted()`` bootstrap step, so a fresh
    install's CA was never generated and the dashboard's cert-install gate
    had nothing to install (see audit finding C1).

    ``BrowserProxyService.setup()`` -> ``interceptor.generate_ca()`` is
    idempotent: it returns immediately without touching the files if a CA
    already exists (see ``generate_ca()``'s early-return when
    ``CA_CERT_PATH``/``CA_KEY_PATH`` are both present), so calling this
    unconditionally on every launch never regenerates or overwrites an
    existing CA.
    """
    try:
        from app.server.api import get_browser_proxy_service

        svc = get_browser_proxy_service()
        if not svc.is_setup:
            print("▶ First-time setup: generating certificate authority...")
            svc.setup()
    except Exception as exc:
        print(f"  ⚠ Certificate setup failed: {exc}")


def _launch_portable(*, api_port: int, open_dashboard: bool) -> NoReturn:
    """Launch the portable browser-dashboard experience."""
    ConfigStore.load()
    server = start_api_server(port=api_port)
    atexit.register(_cleanup_services)

    # Portable mode has no AppKit warmup path; mark startup complete so the
    # dashboard exits its "starting" state instead of spinning forever.
    import app.server.api as _api
    _api._startup_state["phase"] = "ready"
    _api._startup_state["detail"] = ""

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

    dashboard_url = f"http://127.0.0.1:{api_port}/"
    print(f"LLMGuard API running at http://127.0.0.1:{api_port}")
    print(f"Dashboard: {dashboard_url}")
    print("Press Ctrl+C to stop.")

    if open_dashboard:
        webbrowser.open(dashboard_url)

    # System tray icon (Windows/Linux) — mirrors macOS StatusBar.
    tray = _start_system_tray(api_port)

    def _shutdown(_signum=None, _frame=None) -> None:
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
            target=_tray_sync_loop, args=(tray,), daemon=True,
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
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True, text=True, timeout=5,
            )
            ram_gb = round(int(r.stdout.strip()) / (1024 ** 3), 1)
        except Exception:
            ram_gb = 8.0
        chip = "Apple Silicon"
        try:
            r = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=5,
            )
            chip = r.stdout.strip() or chip
        except Exception:
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
            r = subprocess.run(
                [nvidia_smi, "--query-gpu=name,memory.total,memory.free",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5,
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
        except Exception:
            pass

    # AMD ROCm GPU
    rocm_smi = shutil.which("rocm-smi")
    if rocm_smi:
        try:
            r = subprocess.run(
                [rocm_smi, "--showmeminfo", "vram", "--csv"],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.strip().splitlines()[1:]:
                parts = line.split(",")
                if len(parts) >= 2:
                    total_bytes = int(parts[0])
                    return {
                        "type": "rocm",
                        "name": "AMD GPU (ROCm)",
                        "vram_gb": round(total_bytes / (1024 ** 3), 1),
                        "env": {
                            "OLLAMA_FLASH_ATTENTION": "1",
                            "OLLAMA_KEEP_ALIVE": "30m",
                        },
                    }
        except Exception:
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
    which=None,
    sleep=time.sleep,
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
    import urllib.request
    import urllib.error

    config = ConfigStore.current()
    stack = config.detection_stack

    # Determine which model is needed
    model = None
    if stack.gemma4_e2b:
        from llmguard.detectors.local_llm import _resolve_gemma_model
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
                    ["winget", "install", "Ollama.Ollama",
                     "--accept-source-agreements", "--accept-package-agreements"],
                    capture_output=True, timeout=300,
                )
                # Refresh PATH after install
                user_path = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "[Environment]::GetEnvironmentVariable('Path','User')"],
                    capture_output=True, text=True, timeout=10,
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
                    subprocess.run([brew, "install", "ollama"],
                                   capture_output=True, timeout=300)
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
                subprocess.Popen(
                    [ollama_bin, "serve"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(
                    [ollama_bin, "serve"],
                    start_new_session=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
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
            urllib.request.Request("http://localhost:11434/api/tags"), timeout=5,
        )
        tags = json.loads(resp.read())
        pulled = {m["name"] for m in tags.get("models", [])}
    except Exception:
        pulled = set()

    if model not in pulled and not any(m.startswith(model.split(":")[0]) for m in pulled):
        print(f"▶ Pulling model {model} (first run only)...")
        try:
            subprocess.run([ollama_bin, "pull", model], timeout=600)
            print(f"  ✓ {model} ready")
        except Exception as exc:
            print(f"  ⚠ Model pull failed: {exc}")
            return

    # Benchmark CPU vs GPU inference and pick the optimal backend.
    # Inference throughput matters more than model load time for proxy
    # workloads where the number of calls is large. When performance
    # is within a negligible margin, prefer CPU (more energy-efficient).
    _benchmark_and_warm(model, hw, opener)


def _ollama_infer(opener, model: str, text: str, num_predict: int = 5) -> dict | None:
    """Run a single Ollama inference and return timing metadata."""
    import json
    import urllib.request
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": text}],
        "stream": False, "think": False, "keep_alive": "30m",
        "options": {"num_predict": num_predict, "num_ctx": 4096,
                    "temperature": 0, "top_k": 1},
    }).encode()
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


def _benchmark_and_warm(model: str, hw: dict, opener) -> None:
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
            r = _ollama_infer(opener, model, "Classify: My SSN is 123-45-6789",
                              num_predict=10)
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
    except Exception:
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
    except Exception:
        pass
    time.sleep(1)

    _ollama_infer(opener, model, "hi", num_predict=1)
    print(f"  ✓ {model} warm on {chosen}")


def _start_system_tray(api_port: int):
    """Start the system tray icon on Windows/Linux. Returns the tray or None."""
    try:
        from app.services.tray import SystemTray
    except ImportError:
        return None

    from app.server.api import (
        get_proxy_service, get_browser_proxy_service,
    )

    def _toggle() -> None:
        proxy = get_proxy_service()
        bp = get_browser_proxy_service()
        config = ConfigStore.current()
        if proxy.is_running or bp.is_running:
            proxy.stop()
            if bp.is_running:
                bp.stop()
            config.proxy_enabled = False
            config.browser_interception = False
            ConfigStore.save(config)
        else:
            try:
                proxy.start(config)
                config.proxy_enabled = True
                ConfigStore.save(config)
            except Exception:
                pass

    def _quit() -> None:
        import os
        _cleanup_services()
        os._exit(0)

    tray = SystemTray(
        on_toggle=_toggle,
        on_quit=_quit,
        dashboard_url=f"http://127.0.0.1:{api_port}",
    )
    tray.start()
    return tray


def _tray_sync_loop(tray) -> None:
    """Poll proxy status and keep the tray icon in sync."""
    from app.server.api import get_proxy_service, get_browser_proxy_service

    while True:
        try:
            active = (
                get_proxy_service().is_running
                or get_browser_proxy_service().is_running
            )
            tray.set_active(active)
        except Exception:
            pass
        time.sleep(3)


def _auto_start_proxies() -> None:
    """Start proxies that were enabled in the saved configuration.

    Respects the user's last-known state so protection resumes
    automatically after an app restart without manual re-enabling.
    """
    from app.server.api import get_proxy_service, get_browser_proxy_service

    config = ConfigStore.current()

    if config.proxy_enabled:
        proxy = get_proxy_service()
        if not proxy.is_running:
            try:
                proxy.start(config)
                print("▶ Firewall proxy auto-started (port %d)" % config.proxy_port)
            except Exception as exc:
                print(f"  ⚠ Firewall proxy auto-start failed: {exc}")

    if config.browser_interception:
        bp = get_browser_proxy_service()
        if not bp.is_running:
            try:
                if not bp.is_setup:
                    bp.setup()
                bp.start()
                print("▶ Browser proxy auto-started (port %d)" % bp.PROXY_PORT)
            except Exception as exc:
                print(f"  ⚠ Browser proxy auto-start failed: {exc}")


def _cleanup_services() -> None:
    """Stop background services started through the dashboard API."""
    try:
        from app.server.api import get_browser_proxy_service, get_proxy_service

        browser_proxy = get_browser_proxy_service()
        if browser_proxy.is_running:
            browser_proxy.stop()

        proxy = get_proxy_service()
        if proxy.is_running:
            proxy.stop()
    except Exception:
        pass


if __name__ == "__main__":
    main()
