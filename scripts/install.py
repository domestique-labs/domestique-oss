"""LLMGuard hardware-aware installer.

Detects OS / RAM / GPU / Ollama, asks which features to enable, recommends a
local-LLM preset that fits the available VRAM, then performs only the work
the user confirmed.

Usage (interactive):
    python scripts/install.py

Usage (non-interactive — use defaults):
    python scripts/install.py --yes
    python scripts/install.py --yes --features pii,ner,browser-proxy --no-local-llm
    python scripts/install.py --yes --features all --preset minimal
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parent.parent
LLMGUARD_HOME = Path.home() / ".llmguard"

PRESET_TO_STACK_KEY: dict[str, str] = {
    "minimal": "qwen3_1_7b",
    "balanced": "gemma4_e2b",
    "quality": "gemma4_e2b",
    "legacy-cpu": "legacy_cpu",
}
ALL_LLM_STACK_KEYS = ("gemma4_e2b", "qwen3_1_7b", "legacy_cpu")

FEATURE_EXTRAS: dict[str, dict[str, object]] = {
    "pii": {
        "label": "Presidio + spaCy PII detection",
        "extra": "pii",
        "extra_download_mb": 750,
        "spacy_model": "en_core_web_lg",
        "default": True,
    },
    "ner": {
        "label": "GLiNER zero-shot PII (Tier 2b)",
        "extra": "ner",
        "extra_download_mb": 300,
        "hf_model": "knowledgator/gliner-pii-base-v1.0",
        "default": True,
    },
    "browser-proxy": {
        "label": "Browser MITM interception (mitmproxy)",
        "extra": "browser-proxy",
        "extra_download_mb": 50,
        "default": True,
    },
    "file-scanning": {
        "label": "PDF / file scanning helpers",
        "extra": "file-scanning",
        "extra_download_mb": 20,
        "default": False,
    },
}

# Per-preset Tier-3 model — keep in sync with llmguard/detectors/local_llm.py
LLM_PRESETS: dict[str, dict[str, object]] = {
    "minimal": {
        "model": "qwen3:1.7b",
        "vram_gb": 1.5,
        "ram_gb": 4,
        "size_gb": 1.0,
        "notes": "best for ≤4 GB GPUs or pure CPU",
    },
    "balanced": {
        "model": "gemma4:e2b",
        "vram_gb": 3.5,
        "ram_gb": 8,
        "size_gb": 1.9,
        "notes": "needs GPU with ~4 GB free VRAM",
    },
    "quality": {
        "model": "gemma4:e4b",
        "vram_gb": 6.0,
        "ram_gb": 12,
        "size_gb": 3.3,
        "notes": "needs ≥6 GB free VRAM",
    },
    "legacy-cpu": {
        "model": "llama3.2:1b",
        "vram_gb": 0,
        "ram_gb": 4,
        "size_gb": 1.3,
        "notes": "CPU-only fallback when no GPU is usable",
    },
}


# ──────────────────────────────── detection ────────────────────────────────

def detect_total_ram_gb() -> float:
    if platform.system() == "Windows":
        import ctypes

        class _MemStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_uint),
                ("dwMemoryLoad", ctypes.c_uint),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        m = _MemStatus()
        m.dwLength = ctypes.sizeof(m)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        return round(m.ullTotalPhys / (1024 ** 3), 1)

    try:
        return round(
            os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / (1024 ** 3),
            1,
        )
    except (AttributeError, ValueError, OSError):
        return 0.0


def detect_gpu() -> tuple[str | None, float]:
    """Return (gpu_name, vram_gb). vram_gb is 0.0 when no GPU detected."""
    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi:
        try:
            r = subprocess.run(
                [nvidia_smi, "--query-gpu=name,memory.total",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, check=True, timeout=5,
            )
            line = r.stdout.strip().split("\n")[0]
            name, mem_mib = (s.strip() for s in line.split(","))
            return name, round(int(mem_mib) / 1024, 1)
        except (subprocess.SubprocessError, ValueError):
            pass

    if platform.system() == "Darwin" and platform.machine() == "arm64":
        ram = detect_total_ram_gb()
        return f"Apple Silicon (unified memory ≈ {ram} GB)", ram

    return None, 0.0


def detect_gpu_free_vram_gb() -> float | None:
    """Return free VRAM in GB on NVIDIA GPUs, or None if unknown."""
    nvidia_smi = shutil.which("nvidia-smi")
    if not nvidia_smi:
        return None
    try:
        r = subprocess.run(
            [nvidia_smi, "--query-gpu=memory.free",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, check=True, timeout=5,
        )
        return round(int(r.stdout.strip().split("\n")[0]) / 1024, 1)
    except (subprocess.SubprocessError, ValueError):
        return None


def detect_ollama() -> tuple[bool, str | None]:
    binary = shutil.which("ollama")
    if not binary:
        return False, None
    try:
        r = subprocess.run([binary, "--version"],
                           capture_output=True, text=True, timeout=5)
        return True, r.stdout.strip() or r.stderr.strip()
    except subprocess.SubprocessError:
        return True, None


def detect_existing_ollama_models() -> set[str]:
    import urllib.request
    import urllib.error
    import json
    try:
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2) as resp:
            data = json.loads(resp.read())
        return {m["name"] for m in data.get("models", [])}
    except (urllib.error.URLError, ValueError, KeyError, TimeoutError):
        return set()


def recommend_preset(vram_gb: float, free_vram_gb: float | None,
                     ram_gb: float) -> str:
    usable = free_vram_gb if free_vram_gb is not None else vram_gb
    if usable >= LLM_PRESETS["quality"]["vram_gb"]:
        return "quality"
    if usable >= LLM_PRESETS["balanced"]["vram_gb"]:
        return "balanced"
    if usable >= LLM_PRESETS["minimal"]["vram_gb"]:
        return "minimal"
    if ram_gb >= LLM_PRESETS["legacy-cpu"]["ram_gb"]:
        return "legacy-cpu"
    return "minimal"


# ──────────────────────────────── prompts ─────────────────────────────────

def _input(prompt: str, default: str = "") -> str:
    suffix = f" [{default}] " if default else " "
    try:
        ans = input(prompt + suffix).strip()
    except EOFError:
        return default
    return ans or default


def prompt_yes_no(question: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        a = _input(f"{question} ({suffix})", "y" if default else "n").lower()
        if a in ("y", "yes"):
            return True
        if a in ("n", "no"):
            return False
        print("  please answer y or n")


def prompt_choice(question: str, choices: list[tuple[str, str]],
                  default: str) -> str:
    print(question)
    for key, label in choices:
        tag = "  (recommended)" if key == default else ""
        print(f"  [{key}]  {label}{tag}")
    while True:
        a = _input("  choice", default).lower()
        keys = [k for k, _ in choices]
        if a in keys:
            return a
        print(f"  '{a}' not one of {', '.join(keys)}")


# ──────────────────────────────── execution ───────────────────────────────

def run(cmd: list[str], *, cwd: Path | None = None, env: dict | None = None,
        check: bool = True) -> int:
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    r = subprocess.run(cmd, cwd=cwd or ROOT,
                       env={**os.environ, **(env or {})})
    if check and r.returncode != 0:
        raise SystemExit(f"command failed with exit {r.returncode}")
    return r.returncode


def install_extras(extras: list[str]) -> None:
    if not extras:
        return
    spec = f".[{','.join(extras)}]"
    print(f"\n▶ installing pip extras: {spec}")
    run([sys.executable, "-m", "pip", "install", "-e", spec])


def download_spacy_model(model: str) -> None:
    print(f"\n▶ downloading spaCy model: {model}")
    run([sys.executable, "-m", "spacy", "download", model])


def cache_huggingface_model(repo_id: str) -> None:
    print(f"\n▶ caching HuggingFace model: {repo_id}")
    code = (
        "import os; os.environ.pop('HF_HUB_OFFLINE', None);"
        "from gliner import GLiNER;"
        f"GLiNER.from_pretrained({repo_id!r});"
        "print('cached')"
    )
    run([sys.executable, "-c", code], env={"HF_HUB_OFFLINE": "0"})


def pull_ollama_model(model: str, already_pulled: set[str]) -> None:
    if model in already_pulled:
        print(f"  ✓ ollama model already present: {model}")
        return
    print(f"\n▶ pulling Ollama model: {model}")
    run(["ollama", "pull", model])


def align_dashboard_config(preset: str) -> tuple[bool, str]:
    """Update ~/.llmguard/config.json so the dashboard runs the installed preset.

    The dashboard persists which Tier-3 model is active in its detection_stack
    independently of LLMGUARD_* env vars, so without this the dashboard keeps
    using its previously-saved model and ignores what we just pulled.

    Returns (config_changed, message).
    """
    stack_key = PRESET_TO_STACK_KEY.get(preset)

    LLMGUARD_HOME.mkdir(parents=True, exist_ok=True)
    cfg_path = LLMGUARD_HOME / "config.json"
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text())
        except json.JSONDecodeError:
            data = {}
    else:
        data = {}

    changed = False
    valid_literals = {"minimal", "balanced", "quality", "legacy-cpu"}
    if preset in valid_literals and data.get("llm_preset") != preset:
        data["llm_preset"] = preset
        changed = True

    if stack_key:
        stack = data.setdefault("detection_stack", {})
        for k in ALL_LLM_STACK_KEYS:
            want = (k == stack_key)
            if stack.get(k) != want:
                stack[k] = want
                changed = True

    if changed:
        cfg_path.write_text(json.dumps(data, indent=2))

    if not stack_key:
        return changed, (
            f"  ⚠  preset '{preset}' has no matching dashboard toggle in "
            f"DetectionStackConfig — set the Tier-3 model in the dashboard manually."
        )
    if changed:
        return True, (
            f"  ✓ dashboard config aligned: detection_stack.{stack_key}=true "
            f"(other Tier-3 toggles disabled), llm_preset={preset}"
        )
    return False, "  ✓ dashboard config already aligned"


# ──────────────────────────────── main flow ───────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--yes", "-y", action="store_true",
                   help="accept all recommended defaults (non-interactive)")
    p.add_argument("--features",
                   help="comma-separated extras to install (e.g. pii,ner,browser-proxy or 'all' or 'none')")
    p.add_argument("--no-local-llm", action="store_true",
                   help="skip the Tier-3 local LLM setup")
    p.add_argument("--preset", choices=list(LLM_PRESETS.keys()),
                   help="force a specific local-LLM preset; skips the recommendation")
    return p.parse_args()


def parse_features_arg(arg: str | None) -> set[str] | None:
    if arg is None:
        return None
    if arg.strip().lower() == "all":
        return set(FEATURE_EXTRAS.keys())
    if arg.strip().lower() in ("none", ""):
        return set()
    requested = {x.strip() for x in arg.split(",") if x.strip()}
    unknown = requested - set(FEATURE_EXTRAS.keys())
    if unknown:
        raise SystemExit(
            f"unknown feature(s): {', '.join(sorted(unknown))}. "
            f"valid: {', '.join(FEATURE_EXTRAS.keys())} or 'all'"
        )
    return requested


def banner() -> None:
    print("=" * 64)
    print("  LLMGuard installer")
    print("=" * 64)


def section(title: str) -> None:
    print(f"\n── {title} " + "─" * (60 - len(title)))


def report_environment(ram_gb: float, gpu: str | None, vram_gb: float,
                       free_vram_gb: float | None,
                       ollama_present: bool, ollama_version: str | None) -> None:
    section("detected environment")
    print(f"  OS              {platform.system()} {platform.release()}")
    print(f"  Python          {platform.python_version()} ({sys.executable})")
    print(f"  total RAM       {ram_gb} GB")
    if gpu:
        free = f" (free ≈ {free_vram_gb} GB)" if free_vram_gb is not None else ""
        print(f"  GPU             {gpu}")
        print(f"  VRAM            {vram_gb} GB{free}")
    else:
        print("  GPU             not detected (Tier 3 LLM will run on CPU)")
    print(f"  Ollama          {'installed — ' + ollama_version if ollama_present else 'NOT installed (https://ollama.com)'}")


def pick_features(args: argparse.Namespace) -> set[str]:
    forced = parse_features_arg(args.features)
    if forced is not None:
        section("feature selection (from --features)")
        for key in FEATURE_EXTRAS:
            mark = "✓" if key in forced else " "
            print(f"  [{mark}] {FEATURE_EXTRAS[key]['label']}")
        return forced

    section("feature selection")
    if args.yes:
        chosen = {k for k, v in FEATURE_EXTRAS.items() if v["default"]}
        for key in FEATURE_EXTRAS:
            mark = "✓" if key in chosen else " "
            print(f"  [{mark}] {FEATURE_EXTRAS[key]['label']} (default)")
        return chosen

    chosen: set[str] = set()
    for key, info in FEATURE_EXTRAS.items():
        size = f" (~{info['extra_download_mb']} MB)"
        if prompt_yes_no(f"  install {info['label']}{size}?",
                         default=bool(info["default"])):
            chosen.add(key)
    return chosen


def pick_preset(args: argparse.Namespace, ram_gb: float, vram_gb: float,
                free_vram_gb: float | None) -> str | None:
    if args.no_local_llm:
        section("local LLM (Tier 3) — skipped via --no-local-llm")
        return None

    if args.preset:
        section(f"local LLM preset (from --preset): {args.preset}")
        return args.preset

    section("local LLM (Tier 3)")
    if args.yes:
        recommended = recommend_preset(vram_gb, free_vram_gb, ram_gb)
        print(f"  recommended preset: {recommended} "
              f"({LLM_PRESETS[recommended]['model']}) — using it")
        return recommended

    if not prompt_yes_no("  enable the Tier-3 local LLM classifier?", default=True):
        return None

    recommended = recommend_preset(vram_gb, free_vram_gb, ram_gb)
    print("\n  Tier-3 presets:")
    print(f"    {'preset':<11} {'model':<16} {'VRAM':>6}  {'RAM':>5}  {'size':>5}  notes")
    for key, info in LLM_PRESETS.items():
        marker = "  (recommended)" if key == recommended else ""
        print(f"    {key:<11} {str(info['model']):<16} "
              f"{info['vram_gb']:>4} GB  {info['ram_gb']:>3} GB  "
              f"{info['size_gb']:>3} GB  {info['notes']}{marker}")
    return prompt_choice("\n  pick a preset:",
                         [(k, str(LLM_PRESETS[k]["model"])) for k in LLM_PRESETS],
                         default=recommended)


def confirm_plan(extras: set[str], preset: str | None) -> bool:
    section("install plan")
    total_mb = 0
    if extras:
        print("  pip extras:")
        for k in sorted(extras):
            print(f"    - {k} (~{FEATURE_EXTRAS[k]['extra_download_mb']} MB)")
            total_mb += int(FEATURE_EXTRAS[k]["extra_download_mb"])
    if "pii" in extras:
        print(f"    + spaCy model en_core_web_lg (~750 MB)")
    if "ner" in extras:
        print(f"    + HuggingFace model knowledgator/gliner-pii-base-v1.0 (~300 MB)")
    if preset:
        info = LLM_PRESETS[preset]
        print(f"  Ollama model: {info['model']} (~{info['size_gb']} GB)")
    print(f"\n  estimated additional download: ~{total_mb / 1024:.1f} GB"
          f" (pip extras + spaCy model already counted)"
          if total_mb else "  no pip downloads required")
    return prompt_yes_no("\n  proceed?", default=True)


def _auto_install_ollama() -> bool:
    """Attempt to install Ollama automatically.

    Windows: uses winget.  macOS: uses Homebrew.
    Returns True if ollama is available after the attempt.
    """
    system = platform.system()

    if system == "Windows":
        winget = shutil.which("winget")
        if not winget:
            return False
        print("\n▶ Installing Ollama via winget...")
        try:
            subprocess.run(
                [winget, "install", "Ollama.Ollama",
                 "--accept-source-agreements", "--accept-package-agreements"],
                timeout=300,
            )
            # Refresh PATH so shutil.which can find the new binary
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "[Environment]::GetEnvironmentVariable('Path','Machine') + ';' + "
                 "[Environment]::GetEnvironmentVariable('Path','User')"],
                capture_output=True, text=True, timeout=10,
            )
            os.environ["PATH"] = result.stdout.strip()
            if shutil.which("ollama"):
                print("  ✓ Ollama installed")
                return True
        except Exception as exc:
            print(f"  ⚠ winget install failed: {exc}")
        return False

    if system == "Darwin":
        brew = shutil.which("brew")
        if not brew:
            return False
        print("\n▶ Installing Ollama via Homebrew...")
        try:
            subprocess.run([brew, "install", "ollama"], timeout=300)
            if shutil.which("ollama"):
                print("  ✓ Ollama installed")
                return True
        except Exception as exc:
            print(f"  ⚠ brew install failed: {exc}")
        return False

    # Linux: no auto-install, user should use their package manager
    return False


def main() -> int:
    args = parse_args()
    banner()

    ram_gb = detect_total_ram_gb()
    gpu, vram_gb = detect_gpu()
    free_vram_gb = detect_gpu_free_vram_gb() if gpu else None
    ollama_present, ollama_version = detect_ollama()

    report_environment(ram_gb, gpu, vram_gb, free_vram_gb,
                       ollama_present, ollama_version)

    extras = pick_features(args)
    preset = pick_preset(args, ram_gb, vram_gb, free_vram_gb)

    if preset and not ollama_present:
        ollama_present = _auto_install_ollama()
        if ollama_present:
            ollama_version = "(just installed)"
        else:
            print("\n  ⚠  Ollama is not installed — Tier 3 will not work until you")
            print("     install it from https://ollama.com and re-run this installer.")
            if not args.yes and not prompt_yes_no("  continue anyway?", default=False):
                preset = None

    if not args.yes and not confirm_plan(extras, preset):
        print("\n  aborted.")
        return 1

    install_extras(sorted(extras))

    if "pii" in extras:
        download_spacy_model(str(FEATURE_EXTRAS["pii"]["spacy_model"]))

    if "ner" in extras:
        cache_huggingface_model(str(FEATURE_EXTRAS["ner"]["hf_model"]))

    if preset and ollama_present:
        already = detect_existing_ollama_models()
        pull_ollama_model(str(LLM_PRESETS[preset]["model"]), already)

    config_changed = False
    if preset:
        config_changed, msg = align_dashboard_config(preset)
        print()
        print(msg)

    section("done")
    print("  next steps:")
    if platform.system() == "Windows":
        print("    run.bat                  start the desktop app")
    else:
        print("    ./run.sh                 start the desktop app")
    print("    open http://127.0.0.1:9876/   dashboard")
    if config_changed:
        print()
        print("  ⚠  the dashboard config was updated. If the app is currently")
        print("     running, stop it (Ctrl+C in the run.bat / run.sh window) and")
        print("     re-launch — a running app holds the old config in memory and")
        print("     will overwrite the file on next save.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
