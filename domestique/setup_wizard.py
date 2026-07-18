"""Domestique hardware-aware setup wizard and installer logic.

Detects OS / RAM / GPU / Ollama, walks through the detection tiers one
question at a time (each with a one-line WHY based on the detected
hardware), installs only what the user confirmed, and writes the resulting
detection stack to ``~/.domestique/config.json``.

Entry points:
    domestique setup [--yes]      the CLI walkthrough (``run_wizard``)
    python scripts/install.py     the legacy installer flow (``main``) --
                                  scripts/install.py is now a thin shim
                                  that aliases this module.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, NotRequired, TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

ROOT = Path(__file__).resolve().parent.parent
DOMESTIQUE_HOME = Path.home() / ".domestique"

#: Script re-executed by the Linux venv bootstrap (see ``_ensure_linux_venv``).
#: The scripts/install.py shim points this at itself when run directly.
REEXEC_SCRIPT = Path(__file__).resolve()

PRESET_TO_STACK_KEY: dict[str, str] = {
    "minimal": "qwen3_1_7b",
    "balanced": "gemma4_e2b",
    "quality": "gemma4_e2b",
    "legacy-cpu": "legacy_cpu",
}
ALL_LLM_STACK_KEYS = ("gemma4_e2b", "qwen3_1_7b", "legacy_cpu")


class FeatureInfo(TypedDict):
    """One installable feature extra offered by the installer."""

    label: str
    extra: str
    extra_download_mb: int
    default: bool
    spacy_model: NotRequired[str]
    hf_model: NotRequired[str]


FEATURE_EXTRAS: dict[str, FeatureInfo] = {
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


class PresetInfo(TypedDict):
    """One Tier-3 local-LLM preset."""

    model: str
    vram_gb: float
    ram_gb: float
    size_gb: float
    notes: str


# Per-preset Tier-3 model — keep in sync with domestique/detectors/local_llm.py
LLM_PRESETS: dict[str, PresetInfo] = {
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


# ─────────────────────────── console-safe output ───────────────────────────

_ASCII_FALLBACKS = str.maketrans(
    {"✓": "+", "▶": ">", "⚠": "!", "─": "-", "═": "=", "≈": "~", "≤": "<=", "≥": ">=", "→": "->"}
)


def _console_safe(text: str) -> str:
    """Degrade fancy glyphs so output never crashes a cp1252 console."""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        text.encode(enc)
    except (LookupError, UnicodeError):
        return text.translate(_ASCII_FALLBACKS).encode("ascii", "replace").decode("ascii")
    return text


def _print(text: str = "") -> None:
    print(_console_safe(text))


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
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))  # type: ignore[attr-defined]
        return round(float(m.ullTotalPhys) / (1024**3), 1)

    try:
        return round(
            os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / (1024**3),
            1,
        )
    except (AttributeError, ValueError, OSError):
        return 0.0


def detect_gpu() -> tuple[str | None, float]:
    """Return (gpu_name, vram_gb). vram_gb is 0.0 when no GPU detected."""
    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi:
        try:
            r = subprocess.run(  # noqa: S603  # fixed argv, resolved binary path
                [nvidia_smi, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
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
        r = subprocess.run(  # noqa: S603  # fixed argv, resolved binary path
            [nvidia_smi, "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return round(int(r.stdout.strip().split("\n")[0]) / 1024, 1)
    except (subprocess.SubprocessError, ValueError):
        return None


def detect_ollama() -> tuple[bool, str | None]:
    binary = shutil.which("ollama")
    if not binary:
        return False, None
    try:
        r = subprocess.run(  # noqa: S603  # fixed argv, resolved binary path
            [binary, "--version"], capture_output=True, text=True, timeout=5
        )
        return True, r.stdout.strip() or r.stderr.strip()
    except subprocess.SubprocessError:
        return True, None


def detect_existing_ollama_models() -> set[str]:
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(  # noqa: S310  # fixed localhost URL, not user input
            "http://localhost:11434/api/tags", timeout=2
        ) as resp:
            data = json.loads(resp.read())
        return {m["name"] for m in data.get("models", [])}
    except (urllib.error.URLError, ValueError, KeyError, TimeoutError):
        return set()


def recommend_preset(vram_gb: float, free_vram_gb: float | None, ram_gb: float) -> str:
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


@dataclass
class HardwareProfile:
    """Everything the wizard knows about the machine it runs on."""

    ram_gb: float
    gpu: str | None
    vram_gb: float
    free_vram_gb: float | None
    ollama_present: bool
    ollama_version: str | None


def detect_hardware() -> HardwareProfile:
    """Run all hardware probes once and bundle the results."""
    ram_gb = detect_total_ram_gb()
    gpu, vram_gb = detect_gpu()
    free_vram_gb = detect_gpu_free_vram_gb() if gpu else None
    ollama_present, ollama_version = detect_ollama()
    return HardwareProfile(
        ram_gb=ram_gb,
        gpu=gpu,
        vram_gb=vram_gb,
        free_vram_gb=free_vram_gb,
        ollama_present=ollama_present,
        ollama_version=ollama_version,
    )


# ──────────────────────────────── prompts ─────────────────────────────────


def _input(prompt: str, default: str = "", *, eof_raises: bool = False) -> str:
    suffix = f" [{default}] " if default else " "
    try:
        ans = input(_console_safe(prompt + suffix)).strip()
    except EOFError:
        if eof_raises:
            raise
        return default
    return ans or default


def prompt_yes_no(question: str, default: bool = True, *, eof_default: bool | None = None) -> bool:
    """Ask a y/n question; Enter accepts ``default``.

    ``eof_default``: when given, EOF on stdin returns this value instead of
    ``default``. Callers whose accept-path has side effects (installs,
    downloads) should pass ``eof_default=False`` so a stream that passes
    ``isatty()`` but immediately EOFs fails safe instead of auto-accepting.
    """
    suffix = "Y/n" if default else "y/N"
    while True:
        try:
            a = _input(
                f"{question} ({suffix})",
                "y" if default else "n",
                eof_raises=eof_default is not None,
            ).lower()
        except EOFError:
            return default if eof_default is None else eof_default
        if a in ("y", "yes"):
            return True
        if a in ("n", "no"):
            return False
        _print("  please answer y or n")


def prompt_choice(question: str, choices: list[tuple[str, str]], default: str) -> str:
    _print(question)
    for key, label in choices:
        tag = "  (recommended)" if key == default else ""
        _print(f"  [{key}]  {label}{tag}")
    while True:
        a = _input("  choice", default).lower()
        keys = [k for k, _ in choices]
        if a in keys:
            return a
        _print(f"  '{a}' not one of {', '.join(keys)}")


# ─────────────────────── environment-aware installs ────────────────────────

InstallEnvKind = Literal["pipx", "uv-tool", "pip"]


def detect_install_env(
    *,
    prefix: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> InstallEnvKind:
    """Classify the Python environment domestique is running from.

    Determines which installer can add optional extras to *this*
    installation: ``pipx`` (pipx-managed venv), ``uv-tool`` (uv tool
    environment) or plain ``pip`` (regular venv / interpreter).
    """
    raw_prefix = sys.prefix if prefix is None else prefix
    env = os.environ if environ is None else environ
    norm = raw_prefix.replace("\\", "/").lower()

    pipx_home = env.get("PIPX_HOME", "").replace("\\", "/").lower()
    # Match "pipx" as a whole path segment, not a substring — a project
    # living at e.g. ~/dev/pipx-clone/.venv is a plain venv, not pipx.
    if "pipx" in norm.split("/") or (pipx_home and norm.startswith(pipx_home)):
        return "pipx"

    uv_tool_dir = env.get("UV_TOOL_DIR", "").replace("\\", "/").lower()
    if "/uv/tools/" in norm or (uv_tool_dir and norm.startswith(uv_tool_dir)):
        return "uv-tool"

    return "pip"


def extras_install_argv(
    extras: Iterable[str],
    *,
    env_kind: InstallEnvKind | None = None,
) -> list[str]:
    """Return the argv that installs the given extras into this environment.

    Never executes anything -- callers decide when/whether to run it.
    """
    spec = f"domestique[{','.join(sorted(extras))}]"
    kind = detect_install_env() if env_kind is None else env_kind
    if kind == "pipx":
        return ["pipx", "inject", "domestique", spec]
    if kind == "uv-tool":
        return ["uv", "tool", "install", "--force", spec]
    return [sys.executable, "-m", "pip", "install", spec]


def _source_checkout_root() -> Path | None:
    """Return the repo root when running from a source checkout, else None."""
    if (ROOT / "pyproject.toml").exists() and (ROOT / "domestique").is_dir():
        return ROOT
    return None


# ──────────────────────────────── execution ───────────────────────────────


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> int:
    _print(f"  $ {' '.join(str(c) for c in cmd)}")
    r = subprocess.run(  # noqa: S603  # argv assembled from wizard-internal constants
        cmd, cwd=cwd or ROOT, env={**os.environ, **(env or {})}
    )
    if check and r.returncode != 0:
        raise SystemExit(f"command failed with exit {r.returncode}")
    return r.returncode


def install_extras(extras: list[str]) -> None:
    """Install extras editable from the source checkout (installer-script path)."""
    if not extras:
        return
    spec = f".[{','.join(extras)}]"
    _print(f"\n▶ installing pip extras: {spec}")
    run([sys.executable, "-m", "pip", "install", "-e", spec])


def wizard_install_extras(extras: list[str]) -> None:
    """Install extras the right way for the current environment.

    Source checkout -> editable install (same as the installer script);
    pipx / uv tool / plain pip installs -> ``extras_install_argv``.
    """
    if not extras:
        return
    if _source_checkout_root() is not None:
        install_extras(extras)
        return
    argv = extras_install_argv(extras)
    _print(f"\n▶ installing extras: {', '.join(sorted(extras))}")
    run(argv, cwd=Path.cwd())


def download_spacy_model(model: str) -> None:
    _print(f"\n▶ downloading spaCy model: {model}")
    run([sys.executable, "-m", "spacy", "download", model])


def cache_huggingface_model(repo_id: str) -> None:
    _print(f"\n▶ caching HuggingFace model: {repo_id}")
    code = (
        "import os; os.environ.pop('HF_HUB_OFFLINE', None);"
        "from gliner import GLiNER;"
        f"GLiNER.from_pretrained({repo_id!r});"
        "print('cached')"
    )
    run([sys.executable, "-c", code], env={"HF_HUB_OFFLINE": "0"})


def pull_ollama_model(model: str, already_pulled: set[str]) -> None:
    if model in already_pulled:
        _print(f"  ✓ ollama model already present: {model}")
        return
    _print(f"\n▶ pulling Ollama model: {model}")
    run(["ollama", "pull", model])  # noqa: S607  # user-installed binary, resolved via PATH


def align_dashboard_config(preset: str) -> tuple[bool, str]:
    """Update ~/.domestique/config.json so the dashboard runs the installed preset.

    The dashboard persists which Tier-3 model is active in its detection_stack
    independently of DOMESTIQUE_* env vars, so without this the dashboard keeps
    using its previously-saved model and ignores what we just pulled.

    Returns (config_changed, message).
    """
    stack_key = PRESET_TO_STACK_KEY.get(preset)

    DOMESTIQUE_HOME.mkdir(parents=True, exist_ok=True)
    cfg_path = DOMESTIQUE_HOME / "config.json"
    data = _read_config_dict(cfg_path)

    changed = False
    valid_literals = {"minimal", "balanced", "quality", "legacy-cpu"}
    if preset in valid_literals and data.get("llm_preset") != preset:
        data["llm_preset"] = preset
        changed = True

    if stack_key:
        stack = _detection_stack_of(data)
        for k in ALL_LLM_STACK_KEYS:
            want = k == stack_key
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


def _read_config_dict(cfg_path: Path) -> dict[str, object]:
    if cfg_path.exists():
        try:
            loaded = json.loads(cfg_path.read_text())
        except json.JSONDecodeError:
            return {}
        if isinstance(loaded, dict):
            return loaded
    return {}


def _detection_stack_of(data: dict[str, object]) -> dict[str, object]:
    stack = data.get("detection_stack")
    if not isinstance(stack, dict):
        stack = {}
        data["detection_stack"] = stack
    return stack


def apply_wizard_config(
    *,
    gliner: bool,
    preset: str | None,
    browser: bool,
) -> Path:
    """Write the wizard's choices to ~/.domestique/config.json.

    Merges into an existing config if present. Marks the stack and browser
    settings as explicitly configured so the app's first-run auto-detection
    never second-guesses the user's wizard answers.
    """
    DOMESTIQUE_HOME.mkdir(parents=True, exist_ok=True)
    cfg_path = DOMESTIQUE_HOME / "config.json"
    data = _read_config_dict(cfg_path)

    stack = _detection_stack_of(data)
    stack["regex"] = True
    stack["gliner_pii"] = gliner
    stack_key = PRESET_TO_STACK_KEY.get(preset) if preset else None
    for key in ALL_LLM_STACK_KEYS:
        stack[key] = key == stack_key
    if preset:
        data["llm_preset"] = preset
    data["detection_stack_configured"] = True
    data["browser_interception"] = browser
    data["browser_interception_configured"] = True

    cfg_path.write_text(json.dumps(data, indent=2))
    return cfg_path


# ──────────────────────────── installer main flow ──────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="accept all recommended defaults (non-interactive)",
    )
    p.add_argument(
        "--features",
        help="comma-separated extras to install (e.g. pii,ner,browser-proxy or 'all' or 'none')",
    )
    p.add_argument("--no-local-llm", action="store_true", help="skip the Tier-3 local LLM setup")
    p.add_argument(
        "--preset",
        choices=list(LLM_PRESETS.keys()),
        help="force a specific local-LLM preset; skips the recommendation",
    )
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
    _print("=" * 64)
    _print("  Domestique installer")
    _print("=" * 64)


def section(title: str) -> None:
    _print(f"\n── {title} " + "─" * max(0, 60 - len(title)))


def report_environment(
    ram_gb: float,
    gpu: str | None,
    vram_gb: float,
    free_vram_gb: float | None,
    ollama_present: bool,
    ollama_version: str | None,
) -> None:
    section("detected environment")
    _print(f"  OS              {platform.system()} {platform.release()}")
    _print(f"  Python          {platform.python_version()} ({sys.executable})")
    _print(f"  total RAM       {ram_gb} GB")
    if gpu:
        free = f" (free ≈ {free_vram_gb} GB)" if free_vram_gb is not None else ""
        _print(f"  GPU             {gpu}")
        _print(f"  VRAM            {vram_gb} GB{free}")
    else:
        _print("  GPU             not detected (Tier 3 LLM will run on CPU)")
    ollama = (
        f"installed — {ollama_version}" if ollama_present else "NOT installed (https://ollama.com)"
    )
    _print(f"  Ollama          {ollama}")


def pick_features(args: argparse.Namespace) -> set[str]:
    forced = parse_features_arg(args.features)
    if forced is not None:
        section("feature selection (from --features)")
        for key in FEATURE_EXTRAS:
            mark = "✓" if key in forced else " "
            _print(f"  [{mark}] {FEATURE_EXTRAS[key]['label']}")
        return forced

    section("feature selection")
    if args.yes:
        chosen: set[str] = {k for k, v in FEATURE_EXTRAS.items() if v["default"]}
        for key in FEATURE_EXTRAS:
            mark = "✓" if key in chosen else " "
            _print(f"  [{mark}] {FEATURE_EXTRAS[key]['label']} (default)")
        return chosen

    _print("  note: this installer only ADDS features. Answering 'no' below (or")
    _print("        omitting a feature from --features on a later run) will not")
    _print("        uninstall anything already installed for that feature.")
    chosen = set()
    for key, info in FEATURE_EXTRAS.items():
        size = f" (~{info['extra_download_mb']} MB)"
        if prompt_yes_no(
            f"  install {info['label']}{size}?", default=info["default"], eof_default=False
        ):
            chosen.add(key)
    return chosen


def pick_preset(
    args: argparse.Namespace,
    ram_gb: float,
    vram_gb: float,
    free_vram_gb: float | None,
) -> str | None:
    if args.no_local_llm:
        section("local LLM (Tier 3) — skipped via --no-local-llm")
        return None

    if args.preset:
        section(f"local LLM preset (from --preset): {args.preset}")
        return str(args.preset)

    section("local LLM (Tier 3)")
    if args.yes:
        recommended = recommend_preset(vram_gb, free_vram_gb, ram_gb)
        _print(
            f"  recommended preset: {recommended} ({LLM_PRESETS[recommended]['model']}) — using it"
        )
        return recommended

    if not prompt_yes_no(
        "  enable the Tier-3 local LLM classifier?", default=True, eof_default=False
    ):
        return None

    recommended = recommend_preset(vram_gb, free_vram_gb, ram_gb)
    _print("\n  Tier-3 presets:")
    _print(f"    {'preset':<11} {'model':<16} {'VRAM':>6}  {'RAM':>5}  {'size':>5}  notes")
    for key, info in LLM_PRESETS.items():
        marker = "  (recommended)" if key == recommended else ""
        _print(
            f"    {key:<11} {info['model']:<16} "
            f"{info['vram_gb']:>4} GB  {info['ram_gb']:>3} GB  "
            f"{info['size_gb']:>3} GB  {info['notes']}{marker}"
        )
    return prompt_choice(
        "\n  pick a preset:",
        [(k, LLM_PRESETS[k]["model"]) for k in LLM_PRESETS],
        default=recommended,
    )


def confirm_plan(extras: set[str], preset: str | None) -> bool:
    section("install plan")
    total_mb = 0
    if extras:
        _print("  pip extras:")
        for k in sorted(extras):
            _print(f"    - {k} (~{FEATURE_EXTRAS[k]['extra_download_mb']} MB)")
            total_mb += FEATURE_EXTRAS[k]["extra_download_mb"]
    if "pii" in extras:
        _print("    + spaCy model en_core_web_lg (~750 MB)")
    if "ner" in extras:
        _print("    + HuggingFace model knowledgator/gliner-pii-base-v1.0 (~300 MB)")
    if preset:
        info = LLM_PRESETS[preset]
        _print(f"  Ollama model: {info['model']} (~{info['size_gb']} GB)")
    _print(
        f"\n  estimated additional download: ~{total_mb / 1024:.1f} GB"
        f" (pip extras + spaCy model already counted)"
        if total_mb
        else "  no pip downloads required"
    )
    return prompt_yes_no("\n  proceed?", default=True, eof_default=False)


def _wait_for_command(
    name: str,
    attempts: int = 5,
    delay_seconds: float = 1.0,
    which: Callable[[str], str | None] = shutil.which,
    sleep: Callable[[float], None] = time.sleep,
) -> str | None:
    """Poll ``which(name)`` a few times, sleeping between attempts.

    Windows' winget can return before the installed binary's directory is
    fully registered/visible on ``PATH``, so a single immediate check can
    give a false negative. This gives the OS a few seconds to catch up
    before we declare the install a failure. Returns the resolved path (or
    ``None`` if it never shows up).
    """
    for attempt in range(attempts):
        found = which(name)
        if found:
            return found
        if attempt < attempts - 1:
            sleep(delay_seconds)
    return None


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
        _print("\n▶ Installing Ollama via winget...")
        try:
            subprocess.run(  # noqa: S603  # fixed argv, resolved binary path
                [
                    winget,
                    "install",
                    "Ollama.Ollama",
                    "--accept-source-agreements",
                    "--accept-package-agreements",
                ],
                timeout=300,
            )
            # Refresh PATH so shutil.which can find the new binary
            result = subprocess.run(  # noqa: S603  # fixed powershell snippet
                [  # noqa: S607  # powershell resolved via PATH on every Windows box
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "[Environment]::GetEnvironmentVariable('Path','Machine') + ';' + "
                    "[Environment]::GetEnvironmentVariable('Path','User')",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            os.environ["PATH"] = result.stdout.strip()
            # winget's post-install PATH registration can lag a moment
            # behind the process returning, so poll briefly before giving up.
            if _wait_for_command("ollama"):
                _print("  ✓ Ollama installed")
                return True
        except Exception as exc:
            _print(f"  ⚠ winget install failed: {exc}")
        return False

    if system == "Darwin":
        brew = shutil.which("brew")
        if not brew:
            return False
        _print("\n▶ Installing Ollama via Homebrew...")
        try:
            subprocess.run([brew, "install", "ollama"], timeout=300)  # noqa: S603
            if shutil.which("ollama"):
                _print("  ✓ Ollama installed")
                return True
        except Exception as exc:
            _print(f"  ⚠ brew install failed: {exc}")
        return False

    # Linux: no auto-install, user should use their package manager
    return False


def _ensure_linux_venv() -> None:
    """On Linux, auto-create and re-exec into a `.venv` before doing anything else.

    Mirrors install.ps1 (Windows) and scripts/install.sh (macOS), which both
    create/use a venv before running pip. Without this, `pip install -e` runs
    against the system Python and fails outright on PEP 668
    ("externally-managed-environment") distros like Debian 12+/Ubuntu 23.10+.
    No-op if we're already running inside `.venv` (or not on Linux).
    """
    if platform.system() != "Linux":
        return

    venv_python = ROOT / ".venv" / "bin" / "python"
    try:
        already_in_venv = Path(sys.executable).resolve() == venv_python.resolve()
    except OSError:
        already_in_venv = False
    if already_in_venv:
        return

    if not venv_python.exists():
        _print("▶ creating .venv ...")
        try:
            subprocess.run(  # noqa: S603  # fixed argv
                [sys.executable, "-m", "venv", str(ROOT / ".venv")], check=True
            )
            subprocess.run(  # noqa: S603  # fixed argv
                [str(venv_python), "-m", "pip", "install", "--upgrade", "pip", "--quiet"],
                check=True,
            )
        except (subprocess.CalledProcessError, OSError) as exc:
            _print(f"  ⚠ could not create .venv automatically: {exc}")
            _print("  ⚠ continuing with the current Python interpreter — if the")
            _print("    next step fails with 'externally-managed-environment',")
            _print("    create a venv yourself:")
            _print("      python3 -m venv .venv && source .venv/bin/activate")
            return

    _print("▶ re-launching installer inside .venv ...")
    os.execv(str(venv_python), [str(venv_python), str(REEXEC_SCRIPT), *sys.argv[1:]])  # noqa: S606


def main() -> int:
    try:
        return _run_installer()
    except KeyboardInterrupt:
        _print("\n  cancelled — nothing was installed or changed.")
        return 130


def _run_installer() -> int:
    _ensure_linux_venv()
    args = parse_args()
    banner()

    hw = detect_hardware()

    report_environment(
        hw.ram_gb, hw.gpu, hw.vram_gb, hw.free_vram_gb, hw.ollama_present, hw.ollama_version
    )

    extras = pick_features(args)
    preset = pick_preset(args, hw.ram_gb, hw.vram_gb, hw.free_vram_gb)

    ollama_present = hw.ollama_present
    if preset and not ollama_present:
        ollama_present = _auto_install_ollama()
        if not ollama_present:
            _print("\n  ⚠  Ollama is not installed — Tier 3 will not work until you")
            _print("     install it from https://ollama.com and re-run this installer.")
            if not args.yes and not prompt_yes_no("  continue anyway?", default=False):
                preset = None

    if not args.yes and not confirm_plan(extras, preset):
        _print("\n  aborted.")
        return 1

    install_extras(sorted(extras))

    if "pii" in extras:
        download_spacy_model(FEATURE_EXTRAS["pii"].get("spacy_model", ""))

    if "ner" in extras:
        cache_huggingface_model(FEATURE_EXTRAS["ner"].get("hf_model", ""))

    if preset and ollama_present:
        already = detect_existing_ollama_models()
        pull_ollama_model(LLM_PRESETS[preset]["model"], already)

    config_changed = False
    if preset:
        config_changed, msg = align_dashboard_config(preset)
        _print()
        _print(msg)

    section("done")
    _print("  next steps:")
    if platform.system() == "Windows":
        _print("    run.bat                  start the desktop app")
    else:
        _print("    ./run.sh                 start the desktop app")
    _print("    open http://127.0.0.1:9876/   dashboard")
    _print()
    _print("  note: re-running this installer only ADDS features/presets you")
    _print("        select — it never uninstalls a feature you deselect on a")
    _print("        later run. To remove one, uninstall its pip extra manually")
    _print("        (e.g. `pip uninstall gliner`) and clear the matching")
    _print("        detection_stack toggle in the dashboard.")
    if config_changed:
        _print()
        _print("  ⚠  the dashboard config was updated. If the app is currently")
        _print("     running, stop it (Ctrl+C in the run.bat / run.sh window) and")
        _print("     re-launch — a running app holds the old config in memory and")
        _print("     will overwrite the file on next save.")
    return 0


# ─────────────────────────── first-run walkthrough ─────────────────────────


@dataclass
class WizardChoices:
    """What the user picked during the ``domestique setup`` walkthrough."""

    gliner: bool
    preset: str | None
    browser: bool
    desktop_ui: bool


def _gliner_why(hw: HardwareProfile) -> str:
    if 0 < hw.ram_gb < 8:
        return (
            f"why: catches names/addresses/emails that regex can't, but on your "
            f"{hw.ram_gb:g} GB RAM the 300 MB model may load slowly."
        )
    return (
        f"why: catches names/addresses/emails that regex can't; with your "
        f"{hw.ram_gb:g} GB RAM the 300 MB model runs comfortably (~20 ms/prompt)."
    )


def _tier3_why(hw: HardwareProfile, recommended: str) -> str:
    model = LLM_PRESETS[recommended]["model"]
    usable = hw.free_vram_gb if hw.free_vram_gb is not None else hw.vram_gb
    if hw.gpu:
        return (
            f"why: {hw.gpu} with ~{usable:g} GB usable VRAM -> "
            f"'{recommended}' ({model}) fits without swapping."
        )
    return (
        f"why: no GPU detected -> '{recommended}' ({model}) is the best "
        f"CPU-friendly fit for your {hw.ram_gb:g} GB RAM."
    )


def _browser_why(hw: HardwareProfile) -> str:
    cost = "a real cost on" if 0 < hw.ram_gb < 8 else "fine on"
    return (
        f"why: runs a second always-on proxy process ({cost} your {hw.ram_gb:g} GB RAM); "
        f"only needed to filter ChatGPT/Claude *web* chats - the API proxy already "
        f"covers agents and IDEs. Enable later anytime: domestique browser on"
    )


def _desktop_ui_why(hw: HardwareProfile, is_mac: bool) -> str:
    if is_mac:
        return (
            f"why: adds a native menu-bar toggle for the proxies; pulls the pyobjc "
            f"frameworks (~100 MB) onto your {hw.ram_gb:g} GB RAM machine."
        )
    return (
        "why: adds an always-visible tray toggle; note the [desktop] extra also "
        "bundles the browser-proxy and file-scanning dependencies."
    )


def _decide(question: str, *, default: bool, yes: bool) -> bool:
    """Ask, or auto-accept the recommended default under --yes."""
    if yes:
        suffix = "Y/n" if default else "y/N"
        _print(f"{question} ({suffix}) -> {'yes' if default else 'no'} (auto)")
        return default
    return prompt_yes_no(question, default=default, eof_default=False)


def _wizard_walkthrough(hw: HardwareProfile, *, yes: bool) -> WizardChoices:
    recommended = recommend_preset(hw.vram_gb, hw.free_vram_gb, hw.ram_gb)
    is_mac = platform.system() == "Darwin"

    section("Tier 1 - regex secret scanning")
    _print("  Always on: compiled patterns for API keys, tokens, SSNs and more.")
    _print("  Zero download, ~0.03 ms per prompt. Nothing to decide here.")

    section("Tier 2 - GLiNER PII detection (~300 MB) [ner]")
    _print(f"  {_gliner_why(hw)}")
    gliner = _decide("  enable GLiNER PII detection?", default=hw.ram_gb >= 8, yes=yes)

    section("Tier 3 - local LLM classifier (via Ollama)")
    _print(f"  {_tier3_why(hw, recommended)}")
    if yes:
        model = LLM_PRESETS[recommended]["model"]
        _print(f"  -> using recommended preset: {recommended} ({model}) (auto)")
        preset: str | None = recommended
    else:
        options = [(k, LLM_PRESETS[k]["model"]) for k in LLM_PRESETS]
        options.append(("none", "skip Tier 3 (regex/GLiNER only)"))
        choice = prompt_choice("\n  pick a Tier-3 model:", options, default=recommended)
        preset = None if choice == "none" else choice

    section("Browser protection (~50 MB) [browser-proxy]")
    _print("  Cost first: this installs a local CA certificate and sets a")
    _print("  system-wide proxy so browser HTTPS traffic can be inspected.")
    _print(f"  {_browser_why(hw)}")
    browser = _decide("  enable browser protection?", default=False, yes=yes)

    if is_mac:
        section("macOS menu-bar app [macos-native]")
    else:
        section("System tray icon [desktop]")
    _print(f"  {_desktop_ui_why(hw, is_mac)}")
    ui_label = "install the menu-bar app?" if is_mac else "install the tray icon?"
    desktop_ui = _decide(f"  {ui_label}", default=False, yes=yes)

    return WizardChoices(
        gliner=gliner,
        preset=preset,
        browser=browser,
        desktop_ui=desktop_ui,
    )


def _choices_to_extras(choices: WizardChoices) -> list[str]:
    extras: list[str] = []
    if choices.gliner:
        extras.append("ner")
    if choices.browser:
        extras.append("browser-proxy")
    if choices.desktop_ui:
        extras.append("macos-native" if platform.system() == "Darwin" else "desktop")
    return extras


def _confirm_wizard_plan(choices: WizardChoices, extras: list[str]) -> bool:
    section("plan")
    _print("  Tier 1 regex        always on")
    _print(f"  GLiNER PII          {'yes (~300 MB)' if choices.gliner else 'no'}")
    if choices.preset:
        info = LLM_PRESETS[choices.preset]
        _print(f"  Tier 3 LLM          {choices.preset} ({info['model']}, ~{info['size_gb']} GB)")
    else:
        _print("  Tier 3 LLM          none")
    _print(f"  Browser protection  {'yes (local CA + system proxy)' if choices.browser else 'no'}")
    _print(f"  Desktop UI          {'yes' if choices.desktop_ui else 'no'}")
    if extras:
        _print(f"  pip extras          {', '.join(extras)}")
    return prompt_yes_no("\n  proceed?", default=True, eof_default=False)


def _install_wizard_selection(choices: WizardChoices) -> None:
    extras = _choices_to_extras(choices)
    wizard_install_extras(extras)

    if choices.gliner:
        cache_huggingface_model(FEATURE_EXTRAS["ner"].get("hf_model", ""))

    if choices.preset:
        ollama_present, _version = detect_ollama()
        if not ollama_present:
            ollama_present = _auto_install_ollama()
        model = LLM_PRESETS[choices.preset]["model"]
        if ollama_present:
            pull_ollama_model(model, detect_existing_ollama_models())
        else:
            _print("\n  ⚠  Ollama is not installed — Tier 3 stays configured but idle.")
            _print(f"     Install it from https://ollama.com, then: ollama pull {model}")


def _stdin_is_tty() -> bool:
    """True only for a live interactive stdin (None/closed → False)."""
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except ValueError:
        return False


def _run_finale_demo(*, interactive: bool = False) -> None:
    """Show the in-process redaction demo before any server starts.

    ``interactive`` enables the try-your-own loop — must stay False for
    ``--yes`` runs, which promise zero questions even on a TTY.
    """
    section("demo - watch it redact")
    try:
        from domestique.cli import run_demo

        run_demo(interactive=interactive)
    except Exception as exc:  # demo is decorative — never fail setup over it
        _print(f"  (demo skipped: {exc})")


def run_wizard(*, yes: bool = False, demo: bool = True) -> int:
    """The ``domestique setup`` walkthrough. Returns a process exit code."""
    _print("=" * 64)
    _print("  Domestique setup — hardware-aware configuration (re-run anytime)")
    _print("=" * 64)

    hw = detect_hardware()
    report_environment(
        hw.ram_gb, hw.gpu, hw.vram_gb, hw.free_vram_gb, hw.ollama_present, hw.ollama_version
    )

    choices = _wizard_walkthrough(hw, yes=yes)
    extras = _choices_to_extras(choices)

    if not yes and not _confirm_wizard_plan(choices, extras):
        _print("\n  aborted — nothing was installed or changed.")
        return 1

    _install_wizard_selection(choices)

    cfg_path = apply_wizard_config(
        gliner=choices.gliner,
        preset=choices.preset,
        browser=choices.browser,
    )
    _print(f"\n  ✓ configuration written to {cfg_path}")

    if demo:
        _run_finale_demo(interactive=not yes and _stdin_is_tty())

    section("setup complete")
    _print("  next: domestique start          launch the redacting proxy")
    if choices.browser or choices.desktop_ui:
        _print("        python -m app             start the dashboard + browser protection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
