#!/usr/bin/env python3
"""Prove `domestique setup` can actually install an extra into a pipx install.

The bug this exists to catch shipped and reached a user. The wizard ran

    pipx inject domestique domestique[ner]

which injects the app into *itself*. Older pipx answers "domestique already
seems to be injected ... Pass '--force'" and installs nothing, so the wizard
reported success and then died on `ModuleNotFoundError: No module named
'gliner'`. Newer pipx accepts it — so the failure only reproduced on a user's
machine, never the maintainer's, and no test covered it.

Two properties matter, and asserting only the second is what let this through:

  1. the command must be *built* correctly, and
  2. running it must leave the extra genuinely importable.

So this drives the real ``extras_install_argv`` from the installed package
rather than a hard-coded command. Drop ``--force`` and this fails.

Usage:
    python scripts/check_pipx_extras_install.py [--extra file-scanning]
                                                [--module openpyxl]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(argv: list[str], env: dict[str, str], *, label: str) -> subprocess.CompletedProcess[str]:
    print(f"\n$ {' '.join(argv)}")
    proc = subprocess.run(argv, env=env, capture_output=True, text=True, check=False)  # noqa: S603
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        sys.exit(f"FAIL: {label} exited {proc.returncode}")
    return proc


def _module_importable(python: Path, module: str) -> bool:
    code = f"import importlib.util,sys;sys.exit(0 if importlib.util.find_spec('{module}') else 1)"
    probe = subprocess.run(  # noqa: S603
        [str(python), "-c", code], capture_output=True, check=False
    )
    return probe.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    # file-scanning is the cheapest extra with a distinctive import; the bug is
    # in the injection mechanism, not in any particular extra.
    ap.add_argument("--extra", default="file-scanning")
    ap.add_argument("--module", default="openpyxl")
    args = ap.parse_args()

    if not shutil.which("pipx"):
        sys.exit("FAIL: pipx is not on PATH")

    dist = ROOT / "dist"
    wheels = sorted(dist.glob("domestique-*.whl"))
    if not wheels:
        sys.exit(f"FAIL: no wheel in {dist} — run `python -m build` first")
    wheel = wheels[-1]

    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        env = {
            **os.environ,
            "PIPX_HOME": str(home / "pipx"),
            "PIPX_BIN_DIR": str(home / "bin"),
            # The extras spec names `domestique` itself, so the resolver needs
            # somewhere to find it. Locally that is the wheel we just built;
            # after publishing it is PyPI. Both backends are covered because
            # pipx may shell out to uv or to pip depending on version.
            "PIP_FIND_LINKS": str(dist),
            "UV_FIND_LINKS": str(dist),
        }

        _run(["pipx", "install", str(wheel)], env, label="pipx install")
        venv_python = home / "pipx" / "venvs" / "domestique" / "bin" / "python"
        if not venv_python.exists():  # Windows layout
            venv_python = home / "pipx" / "venvs" / "domestique" / "Scripts" / "python.exe"
        if not venv_python.exists():
            sys.exit(f"FAIL: could not locate the pipx venv interpreter under {home}")

        if _module_importable(venv_python, args.module):
            sys.exit(
                f"FAIL: {args.module} is importable before the extra was installed — "
                "this check cannot prove anything. Pick a module unique to the extra."
            )
        print(f"baseline OK: {args.module} not importable")

        # Ask the *product* what command to run, so this cannot drift from it.
        argv_json = subprocess.run(  # noqa: S603
            [
                str(venv_python),
                "-c",
                "import json;from domestique.setup_wizard import extras_install_argv;"
                f"print(json.dumps(extras_install_argv(['{args.extra}'], env_kind='pipx')))",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        argv = json.loads(argv_json)
        print(f"product-built argv: {argv}")

        if "--force" not in argv:
            sys.exit(
                "FAIL: extras_install_argv omits --force. pipx treats injecting the app "
                "into itself as already-injected and installs nothing."
            )

        _run(argv, env, label="extras install")

        if not _module_importable(venv_python, args.module):
            sys.exit(
                f"FAIL: {args.module} still not importable after `{' '.join(argv)}`. "
                "The command reported success but installed nothing — exactly the "
                "failure mode this check exists to catch."
            )

    print(f"\nOK: `{args.extra}` extra installed into the pipx venv; {args.module} importable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
