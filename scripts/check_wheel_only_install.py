"""Fail if today's dependency resolution would need to build anything from
source (no prebuilt wheel for this platform/interpreter).

    pip install --dry-run --report pip-report.json -e ".[dev]"
    python scripts/check_wheel_only_install.py pip-report.json

Generalizes across every dependency and every future version bump: this
doesn't name any package, it inspects pip's own resolution report and flags
any resolved distribution whose download came from a source archive
(``.tar.gz``/``.zip``) instead of a wheel (``.whl``). A dependency that ships
wheels for this platform never triggers this; one that silently drops wheel
support (litellm did exactly this at 1.92.0, switching to a Rust/maturin
build with Linux-only wheels on PyPI) fails loudly here instead of
surprising a contributor with a bare Cargo/compiler error mid-`pip install`.

Runs on CI's hosted Windows/macOS runners, which usually have a rich enough
C/Rust toolchain to build such a package anyway -- so the *install itself*
can quietly succeed there while still being broken for a real contributor's
machine. This check doesn't care whether the build would succeed: needing a
source build on Windows/macOS at all is the thing being flagged.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_SOURCE_SUFFIXES = (".tar.gz", ".tar.bz2", ".zip")


def main(argv: list[str]) -> int:
    report_path = Path(argv[0] if argv else "pip-report.json")
    data = json.loads(report_path.read_text(encoding="utf-8"))
    installs = data.get("install", [])

    offenders = []
    for item in installs:
        url = item.get("download_info", {}).get("url", "")
        if url.endswith(_SOURCE_SUFFIXES):
            name = item["metadata"]["name"]
            version = item["metadata"]["version"]
            offenders.append(f"{name}=={version}  ({url})")

    if offenders:
        print(
            "The following packages have no prebuilt wheel for this platform "
            "and would be built from source (requiring a compiler/Rust/etc. "
            "toolchain a fresh contributor machine may not have):\n"
        )
        for line in offenders:
            print(f"  - {line}")
        print(
            "\nPin the offending dependency to a version with real wheels for "
            "this platform, or explicitly accept and document the new build-"
            "toolchain requirement -- don't let it in silently via a routine "
            "version bump."
        )
        return 1

    print(f"OK: all {len(installs)} resolved packages have prebuilt wheels for this platform.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
