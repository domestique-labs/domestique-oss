"""Thin compatibility shim — the installer now lives in domestique.setup_wizard.

Everything that used to be defined here (hardware detection, LLM presets,
prompts, extras install, Ollama pull, dashboard-config alignment) moved to
``domestique/setup_wizard.py`` so the ``domestique setup`` CLI can reuse it.

Both historical entry points keep working unchanged:

    python scripts/install.py [--yes] [--features ...] [--preset ...]
    from scripts import install   # tests / tooling

The module-alias assignment below makes ``scripts.install`` *be* the
``domestique.setup_wizard`` module object, so monkeypatching attributes on
``scripts.install`` (as the unit tests do) patches the real implementation.
"""

from __future__ import annotations

import sys
from pathlib import Path

# This is the bootstrap installer — it may be run by old system pythons
# (Ubuntu 22.04 / Debian 11 ship 3.10). The wizard module uses 3.11+ syntax,
# so fail with a clear message instead of an opaque ImportError.
if sys.version_info < (3, 11):  # noqa: UP036 — guard MUST run on older interpreters
    sys.exit(
        "Domestique requires Python 3.11+ "
        f"(this is {sys.version_info.major}.{sys.version_info.minor}). "
        "Install a newer Python first, e.g.: uv python install 3.12"
    )

# Support direct invocation from a source checkout where the repo root (and
# therefore the ``domestique`` package) is not yet on sys.path — this script
# is the bootstrap installer, so it must run before any pip install.
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from domestique import setup_wizard as _wizard  # noqa: E402

if __name__ == "__main__":
    # Keep the Linux venv bootstrap re-exec pointed at this script, not at
    # the package module (which is not meant to be run by path).
    _wizard.REEXEC_SCRIPT = Path(__file__).resolve()
    sys.exit(_wizard.main())
else:
    # Alias the module so `from scripts import install` yields the real
    # implementation module (see docstring).
    sys.modules[__name__] = _wizard
