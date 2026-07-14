from __future__ import annotations

import tomllib
from pathlib import Path


def _pyproject() -> dict:
    return tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))


def test_console_script_declared():
    scripts = _pyproject()["project"]["scripts"]
    assert scripts["llmguard"] == "llmguard.cli:main"


def test_build_system_declared():
    build = _pyproject()["build-system"]
    assert "setuptools" in build["requires"][0]


def test_wedge_policy_shipped_as_package_data():
    data = _pyproject()["tool"]["setuptools"]["package-data"]
    globs = data.get("llmguard.policy") or data.get("llmguard") or []
    assert any(g.endswith(".yaml") for g in globs)
