"""Tests for the env-aware install helpers in domestique.setup_wizard.

The wizard must produce the correct install argv for the environment it
runs in (pipx-managed venv, uv tool environment, or a plain venv/pip
install). Only the DECISION logic is tested -- nothing is ever executed.
"""

from __future__ import annotations

import sys

from domestique.setup_wizard import detect_install_env, extras_install_argv


class TestDetectInstallEnv:
    def test_pipx_via_prefix_posix(self):
        prefix = "/home/u/.local/pipx/venvs/domestique"
        assert detect_install_env(prefix=prefix, environ={}) == "pipx"

    def test_pipx_via_prefix_macos(self):
        prefix = "/Users/u/Library/Application Support/pipx/venvs/domestique"
        assert detect_install_env(prefix=prefix, environ={}) == "pipx"

    def test_pipx_via_prefix_windows(self):
        prefix = "C:\\Users\\u\\pipx\\venvs\\domestique"
        assert detect_install_env(prefix=prefix, environ={}) == "pipx"

    def test_pipx_via_pipx_home_env(self):
        prefix = "/custom/px-venvs/venvs/domestique"
        environ = {"PIPX_HOME": "/custom/px-venvs"}
        assert detect_install_env(prefix=prefix, environ=environ) == "pipx"

    def test_uv_tool_via_prefix(self):
        prefix = "/home/u/.local/share/uv/tools/domestique"
        assert detect_install_env(prefix=prefix, environ={}) == "uv-tool"

    def test_uv_tool_via_uv_tool_dir_env(self):
        prefix = "/opt/mytools/domestique"
        environ = {"UV_TOOL_DIR": "/opt/mytools"}
        assert detect_install_env(prefix=prefix, environ=environ) == "uv-tool"

    def test_plain_venv_is_pip(self):
        prefix = "/home/u/dev/project/.venv"
        assert detect_install_env(prefix=prefix, environ={}) == "pip"

    def test_system_python_is_pip(self):
        assert detect_install_env(prefix="/usr", environ={}) == "pip"

    def test_env_vars_do_not_misfire_when_prefix_elsewhere(self):
        """PIPX_HOME being set doesn't mean THIS interpreter is pipx-managed."""
        prefix = "/home/u/dev/project/.venv"
        environ = {"PIPX_HOME": "/home/u/.local/pipx-store"}
        assert detect_install_env(prefix=prefix, environ=environ) == "pip"


class TestExtrasInstallArgv:
    def test_pipx_argv(self):
        argv = extras_install_argv(["ner"], env_kind="pipx")
        assert argv == ["pipx", "inject", "domestique", "domestique[ner]"]

    def test_uv_tool_argv(self):
        argv = extras_install_argv(["browser-proxy"], env_kind="uv-tool")
        assert argv == ["uv", "tool", "install", "--force", "domestique[browser-proxy]"]

    def test_pip_argv_uses_current_interpreter(self):
        argv = extras_install_argv(["ner"], env_kind="pip")
        assert argv == [sys.executable, "-m", "pip", "install", "domestique[ner]"]

    def test_multiple_extras_sorted_into_one_spec(self):
        argv = extras_install_argv(["ner", "browser-proxy"], env_kind="pipx")
        assert argv[-1] == "domestique[browser-proxy,ner]"

    def test_defaults_to_detected_env(self, monkeypatch):
        """Without env_kind, the argv reflects detect_install_env()."""
        import domestique.setup_wizard as wizard

        monkeypatch.setattr(wizard, "detect_install_env", lambda: "pipx")
        assert extras_install_argv(["ner"])[0] == "pipx"
