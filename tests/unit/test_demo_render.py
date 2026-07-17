from __future__ import annotations

from domestique.cli import _render_config_header
from domestique.config import Settings
from domestique.policy import PolicyEngine


class TestConfigHeader:
    def test_shows_active_preset_and_regex_on(self) -> None:
        settings = Settings()  # regex on, preset default "balanced"
        out = _render_config_header(settings, PolicyEngine.from_yaml_default(), color=False)
        assert "Regex" in out
        assert "[balanced]" in out  # active preset bracketed
        assert "redact on" in out
        assert "block on" in out  # wedge policy blocks crown-jewels
        assert "\033[" not in out  # color=False -> no ANSI

    def test_disabled_tiers_marked(self) -> None:
        out = _render_config_header(Settings(), PolicyEngine.from_yaml_default(), color=False)
        assert "GLiNER" in out
