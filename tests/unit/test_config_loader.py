from __future__ import annotations

from typing import TYPE_CHECKING

from domestique.config_loader import load_config_dict, settings_from_config

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


class TestSettingsFromConfig:
    def test_empty_config_is_defaults(self) -> None:
        s = settings_from_config({})
        assert s.enable_secret_detection is True  # regex default on
        assert s.enable_gliner is False
        assert s.enable_local_llm is False

    def test_gliner_flag_enables_gliner(self) -> None:
        s = settings_from_config({"detection_stack": {"regex": True, "gliner_pii": True}})
        assert s.enable_gliner is True

    def test_qwen_preset_selects_model(self) -> None:
        s = settings_from_config({"detection_stack": {"qwen3_1_7b": True}})
        assert s.enable_local_llm is True
        assert s.local_llm_model == "qwen3:1.7b"

    def test_legacy_cpu_selects_llama(self) -> None:
        s = settings_from_config({"detection_stack": {"legacy_cpu": True}})
        assert s.enable_local_llm is True
        assert s.local_llm_model == "llama3.2:1b"

    def test_disabled_patterns_pass_through(self) -> None:
        s = settings_from_config({"disabled_builtin_patterns": ["phone_number"]})
        assert s.disabled_builtin_patterns == ["phone_number"]

    def test_llm_preset_is_mapped(self) -> None:
        s = settings_from_config({"llm_preset": "quality"})
        assert s.local_llm_preset == "quality"

    def test_llm_preset_absent_keeps_default(self) -> None:
        s = settings_from_config({})
        assert s.local_llm_preset == "balanced"  # Settings() default

    def test_llm_preset_invalid_value_falls_back_to_default(self) -> None:
        s = settings_from_config({"llm_preset": "bogus"})
        assert s.local_llm_preset == "balanced"  # ignore unknown values


class TestLoadConfigDict:
    def test_missing_file_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import domestique.config_loader as cl

        monkeypatch.setattr(cl, "DOMESTIQUE_HOME", tmp_path)
        assert load_config_dict() == {}

    def test_reads_existing_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        import domestique.config_loader as cl

        monkeypatch.setattr(cl, "DOMESTIQUE_HOME", tmp_path)
        (tmp_path / "config.json").write_text(json.dumps({"llm_preset": "quality"}))
        assert load_config_dict()["llm_preset"] == "quality"

    def test_invalid_json_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import domestique.config_loader as cl

        monkeypatch.setattr(cl, "DOMESTIQUE_HOME", tmp_path)
        (tmp_path / "config.json").write_text("{ not json")
        assert load_config_dict() == {}
