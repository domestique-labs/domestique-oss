"""Tests for the `domestique setup --yes` non-interactive path.

Hardware detection and every executing step (pip installs, HF caching,
Ollama pulls) are mocked; the tests assert the DECISIONS -- which extras
get requested and what lands in ~/.domestique/config.json (pointed at a
tmp dir, following the pattern in test_install_presets.py).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

import domestique.setup_wizard as wizard


@pytest.fixture()
def mocked_machine(monkeypatch, tmp_path):
    """A 16 GB Apple-Silicon-like machine with Ollama installed, no real exec."""
    monkeypatch.setattr(wizard, "DOMESTIQUE_HOME", tmp_path)
    hw = wizard.HardwareProfile(
        ram_gb=16.0,
        gpu="Apple Silicon (unified memory ~ 16 GB)",
        vram_gb=16.0,
        free_vram_gb=None,
        ollama_present=True,
        ollama_version="ollama version 0.5.0",
    )
    monkeypatch.setattr(wizard, "detect_hardware", lambda: hw)
    monkeypatch.setattr(wizard, "detect_ollama", lambda: (True, "ollama version 0.5.0"))
    monkeypatch.setattr(wizard, "detect_existing_ollama_models", set)
    run = MagicMock(return_value=0)
    monkeypatch.setattr(wizard, "run", run)
    return tmp_path, run


class TestWizardYes:
    def test_writes_expected_config_for_16gb_machine(self, mocked_machine):
        tmp_path, _run = mocked_machine
        assert wizard.run_wizard(yes=True, demo=False) == 0

        data = json.loads((tmp_path / "config.json").read_text())
        stack = data["detection_stack"]
        # 16 GB usable VRAM -> 'quality' preset -> gemma4_e2b stack flag.
        assert data["llm_preset"] == "quality"
        assert stack["gemma4_e2b"] is True
        assert stack["qwen3_1_7b"] is False
        assert stack["legacy_cpu"] is False
        # Recommended defaults: regex on, GLiNER on.
        assert stack["regex"] is True
        assert stack["gliner_pii"] is True
        # Browser protection defaults to NO (local CA + system proxy cost).
        assert data["browser_interception"] is False
        # Wizard answers are explicit configuration.
        assert data["detection_stack_configured"] is True
        assert data["browser_interception_configured"] is True

    def test_installs_ner_and_pulls_recommended_model(self, mocked_machine):
        tmp_path, run = mocked_machine
        wizard.run_wizard(yes=True, demo=False)

        commands = [" ".join(str(c) for c in call.args[0]) for call in run.call_args_list]
        assert any("ner" in cmd and "install" in cmd for cmd in commands)
        assert any(cmd == "ollama pull gemma4:e4b" for cmd in commands)
        # browser-proxy was declined by default -> never installed.
        assert not any("browser-proxy" in cmd for cmd in commands)

    def test_low_end_machine_gets_light_config(self, monkeypatch, tmp_path):
        """4 GB RAM, no GPU -> legacy-cpu preset, GLiNER off by default."""
        monkeypatch.setattr(wizard, "DOMESTIQUE_HOME", tmp_path)
        hw = wizard.HardwareProfile(
            ram_gb=4.0,
            gpu=None,
            vram_gb=0.0,
            free_vram_gb=None,
            ollama_present=True,
            ollama_version="0.5.0",
        )
        monkeypatch.setattr(wizard, "detect_hardware", lambda: hw)
        monkeypatch.setattr(wizard, "detect_ollama", lambda: (True, "0.5.0"))
        monkeypatch.setattr(wizard, "detect_existing_ollama_models", set)
        monkeypatch.setattr(wizard, "run", MagicMock(return_value=0))

        wizard.run_wizard(yes=True, demo=False)

        data = json.loads((tmp_path / "config.json").read_text())
        assert data["llm_preset"] == "legacy-cpu"
        assert data["detection_stack"]["legacy_cpu"] is True
        assert data["detection_stack"]["gliner_pii"] is False

    def test_finale_runs_demo_before_returning(self, mocked_machine, monkeypatch):
        import domestique.cli as cli

        demo = MagicMock(return_value=0)
        monkeypatch.setattr(cli, "run_demo", demo)
        wizard.run_wizard(yes=True, demo=True)
        demo.assert_called_once()

    def test_merges_into_existing_config(self, mocked_machine):
        """Wizard answers must not clobber unrelated existing settings."""
        tmp_path, _run = mocked_machine
        (tmp_path / "config.json").write_text(json.dumps({"proxy_port": 8123}))
        wizard.run_wizard(yes=True, demo=False)
        data = json.loads((tmp_path / "config.json").read_text())
        assert data["proxy_port"] == 8123
        assert data["detection_stack"]["regex"] is True
