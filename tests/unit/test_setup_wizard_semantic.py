"""Tests for the Tier 2c (semantic) install + offline-guard wiring.

Two gaps this covers:

1. ``domestique`` installer now offers the ``semantic`` extra and pre-caches
   the sentence-transformer model, so enabling Tier 2c later never triggers a
   live model download on the request hot path.
2. ``SemanticDetector`` loads its embedding model offline-first: a cold cache
   fails fast (detector disabled) instead of fetching mid-scan, mirroring
   GLiNER (Tier 2b).
"""

from __future__ import annotations

import os
import sys
import types
from unittest.mock import MagicMock

import domestique.setup_wizard as wizard


class TestSemanticFeatureExtra:
    def test_semantic_is_offered(self):
        info = wizard.FEATURE_EXTRAS["semantic"]
        assert info["extra"] == "semantic"
        assert info["st_model"] == "all-MiniLM-L6-v2"
        # Default-off: the embedding model is only useful once the operator
        # configures sensitive_topics, so it is opt-in.
        assert info["default"] is False

    def test_features_all_includes_semantic(self):
        assert "semantic" in wizard.parse_features_arg("all")

    def test_installer_caches_semantic_model(self, monkeypatch):
        run = MagicMock(return_value=0)
        monkeypatch.setattr(wizard, "run", run)
        monkeypatch.setattr(wizard, "_ensure_linux_venv", lambda: None)
        hw = wizard.HardwareProfile(
            ram_gb=16.0,
            gpu=None,
            vram_gb=0.0,
            free_vram_gb=None,
            ollama_present=False,
            ollama_version=None,
        )
        monkeypatch.setattr(wizard, "detect_hardware", lambda: hw)
        monkeypatch.setattr(
            sys,
            "argv",
            ["domestique-install", "--yes", "--features", "semantic", "--no-local-llm"],
        )

        assert wizard._run_installer() == 0

        commands = [" ".join(str(c) for c in call.args[0]) for call in run.call_args_list]
        # The extra is installed and the model is pre-cached in the same run.
        assert any("semantic" in cmd and "install" in cmd for cmd in commands)
        assert any("sentence_transformers" in cmd for cmd in commands)
        # Only semantic was requested -> no other ML tier was pulled.
        assert not any("gliner" in cmd for cmd in commands)
        assert not any("spacy" in cmd for cmd in commands)


class TestSemanticOfflineGuard:
    def test_cold_cache_fails_fast_offline(self, monkeypatch):
        from domestique.detectors.semantic import SemanticDetector

        monkeypatch.delenv("HF_HUB_OFFLINE", raising=False)

        # Fake sentence_transformers whose model construction behaves like a
        # cold, offline HF cache: huggingface_hub raises LocalEntryNotFoundError,
        # an OSError subclass.
        fake_mod = types.ModuleType("sentence_transformers")

        class _ColdCacheModel:
            def __init__(self, *args, **kwargs):
                raise OSError("LocalEntryNotFoundError: model not cached and offline")

        fake_mod.SentenceTransformer = _ColdCacheModel  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "sentence_transformers", fake_mod)

        det = SemanticDetector(sensitive_topics=["merger talks"], enable_embedding_model=True)

        # Cold cache -> detector disables itself instead of raising.
        assert det._get_model() is None
        assert det._available is False
        # The loader forced offline mode, so the miss above was a fast local
        # lookup rather than a network fetch on the request path.
        assert os.environ.get("HF_HUB_OFFLINE") == "1"

    def test_missing_extra_disables_detector(self, monkeypatch):
        from domestique.detectors.semantic import SemanticDetector

        # Simulate the extra never being installed.
        monkeypatch.setitem(sys.modules, "sentence_transformers", None)

        det = SemanticDetector(sensitive_topics=["merger talks"], enable_embedding_model=True)
        assert det._get_model() is None
        assert det._available is False
