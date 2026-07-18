"""Unit tests — GLiNER detector fail-closed reason (C5).

Regression guard for the "opaque detector_error" bug: when GLiNER PII
detection is enabled via ``detection_stack.gliner_pii`` but the ``gliner``
package is not installed, or its model was never cached locally, every
scanned request must be flagged with the distinct, actionable category
``gliner_not_cached`` instead of the generic ``pipeline:detector_error``
that every other unexpected detector exception collapses into.

It also asserts the fail-closed BLOCK decision itself: ``domestique/policy/
browser-rules.yaml`` has an explicit ``block-detector-failures`` rule matching both
``detector_error`` and ``gliner_not_cached`` at high confidence, so a
synthetic failure finding must always resolve to ``Action.BLOCK`` /
``should_block is True`` - never silently ALLOW.
"""

from __future__ import annotations

import asyncio
import sys
import types

import pytest

from domestique.config import Settings
from domestique.detectors.registry import create_detector_pipeline
from domestique.models import Action


def _gliner_only_settings() -> Settings:
    return Settings(
        enable_gliner=True,
        enable_secret_detection=False,
        enable_pii_detection=False,
        enable_semantic_detection=False,
        enable_local_llm=False,
    )


class TestGLiNERNotCached:
    def test_missing_package_yields_gliner_not_cached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`gliner` package not installed -> ModuleNotFoundError -> gliner_not_cached."""
        monkeypatch.setitem(sys.modules, "gliner", None)  # forces ImportError on `import gliner`

        pipeline = create_detector_pipeline(_gliner_only_settings())
        result = asyncio.run(pipeline.inspect("hello, this text is long enough to scan"))

        categories = {f.category for f in result.findings}
        detectors = {f.detector for f in result.findings}
        assert "gliner_not_cached" in categories
        assert "detector_error" not in categories
        assert "gliner_pii" in detectors
        assert result.action is Action.BLOCK
        assert result.should_block is True

    def test_uncached_model_yields_gliner_not_cached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`gliner` package present but model not in the offline HF cache -> OSError -> gliner_not_cached."""
        fake_gliner = types.ModuleType("gliner")

        class _FakeGLiNER:
            @staticmethod
            def from_pretrained(_name: str) -> "_FakeGLiNER":
                # Mirrors huggingface_hub.errors.LocalEntryNotFoundError, which
                # subclasses FileNotFoundError -> OSError.
                raise OSError("model not found in local cache (HF_HUB_OFFLINE=1)")

        fake_gliner.GLiNER = _FakeGLiNER  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "gliner", fake_gliner)

        pipeline = create_detector_pipeline(_gliner_only_settings())
        result = asyncio.run(pipeline.inspect("hello, this text is long enough to scan"))

        categories = {f.category for f in result.findings}
        assert "gliner_not_cached" in categories
        assert "detector_error" not in categories
        assert result.action is Action.BLOCK
        assert result.should_block is True

    def test_only_warns_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The one-time actionable log must not spam on every request."""
        monkeypatch.setitem(sys.modules, "gliner", None)

        warnings: list[tuple] = []
        import domestique.detectors.registry as registry_mod

        monkeypatch.setattr(
            registry_mod.logger,
            "warning",
            lambda *a, **kw: warnings.append((a, kw)),
        )

        pipeline = create_detector_pipeline(_gliner_only_settings())
        asyncio.run(pipeline.inspect("first request long enough to scan"))
        asyncio.run(pipeline.inspect("second request also long enough to scan"))

        gliner_warnings = [w for w in warnings if w[0] and w[0][0] == "gliner_not_cached"]
        assert len(gliner_warnings) == 1

    def test_unexpected_scan_error_still_falls_back_to_detector_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A genuinely unexpected failure (not missing-package/missing-cache)
        must still surface as the generic detector_error - the new category
        must not swallow real bugs."""
        fake_gliner = types.ModuleType("gliner")

        class _FakeGLiNER:
            @staticmethod
            def from_pretrained(_name: str) -> "_FakeGLiNER":
                return _FakeGLiNER()

            def predict_entities(self, *_args, **_kwargs):
                raise RuntimeError("unexpected inference crash, unrelated to caching")

        fake_gliner.GLiNER = _FakeGLiNER  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "gliner", fake_gliner)

        pipeline = create_detector_pipeline(_gliner_only_settings())
        result = asyncio.run(pipeline.inspect("hello, this text is long enough to scan"))

        categories = {f.category for f in result.findings}
        assert "detector_error" in categories
        assert "gliner_not_cached" not in categories
        assert result.action is Action.BLOCK
        assert result.should_block is True
