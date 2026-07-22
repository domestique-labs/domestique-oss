"""GLiNER detector emits canonical taxonomy categories, not ``pii:<label>``."""

from __future__ import annotations

import asyncio

from domestique.config import Settings
from domestique.detectors.registry import build_detectors


class _FakeModel:
    def predict_entities(self, text: str, labels: list[str]) -> list[dict[str, object]]:
        return [{"label": "person", "text": "Jane Doe", "score": 0.9}]


def test_gliner_emits_canonical_category() -> None:
    settings = Settings()
    settings.enable_gliner = True
    settings.gliner_labels = ["person"]
    detectors = build_detectors(settings)
    gliner = next(d for d in detectors if type(d).__name__ == "_GLiNERDetector")
    gliner._model = _FakeModel()  # bypass lazy load
    gliner._unavailable = False
    dets = asyncio.run(gliner.scan("Contact Jane Doe today"))
    assert dets and dets[0].category == "person"  # not "pii:person"
