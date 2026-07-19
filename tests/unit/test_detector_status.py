"""Tests for the startup detector-availability probe (UX-2 fail-loud/strict)."""

from __future__ import annotations

from domestique.config import Settings
from domestique.detectors import status as st


def test_pii_unavailable_when_module_missing(monkeypatch) -> None:
    monkeypatch.setattr(st, "_module_available", lambda name: False)
    settings = Settings(enable_pii_detection=True)
    pii = next(s for s in st.detector_status(settings) if s.key == "pii")
    assert pii.configured is True
    assert pii.available is False
    assert "pii" in pii.install_hint.lower()


def test_pii_not_configured_when_disabled(monkeypatch) -> None:
    monkeypatch.setattr(st, "_module_available", lambda name: True)
    settings = Settings(enable_pii_detection=False)
    pii = next(s for s in st.detector_status(settings) if s.key == "pii")
    assert pii.configured is False
    assert pii.available is False


def test_available_when_module_present(monkeypatch) -> None:
    monkeypatch.setattr(st, "_module_available", lambda name: True)
    settings = Settings(enable_pii_detection=True)
    pii = next(s for s in st.detector_status(settings) if s.key == "pii")
    assert pii.available is True


def test_unavailable_configured_filters_to_broken_tiers(monkeypatch) -> None:
    # gliner present, presidio missing
    monkeypatch.setattr(st, "_module_available", lambda name: name != "presidio_analyzer")
    settings = Settings(enable_pii_detection=True, enable_gliner=True)
    missing = st.unavailable_configured(st.detector_status(settings))
    assert {m.key for m in missing} == {"pii"}
