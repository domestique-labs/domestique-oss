"""Presidio detector emits canonical taxonomy categories, like every other tier.

The ten entities in ``_ENTITIES`` happen to lowercase straight into
``CANONICAL`` keys, so today's ``entity_type.lower()`` produces the right
answer for the shipped configuration. That is an unenforced coincidence, not a
guarantee: ``AnalyzerEngine`` returns whatever its registry holds, and a custom
or additional recognizer (``SSN``, ``EMAIL``) would emit a spelling that only
``normalize_category`` knows how to fold. These tests pin the invariant.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from domestique.detectors.pii import PIIDetector
from domestique.taxonomy import CANONICAL, normalize_category


@dataclass
class _FakeResult:
    entity_type: str
    start: int
    end: int
    score: float


class _FakeAnalyzer:
    """Stands in for ``presidio_analyzer.AnalyzerEngine``."""

    def __init__(self, entity_type: str) -> None:
        self._entity_type = entity_type

    def analyze(self, **kwargs: object) -> list[_FakeResult]:
        return [_FakeResult(entity_type=self._entity_type, start=0, end=4, score=0.9)]


def _scan_with(entity_type: str) -> list[object]:
    detector = PIIDetector()
    detector._analyzer = _FakeAnalyzer(entity_type)  # bypass lazy load
    detector._available = True
    return asyncio.run(detector.scan("some text to scan"))


@pytest.mark.parametrize(
    ("entity_type", "expected"),
    [
        ("SSN", "us_ssn"),  # alias fold
        ("E_MAIL", "email_address"),  # alias fold
        ("PHONE", "phone_number"),  # alias fold
        ("EMAIL_ADDRESS", "email_address"),  # already canonical, must not regress
        ("US_SSN", "us_ssn"),
    ],
)
def test_pii_emits_canonical_category(entity_type: str, expected: str) -> None:
    dets = _scan_with(entity_type)
    assert dets
    assert dets[0].category == expected
    assert dets[0].category in CANONICAL


def test_pii_category_is_normalize_category_of_entity_type() -> None:
    """The invariant itself: output == normalize_category(entity_type)."""
    for entity_type in ("PERSON", "US_DRIVER_LICENSE", "MEDICAL_LICENSE", "LOCATION"):
        dets = _scan_with(entity_type)
        assert dets[0].category == normalize_category(entity_type)
