"""The workshop benchmark must score the categories detectors actually emit.

``APIHandler._CATEGORY_MAP`` used to be keyed on ``llm_classified:`` / ``pii:``
spellings. ``domestique.taxonomy.normalize_category`` strips both prefixes
before any ``Detection`` is constructed, so no detector can ever emit those
keys; every real category fell through to the ``CREDENTIALS`` fallback and was
scored against CUSTOMER_DATA ground truth.
"""

from __future__ import annotations

import pytest

from domestique.taxonomy import CANONICAL
from domestique_app.server.api import (
    _CREDENTIAL_CATEGORIES,
    _CUSTOMER_DATA_CATEGORIES,
    _UNCLASSIFIED_CANONICAL,
    APIHandler,
)


@pytest.fixture
def normalize():
    # _normalize_category is a pure function of its argument; binding it to an
    # uninitialised instance avoids standing up a socket-backed handler.
    handler = APIHandler.__new__(APIHandler)
    return handler._normalize_category


@pytest.mark.parametrize(
    ("category", "expected"),
    [
        ("address", "CUSTOMER_DATA"),
        ("date_of_birth", "CUSTOMER_DATA"),
        ("ip_address", "CUSTOMER_DATA"),
        ("iban_code", "CUSTOMER_DATA"),
        ("us_passport", "CUSTOMER_DATA"),
        ("us_driver_license", "CUSTOMER_DATA"),
        ("medical_license", "CUSTOMER_DATA"),
        ("person", "CUSTOMER_DATA"),
        ("us_ssn", "CUSTOMER_DATA"),
        ("aws_secret_key", "CREDENTIALS"),
        ("password_literal", "CREDENTIALS"),
        ("high_entropy_string", "CREDENTIALS"),
    ],
)
def test_emitted_categories_score_against_the_right_label(normalize, category, expected):
    assert normalize(category) == expected


def test_every_canonical_category_is_mapped(normalize):
    """The map is a split of CANONICAL, so the two cannot drift apart.

    Add a category to ``domestique.taxonomy.CANONICAL`` without classifying it
    here and this test fails -- which is the point.
    """
    assert not _UNCLASSIFIED_CANONICAL
    assert not (_CREDENTIAL_CATEGORIES & _CUSTOMER_DATA_CATEGORIES)
    unmapped = [c for c in CANONICAL if c not in APIHandler._CATEGORY_MAP]
    assert unmapped == []


def test_map_has_no_keys_no_detector_can_emit(normalize):
    """No key may carry a source prefix normalize_category already strips."""
    stale = [k for k in APIHandler._CATEGORY_MAP if k.startswith(("pii:", "llm_classified:"))]
    assert stale == []


def test_standard_dataset_labels_pass_through(normalize):
    for label in (
        "PROPRIETARY_CODE",
        "BUSINESS_STRATEGY",
        "CUSTOMER_DATA",
        "INTERNAL_COMMS",
        "CREDENTIALS",
        "NONE",
    ):
        assert normalize(label) == label


def test_aliases_fold_before_lookup(normalize):
    # A detector emitting an alias spelling must not land in the fallback.
    assert normalize("email") == "CUSTOMER_DATA"
    assert normalize("dob") == "CUSTOMER_DATA"


def test_unknown_coined_term_falls_back_but_is_logged(normalize, capsys):
    assert normalize("employee_badge_id") == "CREDENTIALS"
    captured = capsys.readouterr()
    assert "workshop_benchmark_unmapped_category" in (captured.out + captured.err)
