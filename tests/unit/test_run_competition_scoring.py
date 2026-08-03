"""The workshop competition scorer must not award credit for garbage output.

``run_competition.py`` computes binary precision/recall as "predicted != NONE".
``PARSE_ERROR`` and ``ERROR`` are not NONE, so a prompt whose every response
fails to parse -- 0% accuracy, nothing usable produced -- still scored as a
near-perfect detector. Reproduced against a live Ollama with the *production*
extractor prompt, which this classifier harness cannot parse at all: 0.0%
accuracy, 6/6 PARSE_ERROR, and the scorer reported F1 90.9%.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

_SCRIPT = (
    Path(__file__).resolve().parents[2] / "workshop" / "prompt_competition" / "run_competition.py"
)


@pytest.fixture(scope="module")
def rc() -> ModuleType:
    spec = importlib.util.spec_from_file_location("run_competition", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _result(expected: str, predicted: str) -> dict:
    return {
        "id": 1,
        "expected": expected,
        "predicted": predicted,
        "confidence": 0.0,
        "latency_ms": 100.0,
        "difficulty": "easy",
    }


@pytest.mark.parametrize("sentinel", ["PARSE_ERROR", "ERROR"])
def test_unparseable_response_is_not_a_true_positive(rc: ModuleType, sentinel: str) -> None:
    results = [_result("CREDENTIALS", sentinel) for _ in range(5)]
    scores = rc.score_results(results, {})
    assert scores["tp"] == 0
    assert scores["precision"] == 0
    assert scores["recall"] == 0
    assert scores["f1"] == 0
    assert scores["errors"] == 5


@pytest.mark.parametrize("sentinel", ["PARSE_ERROR", "ERROR"])
def test_unparseable_response_on_sensitive_sample_is_a_miss(rc: ModuleType, sentinel: str) -> None:
    scores = rc.score_results([_result("CREDENTIALS", sentinel)], {})
    assert scores["fn"] == 1
    assert scores["false_negatives"] == 1


@pytest.mark.parametrize("sentinel", ["PARSE_ERROR", "ERROR"])
def test_unparseable_response_on_clean_sample_earns_nothing(rc: ModuleType, sentinel: str) -> None:
    scores = rc.score_results([_result("NONE", sentinel)], {})
    assert scores["correct"] == 0
    assert scores["fp"] == 0
    assert scores["false_positives"] == 0
    assert scores["errors"] == 1


def test_real_predictions_still_score_as_before(rc: ModuleType) -> None:
    results = [
        _result("CREDENTIALS", "CREDENTIALS"),  # hit
        _result("NONE", "NONE"),  # correct reject
        _result("CUSTOMER_DATA", "CREDENTIALS"),  # wrong category, still a positive
        _result("NONE", "CREDENTIALS"),  # false positive
        _result("CUSTOMER_DATA", "NONE"),  # false negative
    ]
    scores = rc.score_results(results, {})
    assert scores["errors"] == 0
    assert (scores["tp"], scores["fp"], scores["fn"], scores["tn"]) == (2, 1, 1, 1)
    assert scores["correct"] == 2
    assert scores["wrong_category"] == 1


def test_max_possible_score_is_derived_from_the_dataset(rc: ModuleType) -> None:
    """The printed ceiling was hardcoded at ~153; the dataset says 117."""
    samples = json.loads((_SCRIPT.parent / "dataset.json").read_text())["samples"]
    assert rc.max_possible_score(samples) == 117
