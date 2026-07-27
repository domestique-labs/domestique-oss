import asyncio

from domestique.detectors.local_llm import LocalLLMClassifier


def _clf(monkeypatch, items):
    """A classifier whose network call returns a fixed parsed list."""
    clf = LocalLLMClassifier(confidence_threshold=0.7)

    async def fake_classify(text):
        return items

    monkeypatch.setattr(clf, "_classify", fake_classify)
    return clf


def test_extracts_spans_with_canonical_categories(monkeypatch):
    text = "email jane@corp.com and ssn 123-45-6789 please"
    items = [
        {"t": "jane@corp.com", "c": "email", "v": 0.9},
        {"t": "123-45-6789", "c": "social_security_number", "v": 0.95},
    ]
    clf = _clf(monkeypatch, items)
    dets = asyncio.run(clf.scan(text))
    by_cat = {d.category: d for d in dets}
    assert by_cat["email_address"].span.start == text.index("jane@corp.com")
    assert by_cat["us_ssn"].span.end == text.index("123-45-6789") + len("123-45-6789")


def test_drops_hallucinated_substring_not_in_text(monkeypatch):
    text = "nothing sensitive here at all really"
    items = [{"t": "AKIAIOSFODNN7EXAMPLE", "c": "aws_access_key", "v": 0.99}]
    clf = _clf(monkeypatch, items)
    assert asyncio.run(clf.scan(text)) == []


def test_below_threshold_dropped(monkeypatch):
    text = "maybe a name Jane Doe here"
    items = [{"t": "Jane Doe", "c": "person", "v": 0.5}]
    clf = _clf(monkeypatch, items)
    assert asyncio.run(clf.scan(text)) == []


def test_coins_and_persists_new_term(monkeypatch, tmp_path):
    import domestique.taxonomy_store as ts

    store = ts.TaxonomyStore(path=tmp_path / "t.json")
    monkeypatch.setattr(ts, "_DEFAULT", store)

    text = "my badge is EMP-4471 for the door"
    items = [{"t": "EMP-4471", "c": "Employee Badge", "v": 0.9}]
    clf = _clf(monkeypatch, items)
    dets = asyncio.run(clf.scan(text))
    assert dets[0].category == "employee_badge"
    assert store.prefix_of("employee_badge") == "EMPLOYEE_BADGE"


def test_malformed_returns_no_detections(monkeypatch):
    clf = _clf(monkeypatch, None)  # _classify returned None (unparseable)
    assert asyncio.run(clf.scan("some text here to scan")) == []


def test_repeated_substring_gets_two_distinct_nonoverlapping_spans(monkeypatch):
    substring = "AKIAIOSFODNN7EXAMPLE"
    text = f"first key {substring} then later a second copy {substring} done"
    items = [
        {"t": substring, "c": "aws_access_key", "v": 0.9},
        {"t": substring, "c": "aws_access_key", "v": 0.9},
    ]
    clf = _clf(monkeypatch, items)
    dets = asyncio.run(clf.scan(text))

    assert len(dets) == 2
    spans = sorted((d.span.start, d.span.end) for d in dets)
    (s1, e1), (s2, e2) = spans
    assert (s1, e1) != (s2, e2)
    assert e1 <= s2  # non-overlapping, ordered
    assert text[s1:e1] == substring
    assert text[s2:e2] == substring
    assert {d.category for d in dets} == {"aws_access_key"}


def test_non_numeric_confidence_drops_item_without_raising(monkeypatch):
    text = "email jane@corp.com and ssn 123-45-6789 please"
    items = [
        {"t": "jane@corp.com", "c": "email", "v": "high"},
        {"t": "123-45-6789", "c": "social_security_number", "v": 0.95},
    ]
    clf = _clf(monkeypatch, items)
    dets = asyncio.run(clf.scan(text))

    assert len(dets) == 1
    assert dets[0].category == "us_ssn"


class TestExtractorTokenBudget:
    """The tier emits a JSON array now, not a one-word verdict.

    ``max_tokens`` (-> Ollama ``num_predict``) is only a safety cap: the request
    sets ``stop=["]"]``, so generation halts at the array close and a larger cap
    costs no extra latency. The classifier-era budget of 40 truncated the array
    mid-object, which parsed to nothing and silently dropped every LLM finding.
    """

    def test_every_preset_budgets_a_json_array(self):
        from domestique.detectors.local_llm import MODEL_PRESETS

        for name, preset in MODEL_PRESETS.items():
            # ~25-30 tokens per {"t","c","v"} entity; 40 fit barely one.
            assert preset["max_tokens"] >= 256, f"{name} cannot fit a multi-entity array"


class TestParseResponseSalvage:
    """A truncated array must degrade to its complete prefix, never to nothing.

    Returning ``None`` makes ``scan`` yield zero detections — a fail-open on a
    DLP path, so the secrets the model *did* find would pass through unredacted.
    """

    def test_salvages_complete_objects_from_truncated_array(self):
        from domestique.detectors.local_llm import LocalLLMClassifier

        # what num_predict truncation actually produces (observed with qwen3:1.7b)
        content = '[\n  {"t": "123-45-6789", "c": "us_ssn", "v": 0.9},\n  {"t": "EB-'
        parsed = LocalLLMClassifier._parse_response(content)
        assert parsed is not None, "truncation dropped every finding (fail-open)"
        assert len(parsed) == 1
        assert parsed[0]["t"] == "123-45-6789"

    def test_still_parses_a_complete_array(self):
        from domestique.detectors.local_llm import LocalLLMClassifier

        content = '[{"t": "a@b.com", "c": "email", "v": 0.9}]'
        assert LocalLLMClassifier._parse_response(content) == [
            {"t": "a@b.com", "c": "email", "v": 0.9}
        ]

    def test_empty_array_stays_empty(self):
        from domestique.detectors.local_llm import LocalLLMClassifier

        assert LocalLLMClassifier._parse_response("[]") == []

    def test_unsalvageable_garbage_returns_none(self):
        from domestique.detectors.local_llm import LocalLLMClassifier

        assert LocalLLMClassifier._parse_response("I cannot help with that") is None
