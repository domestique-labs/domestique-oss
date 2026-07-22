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
