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
