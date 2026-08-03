import asyncio
import json

from domestique.detectors.local_llm import LocalLLMClassifier


def _clf(monkeypatch, items, threshold=0.7):
    """A classifier whose network call returns a fixed parsed list."""
    clf = LocalLLMClassifier(confidence_threshold=threshold)

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
    """A threshold raised above the verbatim floor still drops a weak item.

    This test previously used the default 0.7 threshold and asserted that
    ``v: 0.5`` yielded nothing — but its ``t`` appears verbatim in ``text``,
    so it was asserting exactly the behaviour issue #61 §1 reports: a span we
    had confirmed ourselves, dropped on the model's own say-so, sent upstream
    in cleartext. The gate is still real above ``_VERBATIM_FLOOR``, which is
    what it covers now. An unverified low-confidence item is dropped by the
    hallucination guard (test_drops_hallucinated_substring_not_in_text).
    """
    text = "maybe a name Jane Doe here"
    items = [{"t": "Jane Doe", "c": "person", "v": 0.5}]
    clf = _clf(monkeypatch, items, threshold=0.9)
    assert asyncio.run(clf.scan(text)) == []


class TestVerificationBeatsSelfReportedConfidence:
    """We verify the span ourselves; the model's opinion of it cannot veto that.

    The gate used to run on the model's own ``v`` *before* the verbatim check,
    and a missing ``v`` defaults to 0.0 — so a real model returning ``v: 0.0``
    for a genuine secret dropped it silently and the secret went upstream in
    cleartext. An item whose ``t`` appears exactly in the text has been
    confirmed by us, not merely asserted by the model.
    """

    def test_zero_confidence_verbatim_secret_is_still_detected(self, monkeypatch):
        text = "aws key AKIAIOSFODNN7EXAMPLE is in the config file"
        items = [{"t": "AKIAIOSFODNN7EXAMPLE", "c": "aws_access_key", "v": 0.0}]
        dets = asyncio.run(_clf(monkeypatch, items).scan(text))
        assert len(dets) == 1, "a verified secret was dropped on the model's say-so"
        assert text[dets[0].span.start : dets[0].span.end] == "AKIAIOSFODNN7EXAMPLE"

    def test_missing_confidence_field_verbatim_secret_is_still_detected(self, monkeypatch):
        text = "aws key AKIAIOSFODNN7EXAMPLE is in the config file"
        items = [{"t": "AKIAIOSFODNN7EXAMPLE", "c": "aws_access_key"}]  # no "v" at all
        assert len(asyncio.run(_clf(monkeypatch, items).scan(text))) == 1

    def test_hallucination_guard_survives_the_reorder(self, monkeypatch):
        text = "nothing sensitive here at all really"
        items = [{"t": "AKIAIOSFODNN7EXAMPLE", "c": "aws_access_key", "v": 0.0}]
        assert asyncio.run(_clf(monkeypatch, items).scan(text)) == []

    def test_floored_confidence_clears_the_default_threshold(self, monkeypatch):
        text = "aws key AKIAIOSFODNN7EXAMPLE is in the config file"
        items = [{"t": "AKIAIOSFODNN7EXAMPLE", "c": "aws_access_key", "v": 0.0}]
        dets = asyncio.run(_clf(monkeypatch, items).scan(text))
        assert dets[0].confidence >= 0.7

    def test_a_high_self_reported_confidence_is_not_lowered(self, monkeypatch):
        text = "aws key AKIAIOSFODNN7EXAMPLE is in the config file"
        items = [{"t": "AKIAIOSFODNN7EXAMPLE", "c": "aws_access_key", "v": 0.95}]
        assert asyncio.run(_clf(monkeypatch, items).scan(text))[0].confidence == 0.95


class TestValueLikeCategoryNeverReachesTheToken:
    """Regression for issue #61 §2.

    ``c`` is untrusted model output. A model that answers with the secret in
    the category field used to have it upper-cased into the token prefix — a
    token that is sent upstream — and persisted verbatim as a key in
    ~/.domestique/taxonomy.json.
    """

    SECRET = "Tr0ub4dor3xKlm9zQvBn7Yt2"

    def _scan(self, monkeypatch, tmp_path):
        import domestique.taxonomy_store as ts

        self.path = tmp_path / "taxonomy.json"
        monkeypatch.setattr(ts, "_DEFAULT", ts.TaxonomyStore(path=self.path))
        text = f"the deploy password is {self.SECRET} rotate it monthly"
        items = [{"t": self.SECRET, "c": self.SECRET, "v": 0.9}]
        return text, asyncio.run(_clf(monkeypatch, items).scan(text))

    def _runs_of_eight(self, secret):
        return {secret[i : i + 8].upper() for i in range(len(secret) - 7)}

    def test_minted_token_contains_no_run_of_the_secret(self, monkeypatch, tmp_path):
        from domestique.vault.session import SessionStore

        text, dets = self._scan(monkeypatch, tmp_path)
        assert dets, "the span itself must still be detected and redacted"
        token = SessionStore().tokenize(self.SECRET, dets[0].category)
        for run in self._runs_of_eight(self.SECRET):
            assert run not in token.upper(), f"token {token} leaks the secret"

    def test_nothing_containing_the_secret_is_written_to_disk(self, monkeypatch, tmp_path):
        self._scan(monkeypatch, tmp_path)
        if not self.path.exists():
            return  # nothing persisted at all is the best outcome
        raw = self.path.read_text(encoding="utf-8").upper()
        for run in self._runs_of_eight(self.SECRET):
            assert run not in raw, "the secret reached ~/.domestique/taxonomy.json"
        assert not [k for k in json.loads(self.path.read_text(encoding="utf-8"))]

    def test_the_span_is_still_redacted_under_the_generic_category(self, monkeypatch, tmp_path):
        from domestique.taxonomy import GENERIC_CATEGORY

        text, dets = self._scan(monkeypatch, tmp_path)
        assert [d.category for d in dets] == [GENERIC_CATEGORY]
        assert text[dets[0].span.start : dets[0].span.end] == self.SECRET


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

    ``max_tokens`` (-> Ollama ``num_predict``) is a runaway guard, not a target:
    the model emits its array and stops, so a larger cap costs nothing in the
    normal case. The classifier-era budget of 40 truncated the array mid-object,
    which parsed to nothing and silently dropped every LLM finding.
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


class TestBackendFailureIsVisible:
    """A dead backend must announce itself, not fail open in silence.

    ``_classify`` already has the right handler (mark unavailable + warn
    ``local_llm_unavailable``), but a bare ``except`` inside ``_classify_ollama``
    swallowed transport errors before it could run — so a missing/misnamed
    Ollama model made the whole tier return nothing, forever, with no log line.
    On a DLP path that is a silent fail-open.
    """

    def _raising_opener(self, exc):
        class _Opener:
            def open(self, *a, **k):
                raise exc

        return lambda *a, **k: _Opener()

    def test_missing_model_marks_tier_unavailable_and_warns(self, monkeypatch):
        import urllib.error
        import urllib.request

        from domestique.detectors.local_llm import LocalLLMClassifier

        err = urllib.error.HTTPError("http://x/api/chat", 404, "Not Found", {}, None)
        monkeypatch.setattr(urllib.request, "build_opener", self._raising_opener(err))

        # structlog's own capture API - patching logger.warning directly mutates
        # a global lazy proxy and leaks broken logging config into later tests.
        import structlog.testing

        clf = LocalLLMClassifier(confidence_threshold=0.7)
        with structlog.testing.capture_logs() as logs:
            assert asyncio.run(clf._classify("some text with a secret in it")) is None

        assert clf._available is False, "dead backend not marked unavailable"
        assert any(entry.get("event") == "local_llm_unavailable" for entry in logs), (
            "backend failure was swallowed silently (fail-open, no operator signal)"
        )

    def test_scan_still_returns_no_detections_on_failure(self, monkeypatch):
        import urllib.error
        import urllib.request

        from domestique.detectors.local_llm import LocalLLMClassifier

        err = urllib.error.URLError("connection refused")
        monkeypatch.setattr(urllib.request, "build_opener", self._raising_opener(err))
        clf = LocalLLMClassifier(confidence_threshold=0.7)
        # must degrade gracefully, never raise into the pipeline
        assert asyncio.run(clf.scan("a longer piece of text to scan here")) == []


class TestLegacyPromptFormat:
    """A prompt saved before the extractor rewrite must not silently kill the tier.

    `config_loader` restores `classifier_prompt` from config verbatim, so a
    prompt saved via the dashboard still asks for the old classifier shape - a
    single JSON object rather than an array. That parsed to None, yielding zero
    detections forever with only a DEBUG line: a silent fail-open.
    """

    def test_lone_object_is_accepted_as_a_single_item(self):
        from domestique.detectors.local_llm import LocalLLMClassifier

        parsed = LocalLLMClassifier._parse_response('{"t":"a@b.com","c":"email","v":0.9}')
        assert parsed == [{"t": "a@b.com", "c": "email", "v": 0.9}]

    def test_unparseable_response_warns_once_not_only_debug(self, monkeypatch):
        import urllib.request

        import structlog.testing

        from domestique.detectors.local_llm import LocalLLMClassifier

        class _Resp:
            def read(self):
                return b'{"message": {"content": "SENSITIVE"}}'

        class _Opener:
            def open(self, *a, **k):
                return _Resp()

        monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _Opener())
        clf = LocalLLMClassifier(confidence_threshold=0.7)
        with structlog.testing.capture_logs() as logs:
            assert asyncio.run(clf._classify("some text with a secret in it")) is None
            asyncio.run(clf._classify("more text with another secret here"))

        warned = [e for e in logs if e.get("event") == "local_llm_unusable_response"]
        assert len(warned) == 1, "a tier producing nothing must say so exactly once"
        assert warned[0].get("log_level") == "warning"


class TestSalvageWithBracesInValues:
    """A "}" inside a string value must not defeat truncation salvage."""

    def test_brace_in_password_value(self):
        from domestique.detectors.local_llm import LocalLLMClassifier

        parsed = LocalLLMClassifier._parse_response(
            '[{"t":"pw=a{b}c","c":"password","v":0.9},{"t":"unter}minated'
        )
        assert parsed == [{"t": "pw=a{b}c", "c": "password", "v": 0.9}]

    def test_brace_in_truncated_tail(self):
        from domestique.detectors.local_llm import LocalLLMClassifier

        parsed = LocalLLMClassifier._parse_response(
            '[{"t":"first@x.com","c":"email","v":0.9},{"t":"code {x} = }'
        )
        assert parsed == [{"t": "first@x.com", "c": "email", "v": 0.9}]


class TestEveryOccurrenceRedacted:
    """A value reported once but appearing N times must be redacted N times.

    The model reports each entity once; the old per-substring cursor mapped that
    to exactly one span, so occurrences 2..N went upstream in cleartext. Tiers
    1/2 cover canonical categories, but for an LLM-COINED category the LLM is
    the only source - so this was a live leak path.
    """

    def test_repeated_value_reported_once_redacts_all_occurrences(self, monkeypatch):
        text = "badge EB-99213 issued; reissued badge EB-99213; still EB-99213 today"
        items = [{"t": "EB-99213", "c": "employee_badge", "v": 0.9}]
        clf = _clf(monkeypatch, items)
        dets = asyncio.run(clf.scan(text))
        spans = sorted((d.span.start, d.span.end) for d in dets)
        assert len(spans) == 3, f"only {len(spans)} of 3 occurrences detected: {spans}"
        for start, end in spans:
            assert text[start:end] == "EB-99213"

    def test_duplicate_reports_do_not_double_count(self, monkeypatch):
        text = "key AKIAIOSFODNN7EXAMPLE and again AKIAIOSFODNN7EXAMPLE here"
        items = [
            {"t": "AKIAIOSFODNN7EXAMPLE", "c": "aws_access_key", "v": 0.9},
            {"t": "AKIAIOSFODNN7EXAMPLE", "c": "aws_access_key", "v": 0.9},
        ]
        clf = _clf(monkeypatch, items)
        dets = asyncio.run(clf.scan(text))
        spans = sorted({(d.span.start, d.span.end) for d in dets})
        assert len(spans) == 2, f"expected 2 distinct spans, got {spans}"


class TestParseResponseIsTolerant:
    """A malformed wrapper must not discard entities the model did find.

    Returning None means zero detections and the request goes upstream in
    CLEARTEXT - a total tier bypass. These shapes were all observed from
    supported models (qwen3:1.7b) with the shipped default prompt.
    """

    def _p(self, content):
        from domestique.detectors.local_llm import LocalLLMClassifier

        return LocalLLMClassifier._parse_response(content)

    def test_array_of_pairs_missing_braces(self):
        # observed verbatim from qwen3:1.7b: '{' dropped on every element
        got = self._p(
            '["t":"Priya Raman","c":"person","v":0.9],'
            '["t":"Tomas Berg","c":"person","v":0.9],'
            '["t":"Wei Chen","c":"person","v":0.9]'
        )
        assert got is not None, "malformed wrapper dropped every entity (cleartext)"
        assert [d["t"] for d in got] == ["Priya Raman", "Tomas Berg", "Wei Chen"]

    def test_prose_preamble_before_the_array(self):
        got = self._p('Here is the JSON:\n[{"t":"a@b.com","c":"email","v":0.9}]')
        assert got == [{"t": "a@b.com", "c": "email", "v": 0.9}]

    def test_think_block_then_array(self):
        got = self._p('<think>reasoning...</think>\n[{"t":"a@b.com","c":"email","v":0.9}]')
        assert got == [{"t": "a@b.com", "c": "email", "v": 0.9}]

    def test_trailing_garbage_after_the_array(self):
        got = self._p('[{"t":"a@b.com","c":"email","v":0.9}] Hope this helps!')
        assert got == [{"t": "a@b.com", "c": "email", "v": 0.9}]

    def test_deeply_nested_brackets_do_not_recurse(self):
        # "["*100000 raised RecursionError, which _classify caught and used to
        # mark the tier permanently unavailable for the whole process.
        assert self._p("[" * 100_000) is None

    def test_genuine_prose_still_returns_none(self):
        assert self._p("I cannot help with that request.") is None
