"""Detector thread-offload behaviour.

Covers the rule encoded in ``domestique/detectors/_offload.py``: detectors
backed by native, GIL-releasing libraries run on a worker thread; the
regex/entropy tiers stay inline because offloading them is measurably
pointless (see that module's docstring).

These tests assert *where* the work runs and that lazy model init is safe
under concurrency -- not detection quality, which ``benchmarks/eval`` covers.
"""

from __future__ import annotations

import asyncio
import sys
import threading
import types

import pytest

from domestique.detectors.pii import PIIDetector
from domestique.detectors.secrets import SecretDetector
from domestique.detectors.semantic import SemanticDetector


def _record_thread(monkeypatch, detector, attr="_scan_sync"):
    """Wrap ``detector.<attr>`` so we can see which thread executed it."""
    seen: list[int] = []
    original = getattr(detector, attr)

    def traced(*args, **kwargs):
        seen.append(threading.get_ident())
        return original(*args, **kwargs)

    monkeypatch.setattr(detector, attr, traced)
    return seen


@pytest.mark.asyncio
async def test_secret_scan_stays_on_event_loop_thread(monkeypatch):
    """Regex tier is deliberately inline: ``re`` holds the GIL, so a worker
    thread would add overhead without freeing the loop."""
    detector = SecretDetector()
    seen = _record_thread(monkeypatch, detector)

    await detector.scan("hello world " * 5000)  # well past any size threshold

    assert seen == [threading.get_ident()]


@pytest.mark.asyncio
async def test_pii_scan_runs_off_event_loop_thread(monkeypatch):
    """Presidio releases the GIL, so its scan must not run on the loop thread."""
    detector = PIIDetector()
    # Stand in for Presidio so the test does not need the heavy [pii] extra.
    monkeypatch.setattr(detector, "_get_analyzer", lambda: object())
    monkeypatch.setattr(detector, "_scan_sync", lambda text: [])
    seen = _record_thread(monkeypatch, detector)

    await detector.scan("Alice Smith lives in Denver and her email is a@b.com")

    assert len(seen) == 1
    assert seen[0] != threading.get_ident()


@pytest.mark.asyncio
async def test_pii_short_text_skips_scan_entirely(monkeypatch):
    """The <4 char guard short-circuits before any thread hop."""
    detector = PIIDetector()
    seen = _record_thread(monkeypatch, detector)

    assert await detector.scan("ab") == []
    assert seen == []


@pytest.mark.asyncio
async def test_semantic_inline_without_embedding_model(monkeypatch):
    """Strategies 1-2 are regex/entropy only -- keep them on the loop thread."""
    detector = SemanticDetector(sensitive_topics=[], enable_embedding_model=False)
    seen = _record_thread(monkeypatch, detector)

    await detector.scan("some reasonably long benign text to clear the guard")

    assert seen == [threading.get_ident()]


@pytest.mark.asyncio
async def test_semantic_offloads_when_embedding_enabled(monkeypatch):
    """Embedding inference is native and GIL-releasing -> offload it."""
    detector = SemanticDetector(
        sensitive_topics=["acquisition plans"], enable_embedding_model=True
    )
    monkeypatch.setattr(detector, "_detect_sensitive_topics", lambda text: [])
    seen = _record_thread(monkeypatch, detector)

    await detector.scan("some reasonably long benign text to clear the guard")

    assert len(seen) == 1
    assert seen[0] != threading.get_ident()


@pytest.mark.asyncio
async def test_pii_lazy_init_is_locked_under_concurrency(monkeypatch):
    """Concurrent first-calls must construct exactly one AnalyzerEngine.

    Without the lock this races: ``scan`` now runs on worker threads, so
    several could pass the ``_analyzer is None`` check together and each pay
    the multi-second model load.
    """
    constructions = 0
    counter_lock = threading.Lock()

    class _FakeAnalyzerEngine:
        def __init__(self) -> None:
            nonlocal constructions
            with counter_lock:
                constructions += 1
            # Widen the race window so an unlocked implementation fails loudly
            # rather than intermittently.
            threading.Event().wait(0.05)

        def analyze(self, **kwargs):
            return []

    # Inject a stand-in module so the real ``_get_analyzer`` -- lock,
    # double-check and all -- is the code under test.
    fake_module = types.ModuleType("presidio_analyzer")
    fake_module.AnalyzerEngine = _FakeAnalyzerEngine  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "presidio_analyzer", fake_module)

    detector = PIIDetector()

    await asyncio.gather(*(detector.scan("a longer sample of text") for _ in range(8)))

    assert constructions == 1
    assert detector._available is True
