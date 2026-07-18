"""Tests for background detector-pipeline construction in the mitm addon.

Context: ``DomestiqueAddon.load()`` used to call ``_init_detector()``
synchronously, which in turn calls ``create_detector_pipeline()`` -- a
factory that can instantiate the full ML stack (torch/transformers/GLiNER).
mitmproxy does not accept connections on the proxy port until ``load()``
returns, so a slow/cold pipeline build gated the port bind directly. On a
cold first-run (or weak hardware) that can exceed the readiness-timeout
safety net and get the whole proxy killed.

This suite locks in the fix:

1. ``load()`` returns quickly regardless of how long pipeline construction
   takes -- the build now happens on a background thread.
2. The request-inspection path (``_inspect``) HOLDS briefly for an
   in-flight build, then inspects normally once ready.
3. If the bounded hold expires, or if pipeline construction raised, the
   request path FAILS CLOSED (blocks with a clear reason) -- it must never
   silently allow sensitive data through uninspected.
4. Real detector-scan errors (once the pipeline is up) still fail closed,
   exactly as before this change.
"""

from __future__ import annotations

import asyncio
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("mitmproxy")  # requires the [browser-proxy] extra; skip cleanly when absent

from domestique_app.services.mitm_addon import DomestiqueAddon


def _join_background_init_threads(timeout: float = 3.0) -> None:
    """Wait for any 'detector-pipeline-init' or 'detector-pipeline-retry'
    thread(s) (started by load() / _maybe_retry_detector_init()) to fully
    finish, so a slow-to-settle background thread never outlives the test's
    ctx-patching fixture and trips over the real (unpatched)
    mitmproxy.ctx in a later test."""
    for t in threading.enumerate():
        if t.name in ("detector-pipeline-init", "detector-pipeline-retry"):
            t.join(timeout=timeout)


@pytest.fixture(autouse=True)
def mock_ctx():
    with patch("domestique_app.services.mitm_addon.ctx") as mock:
        mock.log = MagicMock()
        yield mock


class _StubPipeline:
    """Minimal async pipeline stub with the real ``inspect()`` contract."""

    def __init__(self, action_dict: dict | None = None):
        self._action_dict = action_dict or {"action": "allow"}
        self._detectors = []

    async def inspect(self, text: str):
        from domestique.detectors.registry import InspectionResult
        from domestique.models import Action

        return InspectionResult(action=Action.ALLOW, reason="stub")


class TestLoadDoesNotBlockOnPipelineConstruction:
    def test_load_returns_fast_even_when_pipeline_construction_is_slow(self):
        addon = DomestiqueAddon()
        # Hardware detection is irrelevant to this test -- pin it so the
        # test isn't coupled to the speed/outcome of a real nvidia-smi call
        # on whatever machine runs the suite.
        addon._hardware_is_low_resource = lambda: False

        def _slow_pipeline(settings=None):
            time.sleep(1.0)
            return _StubPipeline()

        with patch(
            "domestique.detectors.registry.create_detector_pipeline",
            side_effect=_slow_pipeline,
        ):
            start = time.time()
            addon.load(loader=MagicMock())
            elapsed = time.time() - start

            # load() must return well before the 1s pipeline construction
            # completes -- it must not have blocked waiting on it.
            assert elapsed < 0.5, (
                f"load() blocked for {elapsed:.2f}s -- pipeline construction "
                "must happen on a background thread, not synchronously"
            )
            assert not addon._detector_ready.is_set(), (
                "detector_ready must still be clear immediately after "
                "load() returns, while construction is still running"
            )

            # Eventually (well within the 1s sleep + slack) it does complete.
            assert addon._detector_ready.wait(timeout=3.0)
            assert addon._detector is not None
            _join_background_init_threads()

    def test_detector_ready_is_cleared_by_load_and_set_on_success(self):
        addon = DomestiqueAddon()
        addon._hardware_is_low_resource = lambda: False
        # Constructed fresh, ready defaults True (so direct-construction
        # callers/tests that skip load() are never gated).
        assert addon._detector_ready.is_set()

        pipeline = _StubPipeline()
        with patch(
            "domestique.detectors.registry.create_detector_pipeline",
            return_value=pipeline,
        ):
            addon.load(loader=MagicMock())
            assert addon._detector_ready.wait(timeout=3.0)
            _join_background_init_threads()
        assert addon._detector is pipeline
        assert addon._detector_init_error is None

    def test_load_sets_init_error_and_stays_fail_closed_on_construction_failure(self):
        addon = DomestiqueAddon()
        addon._hardware_is_low_resource = lambda: False

        with patch(
            "domestique.detectors.registry.create_detector_pipeline",
            side_effect=RuntimeError("pipeline construction exploded"),
        ):
            addon.load(loader=MagicMock())
            assert addon._detector_ready.wait(timeout=3.0)

        assert addon._detector is None
        assert isinstance(addon._detector_init_error, RuntimeError)


class TestInspectHoldsThenInspects:
    @pytest.mark.asyncio
    async def test_inspect_holds_until_ready_then_inspects_normally(self):
        from domestique_app.services.pipeline_config import (
            config_hash,
            config_mtime_ns,
            load_config_dict,
        )

        addon = DomestiqueAddon()
        addon._detector_ready.clear()
        addon._detector = None
        # Pin the config fingerprint up front so _inspect()'s hot-reload
        # check never decides mid-wait that the config "changed" and
        # rebuilds a real (unmocked) pipeline in place of our stub.
        addon._config_mtime = config_mtime_ns()
        addon._config_hash = config_hash(load_config_dict())

        async def _flip_ready_soon():
            await asyncio.sleep(0.2)
            addon._detector = _StubPipeline()
            addon._detector_ready.set()

        inspect_task = asyncio.create_task(addon._inspect("hello, just a normal harmless message"))
        flip_task = asyncio.create_task(_flip_ready_soon())

        result = await asyncio.wait_for(inspect_task, timeout=5)
        await flip_task

        assert result["action"] == "allow"

    @pytest.mark.asyncio
    async def test_inspect_fails_closed_when_wait_expires(self):
        addon = DomestiqueAddon()
        addon._detector_ready.clear()
        addon._detector = None
        addon.DETECTOR_READY_WAIT_S = 0.2  # bound the test's real wall time

        start = time.time()
        result = await addon._inspect("some sensitive-looking content")
        elapsed = time.time() - start

        assert result["action"] == "block"
        assert result["reasons"] == ["detectors_unavailable"]
        # Should not wait dramatically longer than the bounded timeout.
        assert elapsed < 2.0

    @pytest.mark.asyncio
    async def test_inspect_fails_closed_immediately_when_init_already_raised(self):
        """If the background build already finished (with an error), later
        requests must fail closed immediately -- no need to re-wait out the
        full bounded timeout on every subsequent request.

        This also triggers a background self-heal retry attempt (see
        TestDetectorSelfHealsAfterTransientFailure below) -- patch
        ``_init_detector`` so that retry can't do real, slow, unmocked
        pipeline construction, and join it before the test's ctx-patch
        fixture tears down.
        """
        addon = DomestiqueAddon()
        addon._detector = None
        addon._detector_init_error = RuntimeError("boom")
        addon._detector_ready.set()  # background thread finished (failed)
        addon.DETECTOR_READY_WAIT_S = 20.0  # would be way too slow if re-waited

        with patch.object(
            addon, "_init_detector", side_effect=RuntimeError("still broken")
        ) as mock_init:
            start = time.time()
            result = await addon._inspect("some content")
            elapsed = time.time() - start
            _join_background_init_threads()

        assert result["action"] == "block"
        assert result["reasons"] == ["detectors_unavailable"]
        assert elapsed < 0.5
        # The not-ready branch is reachable and attempts self-heal -- this
        # is exactly the retry path the permanent-lockout bug made
        # unreachable.
        mock_init.assert_called_once()
        assert isinstance(addon._detector_init_error, RuntimeError)


class TestExistingFailClosedBehaviorPreserved:
    @pytest.mark.asyncio
    async def test_detector_scan_exception_still_fails_closed_once_ready(self):
        """Real detector-scan errors (e.g. GLiNER not cached surfaced as a
        pipeline exception) must still block -- unaffected by the new
        readiness gating once the pipeline itself is up."""
        from domestique_app.services.pipeline_config import (
            config_hash,
            config_mtime_ns,
            load_config_dict,
        )

        class _BoomPipeline:
            async def inspect(self, text):
                raise RuntimeError("boom")

        addon = DomestiqueAddon()
        addon._detector = _BoomPipeline()
        addon._detector_ready.set()
        # Pin the config fingerprint so _inspect()'s hot-reload check doesn't
        # rebuild the pipeline out from under our stub.
        addon._config_mtime = config_mtime_ns()
        addon._config_hash = config_hash(load_config_dict())

        result = await addon._inspect("some content")

        assert result["action"] == "block"
        assert result["reasons"][0].startswith("detection_error:")


class TestDetectorSelfHealsAfterTransientFailure:
    """Fix for the permanent fail-closed lockout: once
    ``_detector_init_error`` is set, nothing used to ever call
    ``_init_detector()`` again -- ``_wait_for_detector_ready()`` required
    ``self._detector is not None`` forever, and the not-ready branch of
    ``_inspect()`` returned immediately without reaching the hot-reload
    rebuild path. A TRANSIENT construction failure (locked/missing policy
    file, an Ollama blip, a disk hiccup) then blocked 100% of LLM traffic
    PERMANENTLY until a full mitmdump restart.

    ``_maybe_retry_detector_init`` fixes this: the not-ready branch now
    attempts a background rebuild (bounded by ``DETECTOR_RETRY_BACKOFF_S``),
    self-healing once the underlying problem clears -- while every request
    in the meantime, including the one that triggers the retry, still fails
    closed.
    """

    @pytest.mark.asyncio
    async def test_retry_rebuilds_pipeline_and_inspection_resumes_without_restart(self):
        addon = DomestiqueAddon()
        addon._hardware_is_low_resource = lambda: False
        addon.DETECTOR_RETRY_BACKOFF_S = 0  # deterministic: never gated by backoff
        addon._detector = None
        addon._detector_init_error = RuntimeError("transient: policy file locked")
        addon._detector_ready.set()  # background thread already finished (failed)

        pipeline = _StubPipeline()
        calls = {"n": 0}

        def _flaky_init():
            calls["n"] += 1
            if calls["n"] == 1:
                # Still broken on the first retry attempt.
                raise RuntimeError("transient: policy file locked")
            # The underlying problem has now cleared.
            addon._detector = pipeline

        with patch.object(addon, "_init_detector", side_effect=_flaky_init):
            # Window 1: still broken. This request must fail closed -- and
            # it's what triggers the first self-heal retry attempt.
            result1 = await addon._inspect("still broken")
            _join_background_init_threads()

            assert result1["action"] == "block"
            assert result1["reasons"] == ["detectors_unavailable"]
            assert addon._detector is None
            assert isinstance(addon._detector_init_error, RuntimeError), (
                "fail-closed must hold throughout the retry window -- a "
                "failed retry must never leave the detector usable"
            )

            # Window 2: the problem is now fixed, but THIS request still
            # fails closed (it already decided "not ready" before the retry
            # it triggers can possibly land) -- fail-closed during the
            # retry window, never allow-through.
            result2 = await addon._inspect("still broken during this request")
            _join_background_init_threads()

            assert result2["action"] == "block"
            assert result2["reasons"] == ["detectors_unavailable"]
            assert addon._detector is pipeline
            assert addon._detector_init_error is None, (
                "self-heal must clear the recorded error once the rebuild actually succeeds"
            )

            # Only a LATER request benefits: inspection resumes normally,
            # with no mitmdump restart involved anywhere in this test.
            result3 = await addon._inspect("hello, harmless message")

        assert result3["action"] == "allow"
        assert calls["n"] == 2, "expected exactly one retry attempt per blocked request"

    @pytest.mark.asyncio
    async def test_retry_is_backoff_gated_absent_a_config_change(self):
        """Without a config change, retries shouldn't fire on every single
        request -- only once per DETECTOR_RETRY_BACKOFF_S -- so a storm of
        blocked requests can't hammer a still-broken dependency."""
        from domestique_app.services.pipeline_config import (
            config_hash,
            config_mtime_ns,
            load_config_dict,
        )

        addon = DomestiqueAddon()
        addon.DETECTOR_RETRY_BACKOFF_S = 999.0
        addon._detector = None
        addon._detector_init_error = RuntimeError("still broken")
        addon._detector_ready.set()
        # Pin the config fingerprint so no config-change is ever detected
        # (that would bypass the backoff intentionally, tested separately).
        addon._config_mtime = config_mtime_ns()
        addon._config_hash = config_hash(load_config_dict())
        # Simulate an already-recent retry attempt.
        addon._last_detector_retry_ts = time.time()

        with patch.object(
            addon, "_init_detector", side_effect=RuntimeError("still broken")
        ) as mock_init:
            for _ in range(5):
                result = await addon._inspect("some content")
                assert result["action"] == "block"
            _join_background_init_threads()

        mock_init.assert_not_called()
