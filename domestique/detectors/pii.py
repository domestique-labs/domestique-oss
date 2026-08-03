"""LLM Firewall - PII detector (Microsoft Presidio).

Presidio is loaded lazily on first use so that the proxy starts instantly and
falls back gracefully when the ``pii`` extra is not installed.

Latency: ~5-8 ms for short text with spaCy ``en_core_web_lg``. The detector
short-circuits on text shorter than 4 characters.
"""

from __future__ import annotations

import threading
from typing import Any, Protocol

import structlog

from domestique.detectors._offload import offload
from domestique.models import Detection, Span
from domestique.taxonomy import normalize_category

logger = structlog.get_logger()


class _Analyzer(Protocol):
    """The one method this module uses from ``presidio_analyzer.AnalyzerEngine``.

    Presidio is an optional extra and ships no stubs, so the concrete engine is
    ``Any`` here. Naming the surface we depend on keeps the call site checked.
    """

    def analyze(self, **kwargs: Any) -> list[Any]: ...


# Entities worth detecting for DLP purposes.
_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "MEDICAL_LICENSE",
]


class PIIDetector:
    """Detects personally identifiable information using Presidio NLP.

    If Presidio or spaCy is unavailable, ``scan`` returns an empty list and
    logs a warning once at startup. This keeps the proxy operational even in
    minimal deployments.
    """

    def __init__(
        self, *, confidence_threshold: float = 0.7, spacy_model: str = "en_core_web_lg"
    ) -> None:
        self._threshold = confidence_threshold
        self._spacy_model = spacy_model
        self._analyzer: _Analyzer | None = None
        self._available: bool | None = None  # tri-state: None = untried
        self._init_lock = threading.Lock()

    @property
    def name(self) -> str:
        return "pii_detector"

    async def scan(self, text: str) -> list[Detection]:
        """Scan for PII entities. Returns empty list if Presidio unavailable.

        Presidio analysis is synchronous CPU work costing several milliseconds
        even on short text, so it is always dispatched to a worker thread --
        unlike the regex tier, there is no input size at which running it
        inline is cheaper than the hop. spaCy releases the GIL for its native
        pipeline stages, so concurrent scans genuinely overlap.
        """
        if len(text) < 4:
            return []

        return await offload(lambda: self._scan_sync(text))

    def _scan_sync(self, text: str) -> list[Detection]:
        """Blocking body of :meth:`scan`. Safe to call from a worker thread."""
        analyzer = self._get_analyzer()
        if analyzer is None:
            return []

        try:
            results = analyzer.analyze(
                text=text,
                language="en",
                entities=_ENTITIES,
                score_threshold=self._threshold,
            )
        except Exception:
            logger.exception("pii_detection_error")
            return []

        return [
            Detection(
                detector=self.name,
                # Every tier canonicalizes through the shared taxonomy so the
                # same entity mints the same token whichever tier caught it.
                # The ten names in _ENTITIES already lowercase into CANONICAL
                # keys, so this is currently a no-op -- but AnalyzerEngine
                # returns whatever its registry holds, and an added recognizer
                # would otherwise coin a duplicate category behind our back.
                category=normalize_category(r.entity_type),
                confidence=r.score,
                span=Span(start=r.start, end=r.end),
            )
            for r in results
        ]

    def _get_analyzer(self) -> _Analyzer | None:
        """Lazy-load Presidio analyzer. Returns None if unavailable.

        Guarded by a lock: ``scan`` now runs on worker threads, so concurrent
        first-calls would otherwise race and each construct their own
        ``AnalyzerEngine`` (seconds of model loading, duplicated).
        """
        if self._available is False:
            return None
        if self._analyzer is not None:
            return self._analyzer

        with self._init_lock:
            return self._load_analyzer_locked()

    def _load_analyzer_locked(self) -> _Analyzer | None:
        """Construct the engine. Caller must hold ``_init_lock``.

        Split out of :meth:`_get_analyzer` so the post-lock re-check -- another
        thread may have finished, or failed, while we waited -- is a fresh read
        of the tri-state rather than one the type checker has already narrowed
        from the fast path above.
        """
        if self._available is False:
            return None
        if self._analyzer is not None:
            return self._analyzer

        try:
            from presidio_analyzer import AnalyzerEngine

            self._analyzer = AnalyzerEngine()
            self._available = True
            logger.info("pii_detector_ready", model=self._spacy_model)
            return self._analyzer
        except (ImportError, OSError) as exc:
            self._available = False
            logger.warning("pii_detector_unavailable", reason=str(exc))
            return None
