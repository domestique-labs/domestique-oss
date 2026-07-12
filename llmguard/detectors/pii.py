"""LLM Firewall - PII detector (Microsoft Presidio).

Presidio is loaded lazily on first use so that the proxy starts instantly and
falls back gracefully when the ``pii`` extra is not installed.

Latency: ~5-8 ms for short text with spaCy ``en_core_web_lg``. The detector
short-circuits on text shorter than 4 characters.
"""

from __future__ import annotations

import structlog

from llmguard.models import Detection, Span

logger = structlog.get_logger()

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
        self._analyzer: object | None = None
        self._available: bool | None = None  # tri-state: None = untried

    @property
    def name(self) -> str:
        return "pii_detector"

    async def scan(self, text: str) -> list[Detection]:
        """Scan for PII entities. Returns empty list if Presidio unavailable."""
        if len(text) < 4:
            return []

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
                category=r.entity_type.lower(),
                confidence=r.score,
                span=Span(start=r.start, end=r.end),
            )
            for r in results
        ]

    def _get_analyzer(self) -> object | None:
        """Lazy-load Presidio analyzer. Returns None if unavailable."""
        if self._available is False:
            return None
        if self._analyzer is not None:
            return self._analyzer

        try:
            from presidio_analyzer import AnalyzerEngine  # type: ignore[import-untyped]

            self._analyzer = AnalyzerEngine()
            self._available = True
            logger.info("pii_detector_ready", model=self._spacy_model)
            return self._analyzer
        except (ImportError, OSError) as exc:
            self._available = False
            logger.warning("pii_detector_unavailable", reason=str(exc))
            return None
