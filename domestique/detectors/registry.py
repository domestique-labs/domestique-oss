"""LLM Firewall - Detector registry.

Provides a single entry-point to instantiate all configured detectors and a
single ``create_detector_pipeline()`` factory used by the browser MITM addon
to run the full inspection pipeline (detectors + policy + redaction) over a
plain text blob.

Adding a new detector requires only appending it to ``build_detectors``.
"""

from __future__ import annotations

import asyncio
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from domestique.config import Settings
from domestique.detectors._offload import offload
from domestique.detectors.local_llm import LocalLLMClassifier
from domestique.detectors.pii import PIIDetector
from domestique.detectors.secrets import SecretDetector
from domestique.detectors.semantic import SemanticDetector
from domestique.models import Action, Detection, Span
from domestique.policy import PolicyEngine

if TYPE_CHECKING:
    from domestique.detectors import Detector

logger = structlog.get_logger()


def build_detectors(settings: Settings) -> list[Detector]:
    """Construct the active detector set from application settings."""
    detectors: list[Detector] = []

    # Tier 1: Always-on, sub-millisecond regex scanning.
    if settings.enable_secret_detection:
        detectors.append(SecretDetector(disabled_patterns=settings.disabled_builtin_patterns))

    # Tier 2a: NLP-based PII detection (Presidio + spaCy).
    if settings.enable_pii_detection:
        detectors.append(
            PIIDetector(
                confidence_threshold=settings.pii_confidence_threshold,
                spacy_model=settings.spacy_model,
            )
        )

    # Tier 2b: GLiNER zero-shot NER (300M params, ~20ms).
    # Only loads when explicitly enabled via detection_stack toggle.
    if settings.enable_gliner:
        try:
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            from domestique.models import Detection, Span

            _gliner_labels = list(settings.gliner_labels)
            _gliner_threshold = settings.gliner_threshold

            class _GLiNERDetector:
                """Lightweight wrapper for GLiNER PII model (lazy-loaded).

                The model is loaded on first ``scan()`` call rather than at
                construction time so the proxy starts instantly even when
                GLiNER is enabled. If the ``gliner`` package is not
                installed, or the model has never been cached locally (we
                force ``HF_HUB_OFFLINE=1`` so a cold cache fails fast instead
                of hanging on a network fetch), that is a distinct, known,
                actionable failure mode -- not a generic detector bug -- so
                it is surfaced as its own detection category
                (``gliner_not_cached``) instead of the opaque
                ``detector_error`` every other unexpected exception collapses
                into. This is still fail-closed: the request is still
                flagged as a suspect Detection for the policy engine to
                evaluate exactly as before, only the label changes.
                """

                def __init__(self, labels: list[str], threshold: float) -> None:
                    self._model = None
                    self._labels = labels
                    self._threshold = threshold
                    self._unavailable = False
                    self._warned = False
                    self._init_lock = threading.Lock()

                def _ensure_model(self) -> None:
                    if self._model is not None or self._unavailable:
                        return
                    with self._init_lock:
                        # Re-check under the lock: ``scan`` runs on worker
                        # threads, so concurrent first-calls would otherwise
                        # each load their own copy of the model.
                        if self._model is not None or self._unavailable:
                            return
                        self._load_model_locked()

                def _load_model_locked(self) -> None:
                    try:
                        from gliner import GLiNER

                        self._model = GLiNER.from_pretrained("knowledgator/gliner-pii-base-v1.0")
                        self._model.predict_entities("warmup", self._labels)
                    except (ModuleNotFoundError, ImportError, OSError) as exc:
                        # ModuleNotFoundError/ImportError: the `gliner` package
                        # (the "ner" extra) was never installed.
                        # OSError (covers huggingface_hub's
                        # LocalEntryNotFoundError, a FileNotFoundError/OSError
                        # subclass): the package is present but the model was
                        # never downloaded/cached, and HF_HUB_OFFLINE=1 above
                        # forbids fetching it now.
                        self._unavailable = True
                        if not self._warned:
                            self._warned = True
                            logger.warning(
                                "gliner_not_cached",
                                error=str(exc),
                                error_type=type(exc).__name__,
                                hint=(
                                    "GLiNER PII detection is enabled "
                                    "(detection_stack.gliner_pii) but the model "
                                    "is not available: install the 'ner' extra "
                                    "(pip install -e '.[ner]') and warm the "
                                    "model cache, or disable gliner_pii in the "
                                    "dashboard. Every request will be flagged "
                                    "as 'gliner_not_cached' until this is "
                                    "resolved."
                                ),
                            )

                @property
                def name(self) -> str:
                    return "gliner_pii"

                async def scan(self, text: str) -> list[Detection]:
                    if len(text) < 10:
                        return []
                    # Model load and inference are both blocking; PyTorch
                    # releases the GIL during inference, so worker threads
                    # give real overlap here rather than just loop relief.
                    return await offload(lambda: self._scan_sync(text))

                def _scan_sync(self, text: str) -> list[Detection]:
                    self._ensure_model()
                    if self._unavailable:
                        # Distinct, actionable category -- see _ensure_model.
                        # Deliberately NOT re-raised: an unavailable model is
                        # a known, diagnosable state, not an unexpected bug,
                        # so it must not fall through to the pipeline's
                        # generic detector_error catch-all.
                        return [
                            Detection(
                                detector=self.name,
                                category="gliner_not_cached",
                                confidence=1.0,
                                span=Span(start=0, end=0),
                            )
                        ]
                    entities = self._model.predict_entities(text[:2000], self._labels)
                    findings = []
                    for e in entities:
                        if e["score"] >= self._threshold:
                            start = text.find(e["text"])
                            end = start + len(e["text"]) if start >= 0 else len(text)
                            findings.append(
                                Detection(
                                    detector=self.name,
                                    category=f"pii:{e['label']}",
                                    confidence=e["score"],
                                    span=Span(start=max(0, start), end=end),
                                )
                            )
                    return findings

            detectors.append(_GLiNERDetector(_gliner_labels, _gliner_threshold))
        except Exception as exc:
            logger.debug("gliner_unavailable", error=str(exc))

    # Tier 2c: Semantic / encoding / entropy detection.
    if settings.enable_semantic_detection:
        detectors.append(
            SemanticDetector(
                sensitive_topics=settings.sensitive_topics,
                similarity_threshold=settings.semantic_similarity_threshold,
            )
        )

    # Tier 3: Local LLM second-pass (Gemma3 by default).
    if settings.enable_local_llm:
        detectors.append(
            LocalLLMClassifier(
                backend=settings.local_llm_backend,
                model=settings.local_llm_model,
                preset=settings.local_llm_preset,
                base_url=settings.local_llm_url,
                timeout_s=settings.local_llm_timeout_s,
                system_prompt=settings.local_llm_system_prompt,
            )
        )

    return detectors


# --- Pipeline wrapper used by the browser MITM addon ------------------------


@dataclass(frozen=True)
class Finding:
    """One human-readable finding surfaced to callers of ``inspect``."""

    detector: str
    category: str
    confidence: float
    span: Span | None = None

    @property
    def description(self) -> str:
        return f"{self.detector}:{self.category} ({self.confidence:.0%})"


@dataclass
class InspectionResult:
    """Result returned by ``DetectorPipeline.inspect``.

    Shape is intentionally compatible with what ``domestique_app/services/mitm_addon.py``
    consumes today: ``should_block``, ``findings`` (with ``.description``),
    and ``redacted_text``.
    """

    action: Action
    reason: str
    findings: list[Finding] = field(default_factory=list)
    redacted_text: str | None = None

    @property
    def should_block(self) -> bool:
        return self.action is Action.BLOCK


class DetectorPipeline:
    """Async pipeline: run all detectors -> evaluate policy -> redact if needed.

    Designed to be created once per process and reused across requests. All
    detectors are stateless after construction, so ``inspect`` is safe to call
    concurrently.
    """

    def __init__(self, detectors: list[Detector], policy: PolicyEngine) -> None:
        self._detectors = detectors
        self._policy = policy

    @property
    def policy(self) -> PolicyEngine:
        """The policy engine this pipeline evaluates against."""
        return self._policy

    async def inspect(self, text: str) -> InspectionResult:
        """Scan *text*, evaluate policy, and return a structured verdict."""
        if not text:
            return InspectionResult(action=Action.ALLOW, reason="empty input")

        results = await asyncio.gather(
            *(d.scan(text) for d in self._detectors),
            return_exceptions=True,
        )

        detections: list[Detection] = []
        for result in results:
            if isinstance(result, BaseException):
                # A single detector failure must not silently allow the request.
                # Surface it as a synthetic high-confidence finding so policy
                # treats the request as suspect.
                detections.append(
                    Detection(
                        detector="pipeline",
                        category="detector_error",
                        confidence=1.0,
                        span=Span(0, 0),
                    )
                )
                continue
            detections.extend(result)

        action, reason = self._policy.explain(detections)
        findings = [
            Finding(
                detector=d.detector,
                category=d.category,
                confidence=d.confidence,
                span=d.span,
            )
            for d in detections
        ]

        redacted_text: str | None = None
        if action is Action.REDACT and detections:
            redacted_text = _redact_text(text, detections)

        return InspectionResult(
            action=action,
            reason=reason,
            findings=findings,
            redacted_text=redacted_text,
        )


def create_detector_pipeline(settings: Settings | None = None) -> DetectorPipeline:
    """Build the full detection pipeline used by the browser MITM addon.

    Loads detectors from ``Settings`` and the policy from
    ``settings.policy_path``. The policy file path is resolved relative to the
    project root so the addon (which runs with a different cwd) finds it.

    Raises:
        ImportError or other exceptions intentionally propagate. The caller
        (mitm addon) MUST fail-closed when this factory cannot construct a
        working pipeline - never fall back to a weaker scanner.
    """
    settings = settings or Settings()

    policy_path = Path(settings.policy_path)
    if not policy_path.is_absolute():
        # Repository root: domestique/detectors/registry.py -> repo/
        repo_root = Path(__file__).resolve().parent.parent.parent
        policy_path = repo_root / policy_path

    return DetectorPipeline(
        detectors=build_detectors(settings),
        policy=PolicyEngine.from_yaml(policy_path),
    )


def _redact_text(text: str, detections: list[Detection]) -> str:
    """Replace each detection span with ``[CATEGORY_REDACTED]``.

    Spans are processed right-to-left so earlier offsets stay valid.
    Overlapping spans are coalesced by skipping any detection whose end
    extends past the next-earliest start we have already redacted.
    """
    sorted_dets = sorted(detections, key=lambda d: d.span.start, reverse=True)
    last_start = len(text) + 1
    redacted = text
    for det in sorted_dets:
        if det.span.end > last_start:
            continue
        placeholder = f"[{det.category.upper()}_REDACTED]"
        redacted = redacted[: det.span.start] + placeholder + redacted[det.span.end :]
        last_start = det.span.start
    return redacted
