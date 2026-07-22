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
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from domestique.config import Settings
from domestique.detectors.local_llm import LocalLLMClassifier
from domestique.detectors.pii import PIIDetector
from domestique.detectors.secrets import SecretDetector
from domestique.detectors.semantic import SemanticDetector
from domestique.models import Action, Detection, Span
from domestique.policy import PolicyEngine
from domestique.taxonomy import normalize_category

if TYPE_CHECKING:
    from domestique.detectors import Detector
    from domestique.vault.service import TokenService

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

                def _ensure_model(self) -> None:
                    if self._model is not None or self._unavailable:
                        return
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
                                    category=normalize_category(e["label"]),
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
    #: Reversible tokens this redaction actually minted/used, e.g.
    #: ``{"[SSN_1]"}``. Only these — never a token-shaped string the user
    #: happened to type — are safe for the response detokenizer to reverse.
    minted_tokens: set[str] = field(default_factory=set)

    @property
    def should_block(self) -> bool:
        return self.action is Action.BLOCK


class DetectorPipeline:
    """Async pipeline: run all detectors -> evaluate policy -> redact if needed.

    Designed to be created once per process and reused across requests. All
    detectors are stateless after construction, so ``inspect`` is safe to call
    concurrently.
    """

    def __init__(
        self,
        detectors: list[Detector],
        policy: PolicyEngine,
        token_service: TokenService | None = None,
    ) -> None:
        self._detectors = detectors
        self._policy = policy
        self._token_service = token_service

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

        # Guaranteed-recall fast path: exact-match scan for pinned vault
        # values runs regardless of what the detectors find, so a pinned
        # secret can never leak on a detector miss.
        pinned_detections: list[Detection] = (
            _scan_pinned(text, self._token_service) if self._token_service else []
        )

        detections: list[Detection] = list(pinned_detections)
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
        if pinned_detections and action is Action.ALLOW:
            # Pinned values are user-confirmed secrets; the policy file may
            # not know their category, but they must never pass unredacted.
            action, reason = Action.REDACT, "pinned vault value present"
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
        minted_tokens: set[str] = set()
        if action is Action.REDACT and detections:
            redacted_text, minted_tokens = _redact_text(text, detections, self._token_service)

        return InspectionResult(
            action=action,
            reason=reason,
            findings=findings,
            redacted_text=redacted_text,
            minted_tokens=minted_tokens,
        )


def create_detector_pipeline(
    settings: Settings | None = None,
    token_service: TokenService | None = None,
) -> DetectorPipeline:
    """Build the full detection pipeline used by the browser MITM addon.

    A session-scoped ``TokenService`` is created by default so browser-path
    redactions mint numbered reversible tokens like the CLI gateway does.

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

    if token_service is None:
        from domestique.vault.service import TokenService
        from domestique.vault.session import SessionStore

        token_service = TokenService(SessionStore(), None)

    return DetectorPipeline(
        detectors=build_detectors(settings),
        policy=PolicyEngine.from_yaml(policy_path),
        token_service=token_service,
    )


def _redaction_priority(det: Detection) -> tuple[int, float]:
    """Ranking used to pick the category when overlapping spans are merged.

    Pinned-vault detections are user-confirmed secrets and win outright;
    otherwise the highest-confidence detection's category is used.
    """
    return (1 if det.detector == "pinned_vault" else 0, det.confidence)


def _redact_text(
    text: str, detections: list[Detection], token_service: TokenService | None = None
) -> tuple[str, set[str]]:
    """Replace each detection span with a redaction marker.

    Returns ``(redacted_text, minted_tokens)`` where ``minted_tokens`` are
    exactly the reversible tokens this call produced — the scope the response
    detokenizer is allowed to reverse.

    With a ``TokenService``, markers are reversible numbered tokens like
    ``[SSN_1]`` (distinct values → distinct numbers); without one, the
    legacy irreversible ``[CATEGORY_REDACTED]`` placeholder is used.

    Overlapping spans are coalesced into their **union** and redacted as one
    token, never dropped. Dropping an overlapping detection (the previous
    behaviour) forwarded the exclusive prefix of the dropped span to the
    provider in cleartext — e.g. two spans over ``123-45-6789`` and its
    ``5-6789`` tail leaked ``123-4``. Disjoint spans that merely touch
    (``a.end == b.start``) are kept separate so two adjacent distinct
    secrets still get two tokens. The merged span's category comes from its
    highest-priority member (see ``_redaction_priority``).
    """
    # Drop zero-length spans (e.g. the synthetic detector_error marker at
    # (0, 0)) — they carry no text to redact.
    spans = [d for d in detections if d.span.end > d.span.start]
    if not spans:
        return text, set()
    spans.sort(key=lambda d: (d.span.start, d.span.end))

    # Coalesce true overlaps into (start, end, category) unions.
    merged: list[tuple[int, int, str]] = []
    cur_start = spans[0].span.start
    cur_end = spans[0].span.end
    cur_best = spans[0]
    for det in spans[1:]:
        if det.span.start < cur_end:  # overlap (touching is not overlap)
            cur_end = max(cur_end, det.span.end)
            if _redaction_priority(det) > _redaction_priority(cur_best):
                cur_best = det
        else:
            merged.append((cur_start, cur_end, cur_best.category))
            cur_start, cur_end, cur_best = det.span.start, det.span.end, det
    merged.append((cur_start, cur_end, cur_best.category))

    # Apply right-to-left so earlier offsets stay valid as we splice.
    redacted = text
    minted: set[str] = set()
    for start, end, category in reversed(merged):
        value = text[start:end]
        if token_service is not None:
            placeholder = token_service.tokenize(value, category)
            token_service.record_sighting(value, category)
            minted.add(placeholder)
        else:
            placeholder = f"[{category.upper()}_REDACTED]"
        redacted = redacted[:start] + placeholder + redacted[end:]
    return redacted, minted


def _scan_pinned(text: str, token_service: TokenService) -> list[Detection]:
    """Exact-match every pinned vault value against *text* (all occurrences)."""
    detections: list[Detection] = []
    if token_service.pinned is None:
        return detections
    for value, (_token, category) in token_service.pinned.values().items():
        start = text.find(value)
        while start != -1:
            detections.append(
                Detection(
                    detector="pinned_vault",
                    category=category,
                    confidence=1.0,
                    span=Span(start, start + len(value)),
                )
            )
            start = text.find(value, start + len(value))
    return detections
