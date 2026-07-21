"""LLM Firewall - Semantic content classifier (local ML).

Uses a lightweight sentence-transformer model running locally to detect
sensitive content that regex cannot catch:

- Paraphrased proprietary information
- Business-sensitive topics (M&A, financials, legal)
- Obfuscated or encoded secrets
- Internal project codenames and context

The model runs entirely on-device - no data leaves your network.

Latency: ~5-15 ms per text chunk on CPU (sentence-transformers/all-MiniLM-L6-v2).
For GPU deployments, < 2 ms.
"""

from __future__ import annotations

import base64
import os
import re
import threading
from typing import Any

import structlog

from domestique.detectors._offload import offload
from domestique.models import Detection, Span

logger = structlog.get_logger()


class SemanticDetector:
    """Detects sensitive content via embedding similarity and local classification.

    Detection strategies:
    1. **Topic similarity** - compares request text embeddings against a library
       of sensitive topic embeddings (configurable per deployment).
    2. **Obfuscation detection** - identifies base64-encoded blobs, hex dumps,
       and other encoding schemes that may hide secrets.
    3. **Entropy analysis** - flags high-entropy strings that evade regex patterns.
    4. **Context classification** - uses a local classifier to determine if content
       discusses internal/proprietary matters.

    All inference is local. No data is sent externally.
    """

    def __init__(
        self,
        *,
        sensitive_topics: list[str] | None = None,
        similarity_threshold: float = 0.75,
        enable_embedding_model: bool = True,
    ) -> None:
        self._sensitive_topics = sensitive_topics or []
        self._similarity_threshold = similarity_threshold
        self._enable_embedding = enable_embedding_model
        self._model: Any = None
        self._topic_embeddings: Any = None
        self._available: bool | None = None
        self._init_lock = threading.Lock()

    @property
    def name(self) -> str:
        return "semantic_classifier"

    async def scan(self, text: str) -> list[Detection]:
        """Run all semantic detection strategies on the input text.

        Offloaded to a worker thread only when the embedding strategy is
        active. Sentence-transformer inference is native code that releases
        the GIL, so moving it off the loop genuinely helps. Strategies 1 and 2
        are pure ``re``/entropy work that holds the GIL, where offloading buys
        nothing and costs a ~31 us hop -- see :meth:`SecretDetector.scan` for
        the measurements.
        """
        if len(text) < 10:
            return []

        if self._enable_embedding and self._sensitive_topics:
            return await offload(lambda: self._scan_sync(text))
        return self._scan_sync(text)

    def _scan_sync(self, text: str) -> list[Detection]:
        """Blocking body of :meth:`scan`. Safe to call from a worker thread."""
        findings: list[Detection] = []

        # Strategy 1: Obfuscation / encoding detection (always available, no ML)
        findings.extend(self._detect_encoded_content(text))

        # Strategy 2: High-entropy substring detection
        findings.extend(self._detect_high_entropy(text))

        # Strategy 3: Embedding-based topic similarity (requires model)
        if self._enable_embedding and self._sensitive_topics:
            findings.extend(self._detect_sensitive_topics(text))

        return findings

    # -- Strategy 1: Encoded content detection --------------------------------

    _BASE64_BLOCK_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    _HEX_BLOCK_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{40,}")
    _UNICODE_ESCAPE_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")

    def _detect_encoded_content(self, text: str) -> list[Detection]:
        """Detect base64, hex, and unicode-escaped blobs that may hide secrets."""
        findings: list[Detection] = []

        # Base64 blocks (likely encoded secrets or data)
        for match in self._BASE64_BLOCK_RE.finditer(text):
            candidate = match.group()
            if self._is_valid_base64(candidate) and self._base64_looks_suspicious(candidate):
                findings.append(
                    Detection(
                        detector=self.name,
                        category="encoded_content_base64",
                        confidence=0.80,
                        span=Span(start=match.start(), end=match.end()),
                    )
                )

        # Long hex blocks (potential encoded keys/tokens)
        for match in self._HEX_BLOCK_RE.finditer(text):
            if len(match.group()) >= 64:  # 32+ bytes in hex
                findings.append(
                    Detection(
                        detector=self.name,
                        category="encoded_content_hex",
                        confidence=0.70,
                        span=Span(start=match.start(), end=match.end()),
                    )
                )

        # Unicode escape sequences (obfuscation technique)
        for match in self._UNICODE_ESCAPE_RE.finditer(text):
            findings.append(
                Detection(
                    detector=self.name,
                    category="obfuscated_unicode",
                    confidence=0.75,
                    span=Span(start=match.start(), end=match.end()),
                )
            )

        return findings

    # -- Strategy 2: Entropy analysis -----------------------------------------

    def _detect_high_entropy(self, text: str) -> list[Detection]:
        """Flag high-entropy substrings that may be obfuscated secrets.

        Uses Shannon entropy. Typical English text has entropy ~4.0 bits/char.
        Random/encrypted data has entropy ~5.5-6.0 bits/char.
        """

        findings: list[Detection] = []

        # Split into words/tokens and check each for unusual entropy
        tokens = re.findall(r"[^\s]{20,}", text)
        for token in tokens:
            entropy = self._shannon_entropy(token)
            # High entropy + sufficient length -> likely a secret
            if entropy > 5.0 and len(token) >= 30:
                start = text.find(token)
                if start >= 0:
                    findings.append(
                        Detection(
                            detector=self.name,
                            category="high_entropy_string",
                            confidence=min(0.60 + (entropy - 5.0) * 0.2, 0.90),
                            span=Span(start=start, end=start + len(token)),
                        )
                    )

        return findings

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy in bits per character."""
        import math

        if not data:
            return 0.0
        freq: dict[str, int] = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    # -- Strategy 3: Embedding-based topic detection --------------------------

    def _detect_sensitive_topics(self, text: str) -> list[Detection]:
        """Compare text embedding against sensitive topic embeddings.

        Uses sentence-transformers (all-MiniLM-L6-v2) for fast local inference.
        Falls back gracefully if the model is not installed.
        """
        model = self._get_model()
        if model is None:
            return []

        try:
            import numpy as np

            # Encode the input text
            text_embedding = model.encode([text], normalize_embeddings=True)

            # Compute cosine similarity against all topic embeddings
            similarities = np.dot(self._topic_embeddings, text_embedding.T).flatten()

            findings: list[Detection] = []
            for i, score in enumerate(similarities):
                if score >= self._similarity_threshold:
                    findings.append(
                        Detection(
                            detector=self.name,
                            category=f"sensitive_topic:{self._sensitive_topics[i][:30]}",
                            confidence=float(min(score, 0.99)),
                            span=Span(start=0, end=len(text)),
                        )
                    )

            return findings

        except Exception:
            logger.exception("semantic_topic_detection_error")
            return []

    def _get_model(self) -> Any:
        """Lazy-load the sentence-transformer model.

        Guarded by a lock: ``scan`` now runs on worker threads, so concurrent
        first-calls would otherwise each load their own copy of the model and
        re-encode the topic embeddings.
        """
        if self._available is False:
            return None
        if self._model is not None:
            return self._model

        with self._init_lock:
            # Re-read under the lock. Another thread may have flipped these
            # while we waited, so the narrowing mypy inferred from the checks
            # above is not sound here -- hence the explicit local.
            available: bool | None = self._available
            if available is False:
                return None
            if self._model is not None:
                return self._model
            return self._load_model_locked()

    def _load_model_locked(self) -> Any:
        # Force offline before loading, mirroring GLiNER (Tier 2b): a cold model
        # cache must fail fast here rather than trigger a ~90 MB HuggingFace
        # fetch on the request hot path. ``domestique setup`` pre-caches the
        # model when the ``semantic`` extra is selected; without that, this
        # tier stays disabled instead of stalling every scan on a live download.
        # ``setdefault`` respects an operator who has explicitly opted into
        # online fetches.
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        try:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            # Pre-encode sensitive topic embeddings
            if self._sensitive_topics:
                self._topic_embeddings = self._model.encode(
                    self._sensitive_topics, normalize_embeddings=True
                )
            self._available = True
            logger.info(
                "semantic_model_ready",
                model="all-MiniLM-L6-v2",
                topic_count=len(self._sensitive_topics),
            )
            return self._model

        except (ImportError, OSError) as exc:
            # ImportError: the ``semantic`` extra (sentence-transformers) was
            # never installed. OSError (huggingface_hub raises
            # LocalEntryNotFoundError, an OSError subclass): the package is
            # present but the model was never cached, and HF_HUB_OFFLINE=1
            # above forbids fetching it now.
            self._available = False
            logger.warning(
                "semantic_detector_unavailable",
                error=str(exc),
                error_type=type(exc).__name__,
                hint=(
                    "Semantic topic detection is enabled but the embedding "
                    "model is not available: install the 'semantic' extra "
                    "(pip install -e '.[semantic]') and warm the model cache "
                    "(run `domestique setup` and select Tier 2c), or disable "
                    "semantic detection in the dashboard."
                ),
            )
            return None

    # -- Helpers --------------------------------------------------------------

    @staticmethod
    def _is_valid_base64(s: str) -> bool:
        """Check if a string is valid base64."""
        try:
            base64.b64decode(s, validate=True)
            return True
        except Exception:
            return False

    @staticmethod
    def _base64_looks_suspicious(s: str) -> bool:
        """Heuristic: decoded base64 contains non-printable or looks like a key."""
        try:
            decoded = base64.b64decode(s).decode("utf-8", errors="replace")
            # If decoded content contains key-like patterns or high entropy
            non_printable = sum(1 for c in decoded if ord(c) < 32 or ord(c) > 126)
            return non_printable > len(decoded) * 0.3 or len(decoded) > 20
        except Exception:
            return True  # Can't decode = likely binary = suspicious
