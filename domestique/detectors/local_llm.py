"""LLM Firewall - Local LLM classifier for nuanced content analysis.

Uses a small local model (via Ollama) to perform free-form classification
that neither regex nor embeddings can handle:

- "Is this user trying to exfiltrate source code?"
- "Does this message contain proprietary business strategy?"
- "Is sensitive information being rephrased to avoid detection?"

The local LLM never sends data externally - it runs on the same host
or an internal GPU cluster.

Recommended models (via Ollama):
- gemma4:e2b-mlx     - Apple Silicon native (nvfp4), ~150ms, best on Mac
- gemma4:e2b         - Q4_K_M GGUF, ~280ms, works everywhere
- qwen3:1.7b         - 1.5GB RAM, lightweight CPU fallback

On Apple Silicon the MLX variant is auto-selected for ~2x faster inference.
On Linux/Windows the GGUF Q4_K_M variant is used with optimized decoding.

This detector is designed as a **second-pass** - only invoked when
fast detectors (regex, embeddings) produce ambiguous results, keeping
the common-case latency near zero.
"""

from __future__ import annotations

from typing import Any

import structlog

from domestique.models import Detection, Span

logger = structlog.get_logger()


def _is_apple_silicon() -> bool:
    """Detect Apple Silicon (M1/M2/M3/M4) for MLX model selection."""
    import platform

    return platform.system() == "Darwin" and platform.machine() in ("arm64", "aarch64")


def _resolve_gemma_model() -> str:
    """Pick the fastest Gemma 4 E2B variant for this platform.

    Apple Silicon: gemma4:e2b-mlx (nvfp4, Metal-native, ~150ms)
    Everything else: gemma4:e2b (Q4_K_M GGUF, ~280ms)
    """
    return "gemma4:e2b-mlx" if _is_apple_silicon() else "gemma4:e2b"


# ═══════════════════════════════════════════════════════════════════════════════
# Model presets - tuned for different hardware profiles.
# ═══════════════════════════════════════════════════════════════════════════════

MODEL_PRESETS: dict[str, dict[str, Any]] = {
    "minimal": {
        "model": "qwen3:1.7b",
        "description": "CPU-only, 1.5GB RAM, lightweight",
        "max_tokens": 40,
        "temperature": 0.0,
    },
    "balanced": {
        "model": _resolve_gemma_model(),
        "description": "Gemma 4 E2B, auto-selects MLX on Apple Silicon",
        "max_tokens": 40,
        "temperature": 0.0,
    },
    "quality": {
        "model": _resolve_gemma_model(),
        "description": "Same as balanced (Gemma 4 E2B is already high quality)",
        "max_tokens": 40,
        "temperature": 0.0,
    },
    "legacy-cpu": {
        "model": "llama3.2:1b",
        "description": "Fallback for non-Google environments, 2GB RAM",
        "max_tokens": 40,
        "temperature": 0.0,
    },
}

# System prompt for the LLM classifier.
# Participants can improve this via the workshop prompt competition.
_CLASSIFIER_SYSTEM_PROMPT = """\
You are a DLP classifier. Classify if text contains sensitive data.

Categories (pick one):
- PROPRIETARY_CODE: source code, algorithms, internal tooling
- BUSINESS_STRATEGY: M&A plans, financials, competitive intelligence
- CUSTOMER_DATA: PII - emails, phones, SSNs, addresses, medical records
- INTERNAL_COMMS: forwarded emails, Slack messages, meeting notes
- CREDENTIALS: passwords, API keys, tokens, connection strings
- NONE: safe content, public knowledge, generic questions

Respond with JSON: {"c":"<CATEGORY>","v":<0.0-1.0>}"""


class LocalLLMClassifier:
    """Uses a local LLM for nuanced sensitive content classification.

    Auto-selects the fastest model variant for the current platform.
    Configurable via presets or explicit model override.
    """

    def __init__(
        self,
        *,
        backend: str = "ollama",
        model: str = "",
        preset: str = "balanced",
        base_url: str = "http://localhost:11434",
        timeout_s: float = 30.0,
        confidence_threshold: float = 0.7,
        system_prompt: str = "",
    ) -> None:
        self._backend = backend
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_s
        self._threshold = confidence_threshold
        self._available: bool | None = None
        self._system_prompt = system_prompt or _CLASSIFIER_SYSTEM_PROMPT

        # Resolve model: explicit override > preset > default
        if model:
            self._model = model
        else:
            preset_config = MODEL_PRESETS.get(preset, MODEL_PRESETS["balanced"])
            self._model = preset_config["model"]

        self._preset = preset
        preset_config = MODEL_PRESETS.get(preset, MODEL_PRESETS["balanced"])
        self._max_tokens = preset_config.get("max_tokens", 100)
        self._temperature = preset_config.get("temperature", 0.0)

    @property
    def name(self) -> str:
        return "local_llm_classifier"

    @property
    def model(self) -> str:
        """The resolved model name being used."""
        return self._model

    def should_invoke(self, prior_detections: list[Detection]) -> bool:
        """Gate: only invoke local LLM when fast detectors are ambiguous.

        Invoke when:
        - There are medium-confidence findings (0.4-0.8) that need confirmation
        - The semantic detector flagged something but below block threshold
        - Content is long and complex (> 500 chars with some findings)
        """
        ambiguous = [d for d in prior_detections if 0.4 <= d.confidence <= 0.8]
        return len(ambiguous) > 0

    async def scan(self, text: str) -> list[Detection]:
        """Classify text using the local LLM.

        For texts longer than _MAX_CHUNK_CHARS, splits into chunks and
        evaluates each independently. If any chunk is flagged, the full
        request is flagged (union of all violations).
        """
        if len(text) < 20:
            return []

        chunks = self._chunk_text(text)
        all_detections: list[Detection] = []
        seen_categories: set[str] = set()

        for chunk in chunks:
            result = await self._classify(chunk)
            if result is None:
                continue
            category = result.get("c", result.get("category", "NONE"))
            confidence = float(result.get("v", result.get("confidence", 0.0)))
            if category == "NONE" or confidence < self._threshold:
                continue
            cat_key = f"llm_classified:{category.lower()}"
            # Deduplicate: overlapping chunks may flag the same category
            if cat_key in seen_categories:
                continue
            seen_categories.add(cat_key)
            all_detections.append(
                Detection(
                    detector=self.name,
                    category=cat_key,
                    confidence=confidence,
                    span=Span(start=0, end=len(text)),
                )
            )

        return all_detections

    # 8K chars (~2K tokens) per chunk — fits in num_ctx=4096 with system prompt.
    _MAX_CHUNK_CHARS = 8000
    _OVERLAP_CHARS = 500  # overlap between chunks to avoid missing context at boundaries

    @staticmethod
    def _chunk_text(text: str, max_chars: int = 8000, overlap: int = 500) -> list[str]:
        """Split text into overlapping chunks, breaking at paragraph/line boundaries.

        Overlap ensures sensitive content spanning a chunk boundary is not missed.
        """
        if len(text) <= max_chars:
            return [text]
        chunks = []
        start = 0
        while start < len(text):
            end = start + max_chars
            if end < len(text):
                # Try to break at a paragraph or line boundary
                break_at = text.rfind("\n\n", start, end)
                if break_at == -1 or break_at <= start:
                    break_at = text.rfind("\n", start, end)
                if break_at == -1 or break_at <= start:
                    break_at = text.rfind(" ", start, end)
                if break_at > start:
                    end = break_at + 1
            chunks.append(text[start:end])
            # Step forward by (chunk_size - overlap) so chunks overlap
            step = (end - start) - overlap
            start += max(step, overlap)  # ensure forward progress
        return chunks

    async def _classify(self, text: str) -> dict[str, Any] | None:
        """Send a single chunk to the local LLM and parse the response."""
        if self._available is False:
            return None

        try:
            if self._backend == "ollama":
                return await self._classify_ollama(text)
            else:
                logger.warning("unsupported_local_llm_backend", backend=self._backend)
                return None

        except Exception as exc:
            if self._available is None:
                self._available = False
                logger.warning(
                    "local_llm_unavailable",
                    error=str(exc),
                    backend=self._backend,
                    model=self._model,
                )
            return None

    async def _classify_ollama(self, text: str) -> dict[str, Any] | None:
        """Classify via Ollama API.

        Speed optimizations (all cross-platform):
        - stop=["}"] : halt generation the instant JSON closes
        - top_k=1, top_p=0.1 : greedy decoding, no sampling overhead
        - think=False : disable chain-of-thought on Qwen/Gemma
        - Compact output format {"c":"CAT","v":0.9} minimizes tokens

        Uses stdlib urllib instead of httpx to avoid anyio dependency
        issues in py2app bundles.
        """
        import json
        import urllib.request

        payload = json.dumps(
            {
                "model": self._model,
                "messages": [
                    {"role": "system", "content": self._system_prompt},
                    {"role": "user", "content": text},
                ],
                "stream": False,
                "think": False,
                "keep_alive": "30m",
                "options": {
                    "temperature": self._temperature,
                    "num_predict": self._max_tokens,
                    "num_ctx": 4096,
                    "top_k": 1,
                    "top_p": 0.1,
                },
                "stop": ["}"],
            }
        ).encode()

        # Bypass system proxy to prevent deadlock when mitmproxy is active
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(  # noqa: S310  # trusted local base_url, not user input
            f"{self._base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            resp = opener.open(req, timeout=self._timeout)
            body = json.loads(resp.read())
        except Exception:
            return None

        content = body.get("message", {}).get("content", "")
        return self._parse_response(content)

    @staticmethod
    def _parse_response(content: str) -> dict[str, Any] | None:
        """Parse LLM JSON response, handling stop-token truncation and markdown."""
        import json

        content = content.strip()
        # Strip markdown code fences (some models wrap output)
        if "```" in content:
            content = content.replace("```json", "").replace("```", "").strip()
        # stop="}" truncates the closing brace
        if not content.endswith("}"):
            content += "}"
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            logger.debug("local_llm_unparseable_response", content=content[:100])
            return None
