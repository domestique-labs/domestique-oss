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

import re
from typing import Any

import structlog

from domestique.models import Detection, Span
from domestique.taxonomy import CANONICAL, GENERIC_CATEGORY, GENERIC_PREFIX, normalize_category
from domestique.taxonomy_store import default_store

logger = structlog.get_logger()

#: Confidence floor for an item whose substring appears verbatim in the scanned
#: text. Such a span has been confirmed *by us*, not merely asserted by the
#: model, so the model's opinion of its own confidence must not be able to veto
#: our verification — real models return ``v: 0.0`` (or omit ``v``) for genuine
#: secrets, which used to drop them silently and send them upstream in
#: cleartext. 0.7 matches the default ``confidence_threshold`` so a verified
#: span always clears its own gate; an operator who deliberately raises the
#: threshold above 0.7 still gets the stricter behaviour they asked for.
_VERBATIM_FLOOR = 0.7


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

#: Generation cap for the extractor (Ollama ``num_predict``).
#:
#: This tier used to be a whole-text classifier answering with a single word, so
#: 40 tokens was plenty. It is now a *span extractor* that returns a JSON array
#: of ``{"t","c","v"}`` objects — roughly 25-30 tokens each — and 40 truncated
#: that array mid-object on any realistic multi-entity prompt, which parsed to
#: nothing and silently dropped every LLM finding.
#:
#: The cap is a runaway guard, not a target: the model emits its array and
#: stops, so a larger cap costs nothing in the normal case — 40 was capping
#: *ordinary* output. Truncation past the cap is salvaged in _parse_response.
_EXTRACTOR_MAX_TOKENS = 512

MODEL_PRESETS: dict[str, dict[str, Any]] = {
    "minimal": {
        "model": "qwen3:1.7b",
        "description": "CPU-only, 1.5GB RAM, lightweight",
        "max_tokens": _EXTRACTOR_MAX_TOKENS,
        "temperature": 0.0,
    },
    "balanced": {
        "model": _resolve_gemma_model(),
        "description": "Gemma 4 E2B, auto-selects MLX on Apple Silicon",
        "max_tokens": _EXTRACTOR_MAX_TOKENS,
        "temperature": 0.0,
    },
    "quality": {
        "model": _resolve_gemma_model(),
        "description": "Same as balanced (Gemma 4 E2B is already high quality)",
        "max_tokens": _EXTRACTOR_MAX_TOKENS,
        "temperature": 0.0,
    },
    "legacy-cpu": {
        "model": "llama3.2:1b",
        "description": "Fallback for non-Google environments, 2GB RAM",
        "max_tokens": _EXTRACTOR_MAX_TOKENS,
        "temperature": 0.0,
    },
}

# System prompt for the LLM extractor.
# Participants can improve this via the workshop prompt competition.
_EXTRACTOR_SYSTEM_PROMPT = """\
You are a DLP entity extractor. Find every sensitive value in the text
(secrets, credentials, PII, proprietary identifiers).

Return a JSON array. Each element:
  {"t": "<the exact sensitive substring, copied verbatim>",
   "c": "<category>",
   "v": <confidence 0.0-1.0>}

Prefer these category names when one fits:
%(categories)s
If none fits, invent a short snake_case category name (e.g. employee_id).
Copy "t" EXACTLY as it appears in the text — do not paraphrase or reformat.

"t" must be the sensitive VALUE, never the word that labels it — a field name
leaks nothing on its own. Extract every other value in the text as usual:
  "Employee Jane Roe, badge B-77, mobile 555-0142"
  [{"t":"Jane Roe","c":"person","v":0.9},
   {"t":"B-77","c":"employee_id","v":0.8},
   {"t":"555-0142","c":"phone_number","v":0.9}]
  ("Employee", "badge" and "mobile" are labels, so they are not extracted.)

Return [] if nothing is sensitive. Output ONLY the JSON array."""


def default_system_prompt() -> str:
    """The extractor prompt as the detector actually uses it.

    Public on purpose: the dashboard's "reset prompt to default" endpoint needs
    the same string, and importing the private template left it serving a raw,
    uninterpolated template — then broke outright when the template was renamed.
    """
    return _EXTRACTOR_SYSTEM_PROMPT % {"categories": "\n".join(sorted(CANONICAL))}


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
        self._warned_unusable = False
        self._system_prompt = system_prompt or default_system_prompt()

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
        """Extract sensitive substrings and emit one Detection per located span.

        For texts longer than _MAX_CHUNK_CHARS, splits into chunks and
        extracts from each independently. Substrings the model hallucinated
        (not present verbatim) are dropped; each surviving substring is redacted
        at every occurrence in the text, since the model reports an entity once
        even when it repeats.
        """
        if len(text) < 20:
            return []

        items: list[dict[str, Any]] = []
        for chunk in self._chunk_text(text):
            parsed = await self._classify(chunk)
            if isinstance(parsed, list):
                items.extend(x for x in parsed if isinstance(x, dict))

        detections: list[Detection] = []
        emitted: set[str] = set()  # substrings already expanded to all occurrences
        for item in items:
            substring = str(item.get("t", ""))
            if not substring or substring in emitted:
                continue
            try:
                confidence = float(item.get("v", item.get("confidence", 0.0)))
            except (TypeError, ValueError):
                continue
            if substring not in text:
                continue  # hallucinated / reformatted → drop (guardrail)
            # Verification first, then the gate: the span is confirmed present,
            # so floor the model's self-reported confidence (see _VERBATIM_FLOOR).
            confidence = max(confidence, _VERBATIM_FLOOR)
            if confidence < self._threshold:
                continue
            emitted.add(substring)
            raw_cat = str(item.get("c", item.get("category", GENERIC_CATEGORY)))
            term = normalize_category(raw_cat)
            # ``c`` is untrusted: a model that echoes the scanned text into it
            # is handing us a leaked value, not a label. register() refuses to
            # coin or persist those and answers GENERIC_PREFIX; fall back to the
            # generic category so the secret never reaches the outbound token
            # either (prefix_for would otherwise derive the prefix from `term`).
            if (
                term not in CANONICAL
                and default_store().register(raw_cat, scanned_text=text) == GENERIC_PREFIX
            ):
                term = GENERIC_CATEGORY
            category = term
            # Redact EVERY occurrence, not just the one the model happened to
            # point at. The model reports an entity once even when it repeats,
            # and for an LLM-coined category no other tier will catch the rest —
            # so the remaining occurrences would go upstream in cleartext.
            start = text.find(substring)
            while start != -1:
                detections.append(
                    Detection(
                        detector=self.name,
                        category=category,
                        confidence=confidence,
                        span=Span(start=start, end=start + len(substring)),
                    )
                )
                start = text.find(substring, start + len(substring))
        return detections

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

    async def _classify(self, text: str) -> list[dict[str, Any]] | None:
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

    async def _classify_ollama(self, text: str) -> list[dict[str, Any]] | None:
        """Classify via Ollama API.

        Speed optimizations (all cross-platform):
        - top_k=1, top_p=0.1 : greedy decoding, no sampling overhead
        - think=False : disable chain-of-thought on Qwen/Gemma
        - Compact output format [{"t":"...","c":"CAT","v":0.9}] minimizes tokens

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
            }
        ).encode()

        # Bypass system proxy to prevent deadlock when mitmproxy is active
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(  # noqa: S310  # trusted local base_url, not user input
            f"{self._base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        # Deliberately unguarded: transport/decode failures propagate to
        # ``_classify``, which marks the tier unavailable and logs
        # ``local_llm_unavailable`` once. Swallowing them here made that handler
        # dead code for the ollama backend, so a missing or misnamed model (404)
        # silently produced zero findings forever with no operator signal — a
        # fail-open on a DLP path.
        resp = opener.open(req, timeout=self._timeout)
        body = json.loads(resp.read())

        content = body.get("message", {}).get("content", "")
        parsed = self._parse_response(content)
        if parsed is None and not self._warned_unusable:
            # The tier is reachable but producing nothing usable — most often a
            # custom prompt saved before this became a span extractor. That is a
            # silent fail-open otherwise: DEBUG-level only, so nobody sees that
            # detection has stopped. Warn once, not per request.
            self._warned_unusable = True
            logger.warning(
                "local_llm_unusable_response",
                model=self._model,
                hint=(
                    "the model's reply could not be parsed as the extractor's JSON array; "
                    "if you saved a custom prompt in the dashboard it predates this format "
                    "— reset it to the default, or the LLM tier contributes no detections."
                ),
                sample=content[:120],
            )
        return parsed

    #: Recovers "t"/"c"/"v" triples when the model drops the object braces
    #: entirely (observed from qwen3:1.7b: ["t":"x","c":"y","v":0.9],[...]).
    _TRIPLE_RE = re.compile(
        r'"t"\s*:\s*"((?:[^"\\]|\\.)*)"\s*,\s*'
        r'"c"\s*:\s*"((?:[^"\\]|\\.)*)"\s*,\s*'
        r'"v"\s*:\s*"?([-\d.eE]+)"?'
    )

    @classmethod
    def _parse_response(cls, content: str) -> list[dict[str, Any]] | None:
        """Recover the extractor's items from whatever the model actually said.

        Returning ``None`` means zero detections and the prompt goes upstream in
        CLEARTEXT, so this is deliberately tolerant: small models wrap the array
        in prose, emit a ``<think>`` block despite ``think=False``, append
        trailing chatter, get cut off mid-object by ``num_predict``, or drop the
        object braces altogether. Every recovered item is still re-vetted by
        ``scan`` (must appear verbatim in the text, must clear the confidence
        threshold), so tolerating junk here cannot manufacture a redaction.
        """
        import json

        if not isinstance(content, str):
            return None
        content = content.strip()
        if "```" in content:
            content = content.replace("```json", "").replace("```", "").strip()
        # some models emit reasoning even with think=False
        content = re.sub(r"(?s)<think>.*?</think>", "", content).strip()

        def _as_items(value: object) -> list[dict[str, Any]] | None:
            if isinstance(value, dict):
                return [value]  # legacy classifier-era prompts return one object
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
            return None

        # 1. the well-formed case
        try:
            items = _as_items(json.loads(content))
        except (json.JSONDecodeError, RecursionError):
            items = None
        if items is not None:
            return items

        # 2. Scan for complete objects anywhere in the text. This subsumes
        #    truncation (the incomplete tail simply fails to decode and is
        #    skipped) and is immune to a "}" inside a string value, unlike
        #    cutting back to the last "}".
        decoder = json.JSONDecoder()
        found: list[dict[str, Any]] = []
        i = content.find("{")
        while i != -1:
            try:
                obj, offset = decoder.raw_decode(content, i)
            except (json.JSONDecodeError, RecursionError):
                i = content.find("{", i + 1)
                continue
            if isinstance(obj, dict):
                found.append(obj)
                i = content.find("{", offset)
            else:
                i = content.find("{", i + 1)
        if found:
            logger.debug("local_llm_salvaged_response", kept=len(found))
            return found

        # 3. Braces dropped entirely — pull the triples out directly.
        triples = cls._TRIPLE_RE.findall(content)
        if triples:
            logger.debug("local_llm_recovered_braceless_items", kept=len(triples))
            return [{"t": t, "c": c, "v": v} for t, c, v in triples]

        logger.debug("local_llm_unparseable_response", content=content[:100])
        return None
