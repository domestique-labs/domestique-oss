"""Typed configuration schema and defaults.

All configuration fields are defined here with their types and default values.
This serves as the single source of truth for what the app can be configured to do.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Literal


@dataclass
class DetectionStackConfig:
    """Which detectors are enabled in the inspection pipeline."""

    regex: bool = True
    """Tier 1: Compiled regex patterns for secrets, API keys, passwords. ~0.03ms."""

    gliner_pii: bool = False
    """Tier 2: GLiNER2-PII zero-shot NER model (300M params). ~20ms. High recall but adds false positives."""

    openai_privacy_filter: bool = False
    """Tier 2: OpenAI Privacy Filter (1.5B params). ~130ms. Heavy."""

    gemma4_e2b: bool = False
    """Tier 3: Gemma 4 E2B via Ollama. ~155ms (MLX) / ~285ms (GGUF). Best quality. Needs 32GB+ RAM."""

    qwen3_1_7b: bool = True
    """Tier 3: Qwen3 1.7B via Ollama. ~163ms. 1.8GB VRAM. Default - fits 16GB laptops."""

    legacy_cpu: bool = False
    """Tier 3: Llama 3.2 1B via Ollama. CPU-only fallback, ~2GB RAM. Used by the
    installer's 'legacy-cpu' preset for machines with no usable GPU."""



@dataclass
class AppConfig:
    """Root application configuration.

    Persisted to ~/.llmguard/config.json.
    Loaded on startup, saved on any change via the dashboard or menu bar.
    """

    proxy_enabled: bool = False
    """Whether the transparent proxy is currently active."""

    proxy_port: int = 8000
    """Port the proxy listens on."""

    detection_stack: DetectionStackConfig = field(default_factory=DetectionStackConfig)
    """Active detectors configuration."""

    llm_preset: Literal["minimal", "balanced", "quality", "legacy-cpu"] = "balanced"
    """Hardware preset controlling which models are loaded."""

    fail_mode: Literal["open", "closed"] = "closed"
    """Behavior when a detector errors: 'closed' blocks, 'open' allows."""

    ollama_url: str = "http://localhost:11434"
    """Ollama API endpoint for local LLM inference."""

    audit_logging: bool = True
    """Whether to write audit logs for every inspected request."""

    browser_interception: bool = False
    """Whether to intercept browser/native app traffic to LLM endpoints."""

    browser_proxy_port: int = 8080
    """Port for the HTTPS interception proxy (mitmproxy)."""

    approval_mode: bool = False
    """When True, flagged requests go to approval queue instead of immediate block."""

    approval_timeout_seconds: int = 30
    """Seconds before a pending approval is automatically denied."""

    classifier_prompt: str = ""
    """Custom system prompt for the LLM classifier (Tier 3).
    
    Leave empty to use the built-in default. When set, this replaces the
    system prompt sent to the local LLM (Qwen3/Gemma) for classification.
    The prompt must instruct the model to respond with JSON:
    {"category": "<CATEGORY>", "confidence": <0.0-1.0>, "reason": "<text>"}
    """

    custom_patterns: list = field(default_factory=list)
    """User-defined regex patterns for detection.
    
    Each entry is a dict: {"name": str, "regex": str, "confidence": float, "category": str}
    Patterns are compiled and merged into Tier 1 at runtime.
    """

    disabled_builtin_patterns: list = field(default_factory=list)
    """Names of built-in regex patterns to disable (e.g. ["phone_number", "email_address"])."""

    gliner_labels: list = field(default_factory=lambda: [
        "person", "email", "phone_number", "address", "date_of_birth",
        "social_security_number", "credit_card", "password", "ip_address",
    ])
    """Entity labels GLiNER will detect. Remove labels to reduce false positives."""

    gliner_threshold: float = 0.5
    """Minimum GLiNER confidence score (0.0-1.0). Higher = fewer false positives."""

    monitored_domains: list = field(default_factory=lambda: [
        "chatgpt.com", "chat.openai.com", "api.openai.com",
        "claude.ai", "api.anthropic.com",
        "gemini.google.com", "generativelanguage.googleapis.com",
        "copilot.microsoft.com", "github.com/copilot",
        "grok.x.ai", "api.x.ai",
    ])
    """LLM domains routed through the interception proxy via PAC file."""

    allowed_domains: list = field(default_factory=list)
    """Domains explicitly excluded from interception (bypass list)."""

    policy_rules: list = field(default_factory=lambda: [
        {"category": "CREDENTIALS", "action": "block", "min_confidence": 0.8},
        {"category": "CUSTOMER_DATA", "action": "block", "min_confidence": 0.7},
        {"category": "PROPRIETARY_CODE", "action": "approve", "min_confidence": 0.6},
        {"category": "INTERNAL_COMMS", "action": "log", "min_confidence": 0.5},
        {"category": "BUSINESS_STRATEGY", "action": "block", "min_confidence": 0.9},
    ])
    """Per-category policy rules determining action when sensitive content is detected.
    
    Each entry: {"category": str, "action": "block"|"approve"|"log", "min_confidence": float}
    """

    confidence_threshold: float = 0.7
    """Global minimum confidence threshold for detection.
    
    Detections below this score are ignored. Range: 0.0-1.0.
    Lower = more aggressive (more false positives).
    Higher = more permissive (may miss borderline cases).
    """

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> AppConfig:
        """Deserialize from a dictionary, with graceful handling of missing fields."""
        stack_data = data.pop("detection_stack", {})
        if isinstance(stack_data, dict):
            stack = DetectionStackConfig(**{
                k: v for k, v in stack_data.items()
                if k in DetectionStackConfig.__dataclass_fields__
            })
        else:
            stack = DetectionStackConfig()

        valid_fields = {
            k: v for k, v in data.items()
            if k in cls.__dataclass_fields__ and k != "detection_stack"
        }

        # One-time migration: configs written by the old installer's
        # 'legacy-cpu' preset predate the `legacy_cpu` stack flag (added
        # alongside the fix that made the preset actually pull/use
        # llama3.2:1b). Those configs have llm_preset == "legacy-cpu" but
        # no `legacy_cpu` key, so it defaults False and the app silently
        # keeps trying to use the never-pulled qwen3:1.7b model instead
        # of the CPU fallback the user actually installed. Flip the flags
        # to match the preset the user is already on.
        if valid_fields.get("llm_preset") == "legacy-cpu" and not stack.legacy_cpu:
            stack.legacy_cpu = True
            stack.qwen3_1_7b = False

        return cls(detection_stack=stack, **valid_fields)
