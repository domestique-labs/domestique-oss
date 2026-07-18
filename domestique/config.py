"""Domestique - Configuration.

All settings are driven by environment variables prefixed with ``DOMESTIQUE_``.
Defaults are safe for development; override for production.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Immutable, validated application configuration."""

    # --- Server ---
    host: str = "0.0.0.0"  # noqa: S104  # bind-all is intentional for the proxy listener
    port: int = 8000
    workers: int = 4
    debug: bool = False

    # --- Upstream LLM keys (held centrally; never on client machines) ---
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    azure_api_key: str = ""
    azure_api_base: str = ""

    # --- Detection ---
    enable_pii_detection: bool = False
    enable_gliner: bool = False
    gliner_labels: list[str] = Field(
        default_factory=lambda: [
            "person",
            "email",
            "phone_number",
            "address",
            "date_of_birth",
            "social_security_number",
            "credit_card",
            "password",
            "ip_address",
        ],
        description="Entity labels GLiNER will detect. Remove labels to reduce false positives.",
    )
    gliner_threshold: float = Field(
        default=0.5,
        description="Minimum GLiNER confidence score (0.0-1.0). Higher = fewer false positives.",
    )
    enable_secret_detection: bool = True
    enable_semantic_detection: bool = False
    enable_local_llm: bool = False
    pii_confidence_threshold: float = 0.7
    spacy_model: str = "en_core_web_lg"
    disabled_builtin_patterns: list[str] = Field(
        default_factory=list,
        description=(
            "Names of built-in regex patterns to disable (e.g. phone_number, email_address)"
        ),
    )

    # --- Semantic / ML detection ---
    sensitive_topics: list[str] = Field(
        default_factory=lambda: [
            "merger and acquisition plans",
            "unreleased financial results",
            "proprietary source code and algorithms",
            "customer personal data and contracts",
            "internal security vulnerabilities",
            "employee compensation and HR records",
        ],
        description="Topics the semantic detector flags via embedding similarity.",
    )
    semantic_similarity_threshold: float = 0.75

    # --- Local LLM (second-pass classifier) ---
    local_llm_backend: str = "ollama"
    local_llm_model: str = "gemma4:e2b"
    local_llm_url: str = "http://localhost:11434"
    local_llm_timeout_s: float = 30.0
    local_llm_preset: str = Field(
        default="balanced",
        description=(
            "Hardware preset: "
            "'minimal' = qwen3:1.7b (CPU, 1.5GB RAM); "
            "'balanced' = gemma4:e2b (GPU recommended, 3.1GB RAM); "
            "'quality' = gemma4:e4b (GPU required, 5.5GB RAM); "
            "'legacy-cpu' = llama3.2:1b (CPU fallback, 2GB RAM)"
        ),
    )
    local_llm_system_prompt: str = Field(
        default="",
        description=(
            "Custom system prompt for the LLM classifier. "
            "Leave empty to use the built-in default. Must instruct the model to "
            'respond with JSON: {"category": "<CAT>", "confidence": <0-1>, '
            '"reason": "<text>"}'
        ),
    )

    # --- Policy ---
    policy_path: str = Field(
        default="domestique/policy/browser-rules.yaml",
        description="Path to the YAML policy file.",
    )

    # --- Resilience ---
    fail_mode: str = Field(
        default="closed",
        description="'closed' blocks on error; 'open' allows through.",
    )
    upstream_timeout_s: int = 120

    # --- Audit ---
    audit_log_path: str = "logs/audit.jsonl"

    # --- Domains intercepted (used by infra tooling, not at runtime) ---
    intercepted_domains: list[str] = Field(
        default_factory=lambda: [
            "api.openai.com",
            "api.anthropic.com",
            "generativelanguage.googleapis.com",
            "api.cohere.ai",
            "api.mistral.ai",
            "api.together.xyz",
        ]
    )

    model_config = {"env_prefix": "DOMESTIQUE_", "env_file": ".env"}
