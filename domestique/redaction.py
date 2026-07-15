"""Smart redaction engine - tokenize PII for safe LLM usage.

Instead of blocking requests entirely, this module replaces sensitive data
with reversible tokens, forwards the sanitized request, then de-tokenizes
the response so the user gets a seamless experience.

Flow:
    User: "Analyze: John Smith (SSN 123-45-6789) owes $50K"
        ↓ Firewall intercepts and tokenizes
    Sent to LLM: "Analyze: [PERSON_1] (SSN [SSN_1]) owes $50K"
        ↓ LLM responds
    LLM says: "[PERSON_1] with [SSN_1] should set up a payment plan..."
        ↓ Firewall de-tokenizes
    User sees: "John Smith with 123-45-6789 should set up a payment plan..."

Features:
- Bidirectional token mapping (request -> response)
- Session-scoped token store (cleared per conversation)
- Configurable per-category: block SSN, redact email, allow name
- Deterministic tokens for same input within a session

Thread Safety:
- TokenStore is thread-safe via internal locking
- Each proxy request gets its own redaction context
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum


class RedactionAction(Enum):
    """What to do when sensitive data is detected."""

    BLOCK = "block"  # Reject the entire request
    REDACT = "redact"  # Replace with token and forward
    ALLOW = "allow"  # Let it through (log only)
    MASK = "mask"  # Replace with asterisks (irreversible)


@dataclass
class RedactionRule:
    """A rule mapping a PII category to an action."""

    category: str
    action: RedactionAction
    token_prefix: str = ""  # e.g., "PERSON", "SSN", "EMAIL"

    def __post_init__(self) -> None:
        if not self.token_prefix:
            self.token_prefix = self.category.upper()


# Default policy: block high-risk, redact medium-risk, allow low-risk
DEFAULT_RULES = [
    RedactionRule("SSN", RedactionAction.BLOCK),
    RedactionRule("credit_card", RedactionAction.BLOCK),
    RedactionRule("private_key", RedactionAction.BLOCK),
    RedactionRule("AWS_key", RedactionAction.BLOCK),
    RedactionRule("API_key", RedactionAction.REDACT),
    RedactionRule("email", RedactionAction.REDACT, "EMAIL"),
    RedactionRule("phone", RedactionAction.REDACT, "PHONE"),
    RedactionRule("address", RedactionAction.REDACT, "ADDR"),
    RedactionRule("name", RedactionAction.ALLOW, "PERSON"),
]


@dataclass
class TokenMapping:
    """Maps a token to its original sensitive value."""

    token: str
    original: str
    category: str
    created_at: float = field(default_factory=time.time)


class TokenStore:
    """Session-scoped bidirectional token registry.

    Stores mappings between tokens and original sensitive values.
    Thread-safe for concurrent proxy requests.

    Tokens are deterministic within a session: the same input value
    always maps to the same token (enables consistent conversation).
    """

    def __init__(self, session_id: str | None = None, ttl: float = 3600.0) -> None:
        """Initialize a token store.

        Args:
            session_id: Optional session identifier for logging.
            ttl: Time-to-live in seconds for tokens (default: 1 hour).
        """
        self._session_id = session_id or "default"
        self._ttl = ttl
        self._lock = threading.Lock()
        # value -> token mapping (for tokenization)
        self._forward: dict[str, str] = {}
        # token -> TokenMapping (for de-tokenization)
        self._reverse: dict[str, TokenMapping] = {}
        # Counter per category for generating sequential tokens
        self._counters: dict[str, int] = {}

    def tokenize(self, value: str, category: str) -> str:
        """Replace a sensitive value with a deterministic token.

        If the same value was already tokenized in this session,
        returns the same token (consistency across conversation turns).

        Args:
            value: The sensitive text to replace.
            category: PII category (e.g., "SSN", "EMAIL").

        Returns:
            Token string like "[SSN_1]" or "[EMAIL_2]".
        """
        with self._lock:
            # Return existing token for same value
            if value in self._forward:
                return self._forward[value]

            # Generate new sequential token
            prefix = category.upper()
            count = self._counters.get(prefix, 0) + 1
            self._counters[prefix] = count
            token = f"[{prefix}_{count}]"

            # Store bidirectional mapping
            self._forward[value] = token
            self._reverse[token] = TokenMapping(
                token=token,
                original=value,
                category=category,
            )
            return token

    def detokenize(self, text: str) -> str:
        """Replace all tokens in text with their original values.

        Args:
            text: Text potentially containing tokens like [SSN_1].

        Returns:
            Text with tokens replaced by original sensitive values.
        """
        with self._lock:
            result = text
            for token, mapping in self._reverse.items():
                result = result.replace(token, mapping.original)
            return result

    def clear(self) -> None:
        """Clear all token mappings (end of session)."""
        with self._lock:
            self._forward.clear()
            self._reverse.clear()
            self._counters.clear()

    @property
    def size(self) -> int:
        """Number of active token mappings."""
        with self._lock:
            return len(self._reverse)

    def cleanup_expired(self) -> int:
        """Remove expired tokens. Returns count of removed tokens."""
        now = time.time()
        removed = 0
        with self._lock:
            expired_tokens = [
                token
                for token, mapping in self._reverse.items()
                if now - mapping.created_at > self._ttl
            ]
            for token in expired_tokens:
                mapping = self._reverse.pop(token)
                self._forward.pop(mapping.original, None)
                removed += 1
        return removed


class RedactionEngine:
    """Applies redaction rules to text content.

    Detects sensitive patterns, applies per-category rules (block/redact/allow),
    and manages the token store for bidirectional mapping.

    Usage:
        engine = RedactionEngine()
        result = engine.redact("My SSN is 123-45-6789 and email is a@b.com")
        # result.redacted_text = "My SSN is [SSN_1] and email is [EMAIL_1]"
        # result.action = RedactionAction.REDACT (highest severity)

        # Later, de-tokenize LLM response:
        original = engine.detokenize("[SSN_1] needs a payment plan")
        # original = "123-45-6789 needs a payment plan"
    """

    # Regex patterns for each PII category
    PATTERNS = [
        ("SSN", r"\b\d{3}-\d{2}-\d{4}\b"),
        ("credit_card", r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        ("phone", r"\b(?:\+1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        ("API_key", r"\b(?:sk-|pk_live_|sk_live_)[a-zA-Z0-9_-]{20,}\b"),
        ("AWS_key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        (
            "private_key",
            r"-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA )?PRIVATE KEY-----",
        ),
    ]

    def __init__(
        self,
        rules: list[RedactionRule] | None = None,
        token_store: TokenStore | None = None,
    ) -> None:
        self._rules = {r.category: r for r in (rules or DEFAULT_RULES)}
        self._token_store = token_store or TokenStore()
        self._compiled_patterns = [(cat, re.compile(pattern)) for cat, pattern in self.PATTERNS]

    @property
    def token_store(self) -> TokenStore:
        """Access the underlying token store."""
        return self._token_store

    def redact(self, text: str) -> RedactionResult:
        """Scan text and apply redaction rules.

        Returns a RedactionResult with the processed text and metadata.
        """
        findings: list[tuple[str, str, int, int]] = []  # (category, value, start, end)

        # Find all sensitive patterns
        for category, pattern in self._compiled_patterns:
            for match in pattern.finditer(text):
                findings.append((category, match.group(), match.start(), match.end()))

        if not findings:
            return RedactionResult(
                original_text=text,
                redacted_text=text,
                action=RedactionAction.ALLOW,
                findings=[],
                token_count=0,
            )

        # Determine highest-severity action
        overall_action = RedactionAction.ALLOW
        finding_details = []

        for category, value, start, end in findings:
            rule = self._rules.get(category)
            action = rule.action if rule else RedactionAction.REDACT

            if action == RedactionAction.BLOCK:
                overall_action = RedactionAction.BLOCK
            elif action == RedactionAction.REDACT and overall_action != RedactionAction.BLOCK:
                overall_action = RedactionAction.REDACT

            finding_details.append(
                RedactionFinding(
                    category=category,
                    value=value,
                    start=start,
                    end=end,
                    action=action,
                )
            )

        # If blocking, return immediately (no redaction needed)
        if overall_action == RedactionAction.BLOCK:
            return RedactionResult(
                original_text=text,
                redacted_text=text,
                action=RedactionAction.BLOCK,
                findings=finding_details,
                token_count=0,
            )

        # Apply redaction: replace sensitive values with tokens
        # Sort by position (reverse) to replace from end to start
        redacted = text
        token_count = 0
        for finding in sorted(finding_details, key=lambda f: f.start, reverse=True):
            if finding.action in (RedactionAction.REDACT, RedactionAction.MASK):
                if finding.action == RedactionAction.MASK:
                    replacement = "*" * len(finding.value)
                else:
                    replacement = self._token_store.tokenize(finding.value, finding.category)
                    token_count += 1
                redacted = redacted[: finding.start] + replacement + redacted[finding.end :]

        return RedactionResult(
            original_text=text,
            redacted_text=redacted,
            action=overall_action,
            findings=finding_details,
            token_count=token_count,
        )

    def detokenize(self, text: str) -> str:
        """Replace tokens in LLM response with original values."""
        return self._token_store.detokenize(text)

    def get_rule(self, category: str) -> RedactionRule | None:
        """Get the redaction rule for a category."""
        return self._rules.get(category)

    def set_rule(self, category: str, action: RedactionAction) -> None:
        """Update or add a redaction rule."""
        if category in self._rules:
            self._rules[category] = RedactionRule(
                category=category,
                action=action,
                token_prefix=self._rules[category].token_prefix,
            )
        else:
            self._rules[category] = RedactionRule(category=category, action=action)


@dataclass(frozen=True)
class RedactionFinding:
    """A single sensitive data detection within text."""

    category: str
    value: str
    start: int
    end: int
    action: RedactionAction


@dataclass(frozen=True)
class RedactionResult:
    """Result of applying redaction rules to text."""

    original_text: str
    redacted_text: str
    action: RedactionAction
    findings: list[RedactionFinding]
    token_count: int

    @property
    def was_modified(self) -> bool:
        """True if the text was changed."""
        return self.original_text != self.redacted_text

    @property
    def categories_found(self) -> list[str]:
        """Unique categories of sensitive data found."""
        return list({f.category for f in self.findings})
