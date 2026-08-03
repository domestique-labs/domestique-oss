"""Canonical detection taxonomy: one vocabulary + prefix mapping for every tier.

Every detector normalizes its raw category here (``pii:person`` → ``person``)
so the same entity always mints the same reversible token regardless of which
tier caught it. The LLM tier may coin new terms; those persist via TaxonomyStore
(see task 2). Stdlib-only — never import vault/detectors (avoids import cycles).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Protocol

    class TaxonomyStore(Protocol):
        """Interface for taxonomy store (see task 2)."""

        def prefix_of(self, category: str) -> str | None:
            """Return learned prefix for category, or None if not found."""
            ...


#: Longest prefix that fits ``[PREFIX_index]`` within MAX_TOKEN_LEN (32):
#: 32 - len("[") - len("_") - len("]") - 6 reserved index digits.
MAX_PREFIX_LEN = 23

#: Canonical category -> compact token prefix. Compact on purpose: the marker
#: rides every conversation turn, so BPE cost matters (M11 metric). Prefixes
#: MUST be unique (a collision merges two categories' token counters).
CANONICAL: dict[str, str] = {
    # Tier 1 secrets
    "us_ssn": "SSN",
    "email_address": "EMAIL",
    "phone_number": "PHONE",
    "credit_card": "CARD",
    "aws_access_key": "AWSKEY",
    "aws_secret_key": "AWSSECRET",
    "private_key": "PRIVKEY",
    "connection_string": "CONNSTR",
    "github_token": "GHTOKEN",
    "github_fine_grained": "GHPAT",
    "anthropic_key": "ANTKEY",
    "openai_key": "OAIKEY",
    "slack_token": "SLACKKEY",
    "jwt": "JWT",
    "generic_api_key": "APIKEY",
    "password_literal": "PASSWORD",
    # Tier 2 PII (Presidio + GLiNER, canonicalized)
    "person": "PERSON",
    "address": "ADDR",
    "ip_address": "IP",
    "iban_code": "IBAN",
    "us_passport": "PASSPORT",
    "us_driver_license": "DL",
    "medical_license": "MEDLIC",
    "date_of_birth": "DOB",
}

#: Raw (already prefix-stripped, lowercased) variant -> canonical category.
_ALIASES: dict[str, str] = {
    "email": "email_address",
    "e_mail": "email_address",
    "ssn": "us_ssn",
    "social_security_number": "us_ssn",
    "phone": "phone_number",
    "phone_no": "phone_number",
    "password": "password_literal",
    "credit_card_number": "credit_card",
    "ip": "ip_address",
    "dob": "date_of_birth",
}

#: Source-tier prefixes stripped before alias lookup.
_SOURCE_PREFIXES = ("pii:", "llm_classified:")

_NON_TOKEN_CHARS = re.compile(r"[^A-Z0-9_]+")
_NON_SNAKE_CHARS = re.compile(r"[^a-z0-9]+")

#: Category used when a model-coined category is rejected as a leaked value.
GENERIC_CATEGORY = "sensitive"
#: Token prefix that category mints. Kept literal (rather than derived) because
#: it is part of the interface callers compare against; a test pins the two
#: together so they cannot drift.
GENERIC_PREFIX = "SENSITIVE"


def is_value_like(term: str, text: str) -> bool:
    """True when a model-coined category looks like content lifted from *text*.

    A legitimate coined category is a *label* (``employee_id``, ``badge_number``)
    and does not appear in the text being scanned; a leaked value *is* that text.
    So case-insensitive containment is the discriminator, and it is cheap.

    Comparison also runs with every non-alphanumeric character stripped from
    both sides, because ``normalize_category`` snake-cases the raw category
    (``Tr0ub4dor&3x`` -> ``tr0ub4dor_3x``): without that pass, any value
    containing punctuation would slip through. This subsumes the underscore-free
    form of the term.

    Erring towards True is the safe direction: a false positive only costs the
    coined label (the span is still redacted, under the generic prefix).
    """
    if not term or not text:
        return False
    lowered_term = term.lower()
    lowered_text = text.lower()
    if lowered_term in lowered_text:
        return True
    squashed_term = _NON_SNAKE_CHARS.sub("", lowered_term)
    if not squashed_term:
        return False
    return squashed_term in _NON_SNAKE_CHARS.sub("", lowered_text)


def normalize_category(raw: str) -> str:
    """Any tier's category spelling -> canonical name, or a snake_case coined term."""
    c = raw.strip().lower()
    for pfx in _SOURCE_PREFIXES:
        if c.startswith(pfx):
            c = c[len(pfx) :]
            break
    c = _ALIASES.get(c, c)
    if c in CANONICAL:
        return c
    c = _NON_SNAKE_CHARS.sub("_", c).strip("_")
    if not c:
        return "sensitive"
    return _ALIASES.get(c, c)


def _derive_prefix(category: str) -> str:
    """Sanitize an arbitrary category to a token-grammar-safe, bounded prefix."""
    prefix = _NON_TOKEN_CHARS.sub("_", category.upper()).strip("_")
    prefix = prefix[:MAX_PREFIX_LEN].rstrip("_")
    return prefix or "REDACTED"


def prefix_for(category: str, store: TaxonomyStore | None = None) -> str:
    """Token prefix for a category: canonical, else store-learned, else derived."""
    canonical = CANONICAL.get(category)
    if canonical is not None:
        return canonical
    if store is None:
        from domestique.taxonomy_store import default_store

        store = default_store()
    learned = store.prefix_of(category)
    if learned is not None:
        return learned
    return _derive_prefix(category)
