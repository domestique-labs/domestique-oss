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
