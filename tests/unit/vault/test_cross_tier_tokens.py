"""Cross-tier integration: one taxonomy mints the same token from any detector.

Proves the point of the whole taxonomy-unification effort — a Presidio
``person`` hit and a GLiNER ``pii:person`` hit for the identical value
collapse to the identical token, and an LLM-coined category (never seen in
``CANONICAL``) still mints a valid, reversible token.
"""

from __future__ import annotations

from domestique.vault.service import TokenService
from domestique.vault.session import SessionStore


def test_same_entity_same_token_across_tiers() -> None:
    """A person flagged as Presidio `person` and GLiNER `pii:person`
    (normalized) mints the identical token."""
    svc = TokenService(SessionStore(), None)
    t_presidio = svc.tokenize("Jane Doe", "person")
    t_gliner = svc.tokenize("Jane Doe", "pii:person")  # normalizes to person
    assert t_presidio == t_gliner == "[PERSON_1]"


def test_distinct_values_across_tier_spellings_share_prefix() -> None:
    """Distinct values under the two tiers' spellings for the same concept
    normalize to the same category and thus share a token prefix, proving
    normalization runs (not just value-caching)."""
    svc = TokenService(SessionStore(), None)
    t1 = svc.tokenize("Alice Smith", "person")  # Presidio spelling
    t2 = svc.tokenize("Bob Jones", "pii:person")  # GLiNER spelling
    assert t1 == "[PERSON_1]" and t2 == "[PERSON_2]"


def test_coined_llm_term_mints_and_reverses() -> None:
    """A category the LLM tier coins on the fly (not in the canonical
    vocabulary) still derives a deterministic, grammar-valid prefix and
    round-trips through detokenize_text."""
    svc = TokenService(SessionStore(), None)
    token = svc.tokenize("EMP-4471", "employee_badge")
    assert token.startswith("[EMPLOYEE_BADGE_")
    restored, unknown = svc.detokenize_text(f"your id is {token}", allowed={token})
    assert restored == "your id is EMP-4471"
    assert not unknown
