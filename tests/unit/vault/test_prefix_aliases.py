"""Short semantic prefix aliases: LLM-token cost of a redaction marker
should be minimal without losing category meaning or reversibility."""

from __future__ import annotations

from domestique.vault.session import _PREFIX_ALIASES, SessionStore, category_prefix


class TestAliasTable:
    def test_verbose_detector_categories_get_short_prefixes(self) -> None:
        assert category_prefix("us_ssn") == "SSN"
        assert category_prefix("email_address") == "EMAIL"
        assert category_prefix("aws_access_key") == "AWSKEY"
        assert category_prefix("phone_number") == "PHONE"
        assert category_prefix("connection_string") == "CONNSTR"
        assert category_prefix("credit_card") == "CARD"

    def test_lookup_is_case_insensitive(self) -> None:
        assert category_prefix("US_SSN") == "SSN"
        assert category_prefix("Email_Address") == "EMAIL"

    def test_unknown_category_falls_back_to_uppercase(self) -> None:
        assert category_prefix("codename") == "CODENAME"
        assert category_prefix("API_key") == "API_KEY"

    def test_aliases_are_unique_no_collisions(self) -> None:
        values = list(_PREFIX_ALIASES.values())
        assert len(values) == len(set(values))

    def test_aliases_fit_token_grammar(self) -> None:
        for alias in _PREFIX_ALIASES.values():
            assert alias.isupper() or alias.isdigit() or "_" in alias or alias.isalnum()
            assert len(alias) <= 9  # keeps [ALIAS_nnn] within 14 chars


class TestMintingWithAliases:
    def test_detector_category_mints_short_token(self) -> None:
        store = SessionStore()
        assert store.tokenize("123-45-6789", "us_ssn") == "[SSN_1]"
        assert store.tokenize("a@b.com", "email_address") == "[EMAIL_1]"

    def test_alias_and_fallback_share_counter_when_same_prefix(self) -> None:
        store = SessionStore()
        assert store.tokenize("123-45-6789", "us_ssn") == "[SSN_1]"
        # legacy SDK category "SSN" resolves to the same prefix -> same counter
        assert store.tokenize("987-65-4321", "SSN") == "[SSN_2]"
