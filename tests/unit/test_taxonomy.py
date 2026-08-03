from domestique.taxonomy import (
    CANONICAL,
    GENERIC_CATEGORY,
    GENERIC_PREFIX,
    is_value_like,
    normalize_category,
    prefix_for,
)


def test_canonical_categories_have_compact_prefixes():
    assert CANONICAL["email_address"] == "EMAIL"
    assert CANONICAL["us_ssn"] == "SSN"
    assert CANONICAL["person"] == "PERSON"
    assert CANONICAL["aws_access_key"] == "AWSKEY"  # compact, not AWS_KEY


def test_normalize_strips_source_prefixes_and_aliases():
    assert normalize_category("pii:person") == "person"
    assert normalize_category("pii:email") == "email_address"
    assert normalize_category("pii:social_security_number") == "us_ssn"
    assert normalize_category("social_security_number") == "us_ssn"
    assert normalize_category("EMAIL_ADDRESS") == "email_address"
    assert normalize_category("llm_classified:credentials") == "credentials"


def test_normalize_coins_snake_case_for_unknown():
    assert normalize_category("Employee ID") == "employee_id"
    assert normalize_category("internal project codename!!") == "internal_project_codename"


def test_prefix_for_canonical_and_derived():
    assert prefix_for("email_address") == "EMAIL"
    assert prefix_for("person") == "PERSON"
    # unknown coined term with no store → derived, token-grammar-safe
    assert prefix_for("employee_id") == "EMPLOYEE_ID"


def test_prefix_for_never_exceeds_bound():
    from domestique.taxonomy import MAX_PREFIX_LEN
    long = "a_very_long_made_up_category_" * 3
    assert len(prefix_for(long)) <= MAX_PREFIX_LEN


def test_normalize_aliases_apply_after_snakecasing():
    assert normalize_category("social security number") == "us_ssn"
    assert normalize_category("Credit Card Number") == "credit_card"
    assert normalize_category("e mail") == "email_address"


class TestIsValueLike:
    """A model-coined category that echoes the scanned text is a leaked value.

    A legitimate coined category is a *label* (``employee_id``); a leaked value
    is *content*, so it appears in the text being scanned. That containment
    check is the discriminator between the two.
    """

    def test_term_lifted_verbatim_from_the_text(self):
        text = "the deploy password is correcthorse, do not share it"
        assert is_value_like("correcthorse", text)

    def test_case_insensitive_both_directions(self):
        assert is_value_like("correcthorse", "PASSWORD IS CORRECTHORSE OK")
        assert is_value_like(normalize_category("CorrectHorse"), "password is correcthorse ok")

    def test_underscore_free_form_of_the_term(self):
        # normalize_category snake-cases, so a value the model echoed can reach
        # us with separators the raw text does not have.
        assert is_value_like("correct_horse", "the password is correcthorse ok")

    def test_punctuation_in_the_value_survives_snake_casing(self):
        secret = "Tr0ub4dor&3xKlm9zQvBn7Yt2"
        term = normalize_category(secret)
        assert term != secret.lower()  # normalization mangled the punctuation
        assert is_value_like(term, f"login with {secret} today")

    def test_genuine_label_absent_from_the_text_is_not_value_like(self):
        assert not is_value_like("employee_id", "my badge is EMP-4471 for the door")

    def test_empty_inputs_are_never_value_like(self):
        assert not is_value_like("", "any text at all here")
        assert not is_value_like("employee_id", "")


def test_generic_prefix_is_what_the_generic_category_mints():
    # The rejection path returns GENERIC_PREFIX while the Detection carries
    # GENERIC_CATEGORY; if these two drifted apart the token would not match.
    assert prefix_for(GENERIC_CATEGORY) == GENERIC_PREFIX
