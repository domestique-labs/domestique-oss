from domestique.taxonomy import CANONICAL, normalize_category, prefix_for


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
