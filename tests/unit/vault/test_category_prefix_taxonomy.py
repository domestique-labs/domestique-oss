from domestique.vault.session import category_prefix


def test_existing_categories_keep_their_prefixes():
    assert category_prefix("email_address") == "EMAIL"
    assert category_prefix("us_ssn") == "SSN"
    assert category_prefix("aws_access_key") == "AWSKEY"


def test_gliner_and_llm_prefixes_normalize():
    assert category_prefix("pii:person") == "PERSON"      # was PII_PERSON
    assert category_prefix("pii:email") == "EMAIL"
    assert category_prefix("person") == "PERSON"          # same token as GLiNER now
