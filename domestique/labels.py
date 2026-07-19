"""Human-friendly labels for detection categories.

Shared by the CLI demo/ticker (`cli.py`) and the `report` command (`report.py`)
so the same category always renders with the same name.
"""

from __future__ import annotations

CATEGORY_LABELS = {
    "aws_access_key": "AWS access key",
    "aws_secret_key": "AWS secret key",
    "email_address": "Email address",
    "us_ssn": "US SSN",
    "phone_number": "Phone number",
    "credit_card": "Credit card",
    "github_token": "GitHub token",
    "jwt": "JWT token",
    "private_key": "Private key",
    "connection_string": "Connection string",
}


def label(category: str) -> str:
    """Return a friendly display name for a detection *category*."""
    return CATEGORY_LABELS.get(category, category.replace("_", " ").capitalize())
