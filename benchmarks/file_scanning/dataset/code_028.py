"""Utility functions for string manipulation."""


def slugify(text: str) -> str:
    """Convert text to URL-friendly slug."""
    return text.lower().replace(" ", "-").strip("-")


def truncate(text: str, max_length: int = 100) -> str:
    """Truncate text with ellipsis."""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def word_count(text: str) -> int:
    """Count words in text."""
    return len(text.split())
