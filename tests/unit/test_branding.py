"""Tests for domestique.branding — the shared console logo + unicode probe."""

from __future__ import annotations

import io
import sys
from typing import TYPE_CHECKING

from domestique import branding, cli

if TYPE_CHECKING:
    import pytest


class _FakeStream(io.StringIO):
    def __init__(self, encoding: str) -> None:
        super().__init__()
        self._encoding = encoding

    @property
    def encoding(self) -> str:  # type: ignore[override]
        return self._encoding


def test_logo_is_pure_ascii() -> None:
    # The logo must render on any console, including cp1252 Windows ones.
    assert branding.LOGO.encode("ascii")
    assert "domestique" not in branding.LOGO  # it's figlet art, not plain text
    assert branding.LOGO.startswith("\n")


def test_supports_unicode_false_on_cp1252(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", _FakeStream("cp1252"))
    assert branding.supports_unicode() is False


def test_supports_unicode_true_on_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", _FakeStream("utf-8"))
    assert branding.supports_unicode() is True


def test_supports_unicode_false_on_missing_or_bogus_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "stdout", _FakeStream(""))
    assert branding.supports_unicode() is False
    monkeypatch.setattr(sys, "stdout", _FakeStream("not-a-real-codec"))
    assert branding.supports_unicode() is False


def test_cli_aliases_still_point_at_branding() -> None:
    # domestique.cli re-exports the moved names; tests/callers rely on them.
    assert cli._LOGO == branding.LOGO
    assert cli._supports_unicode is branding.supports_unicode
