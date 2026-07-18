"""TokenService: pinned-first minting, strict detokenization, pin suggestions."""

from __future__ import annotations

import os
from pathlib import Path

from domestique.vault.pinned import PinnedVault
from domestique.vault.service import TokenService
from domestique.vault.session import SessionStore


class FakeKeyProvider:
    def __init__(self) -> None:
        self._key = os.urandom(32)

    def get_or_create_key(self) -> bytes | None:
        return self._key


def _service(tmp_path: Path, *, pinned: bool = True) -> TokenService:
    vault = None
    if pinned:
        vault = PinnedVault(tmp_path / "vault.bin", FakeKeyProvider())
        vault.load()
    return TokenService(SessionStore(), vault)


class TestMinting:
    def test_pinned_value_gets_pinned_token(self, tmp_path: Path) -> None:
        svc = _service(tmp_path)
        assert svc.pinned is not None
        svc.pinned.pin("123-45-6789", "SSN")
        svc.sync_counter_floors()
        assert svc.tokenize("123-45-6789", "SSN") == "[SSN_1]"

    def test_session_counter_starts_above_pinned_max(self, tmp_path: Path) -> None:
        svc = _service(tmp_path)
        assert svc.pinned is not None
        svc.pinned.pin("123-45-6789", "SSN")
        svc.sync_counter_floors()
        # a *different* SSN must not collide with the pinned [SSN_1]
        assert svc.tokenize("987-65-4321", "SSN") == "[SSN_2]"

    def test_no_pinned_vault_still_works(self, tmp_path: Path) -> None:
        svc = _service(tmp_path, pinned=False)
        assert svc.tokenize("123-45-6789", "SSN") == "[SSN_1]"


class TestDetokenize:
    def test_restores_mixed_pinned_and_session(self, tmp_path: Path) -> None:
        svc = _service(tmp_path)
        assert svc.pinned is not None
        svc.pinned.pin("a@b.com", "email")
        svc.sync_counter_floors()
        t_pin = svc.tokenize("a@b.com", "email")
        t_sess = svc.tokenize("123-45-6789", "SSN")
        text = f"Contact {t_pin} about {t_sess} today"
        out, unknown = svc.detokenize_text(text)
        assert out == "Contact a@b.com about 123-45-6789 today"
        assert unknown == []

    def test_unknown_token_left_in_place_and_reported(self, tmp_path: Path) -> None:
        svc = _service(tmp_path, pinned=False)
        svc.tokenize("123-45-6789", "SSN")
        out, unknown = svc.detokenize_text("[SSN_1] but also [SSN_9] and [MADEUP_3]")
        assert out == "123-45-6789 but also [SSN_9] and [MADEUP_3]"
        assert unknown == ["[SSN_9]", "[MADEUP_3]"]

    def test_no_tokens_is_identity(self, tmp_path: Path) -> None:
        svc = _service(tmp_path, pinned=False)
        out, unknown = svc.detokenize_text("plain text [not a token] [lower_1]")
        assert out == "plain text [not a token] [lower_1]"
        assert unknown == []

    def test_adjacent_tokens(self, tmp_path: Path) -> None:
        svc = _service(tmp_path, pinned=False)
        a = svc.tokenize("123-45-6789", "SSN")
        b = svc.tokenize("987-65-4321", "SSN")
        out, _ = svc.detokenize_text(f"{a}{b}")
        assert out == "123-45-6789987-65-4321"


class TestSightings:
    def test_third_sighting_triggers_suggestion(self, tmp_path: Path) -> None:
        svc = _service(tmp_path)
        assert svc.record_sighting("a@b.com", "email") is False
        assert svc.record_sighting("a@b.com", "email") is False
        assert svc.record_sighting("a@b.com", "email") is True
        assert ("a@b.com", "email") in svc.suggestions()

    def test_already_pinned_value_never_suggested(self, tmp_path: Path) -> None:
        svc = _service(tmp_path)
        assert svc.pinned is not None
        svc.pinned.pin("a@b.com", "email")
        for _ in range(5):
            assert svc.record_sighting("a@b.com", "email") is False
        assert svc.suggestions() == []
