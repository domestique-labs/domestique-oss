"""PinnedVault: encrypted persistence for common values (M3-persistent, M10)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from domestique.vault.pinned import PinnedVault


class FakeKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key if key is not None else os.urandom(32)

    def get_or_create_key(self) -> bytes | None:
        return self.key


class BrokenKeyProvider:
    def get_or_create_key(self) -> bytes | None:
        return None


def _vault(tmp_path: Path, provider: object | None = None) -> PinnedVault:
    v = PinnedVault(tmp_path / "vault.bin", provider or FakeKeyProvider())
    v.load()
    return v


class TestPersistence:
    def test_pin_survives_reload_with_same_token(self, tmp_path: Path) -> None:
        provider = FakeKeyProvider()
        v1 = _vault(tmp_path, provider)
        token = v1.pin("123-45-6789", "SSN")
        assert token == "[SSN_1]"

        v2 = _vault(tmp_path, provider)  # simulates restart
        assert v2.lookup_value("123-45-6789") == "[SSN_1]"
        assert v2.lookup_token("[SSN_1]") == "123-45-6789"

    def test_pin_same_value_twice_is_stable(self, tmp_path: Path) -> None:
        v = _vault(tmp_path)
        assert v.pin("a@b.com", "email") == v.pin("a@b.com", "email") == "[EMAIL_1]"

    def test_values_snapshot(self, tmp_path: Path) -> None:
        v = _vault(tmp_path)
        v.pin("123-45-6789", "SSN")
        assert v.values() == {"123-45-6789": ("[SSN_1]", "SSN")}

    def test_max_index_per_category(self, tmp_path: Path) -> None:
        v = _vault(tmp_path)
        v.pin("123-45-6789", "SSN")
        v.pin("987-65-4321", "SSN")
        v.pin("a@b.com", "email")
        assert v.max_index("SSN") == 2
        assert v.max_index("EMAIL") == 1
        assert v.max_index("PHONE") == 0


class TestEncryptionAtRest:
    def test_vault_file_never_contains_plaintext(self, tmp_path: Path) -> None:
        v = _vault(tmp_path)
        secret = "123-45-6789"
        v.pin(secret, "SSN")
        raw = (tmp_path / "vault.bin").read_bytes()
        assert secret.encode() not in raw
        assert b"SSN_1" not in raw

    def test_file_is_versioned_envelope(self, tmp_path: Path) -> None:
        v = _vault(tmp_path)
        v.pin("123-45-6789", "SSN")
        envelope = json.loads((tmp_path / "vault.bin").read_text())
        assert envelope["v"] == 1
        assert set(envelope) == {"v", "nonce", "ct"}


class TestFailSafe:
    def test_no_key_means_unavailable_and_noop(self, tmp_path: Path) -> None:
        v = _vault(tmp_path, BrokenKeyProvider())
        assert v.available is False
        assert v.pin("123-45-6789", "SSN") == ""
        assert v.lookup_value("123-45-6789") is None
        assert not (tmp_path / "vault.bin").exists()

    def test_corrupt_file_disables_without_raising(self, tmp_path: Path) -> None:
        (tmp_path / "vault.bin").write_text("not json at all")
        v = _vault(tmp_path)
        assert v.available is False
        assert v.pin("x", "SSN") == ""

    def test_wrong_key_disables_without_raising(self, tmp_path: Path) -> None:
        v1 = _vault(tmp_path, FakeKeyProvider())
        v1.pin("123-45-6789", "SSN")
        v2 = _vault(tmp_path, FakeKeyProvider())  # different random key
        assert v2.available is False

    def test_missing_file_starts_empty_and_available(self, tmp_path: Path) -> None:
        v = _vault(tmp_path)
        assert v.available is True
        assert v.values() == {}
