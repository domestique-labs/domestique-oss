"""Real-backend validation of the pinned vault's keyring fail-safe on Windows.

``test_pinned_vault.py`` proves the ``PinnedVault`` *contract* (via
``FakeKeyProvider``/``BrokenKeyProvider`` stand-ins for the ``KeyProvider``
protocol), but nothing exercises ``KeyringKeyProvider`` itself against a real
OS credential store — the one place a Windows-specific surprise could hide
(DPAPI/Credential Manager availability, exception shapes on failure). This
module closes that gap on real Windows hardware:

1. the real backend genuinely persists a key across process-like restarts
   (a fresh ``KeyringKeyProvider``/``PinnedVault`` instance, same credential),
2. a real backend failure is caught broadly and degrades to ``available =
   False`` without raising,
3. degradation never weakens *session* redaction — only cross-restart
   stability of pinned values is lost (the module docstring's core promise),
   verified one layer up through ``TokenService``, not just ``PinnedVault``.

All tests use a throwaway keyring service/user (never the real
``domestique-vault``/``vault-key`` entry) and delete it in teardown.
"""

from __future__ import annotations

import contextlib
import sys
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="validates the real Windows Credential Manager (DPAPI) keyring backend",
)

keyring = pytest.importorskip("keyring")

from domestique.vault import pinned as pinned_module  # noqa: E402
from domestique.vault.pinned import KeyringKeyProvider, PinnedVault  # noqa: E402
from domestique.vault.service import TokenService  # noqa: E402
from domestique.vault.session import SessionStore  # noqa: E402


@pytest.fixture()
def throwaway_keyring_entry(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Point KeyringKeyProvider at a disposable service/user for this test only.

    Never touches the real domestique-vault/vault-key entry a real install
    would use, and removes whatever it wrote when the test ends -- even if
    the test fails or the backend is in a weird state.
    """
    service = f"domestique-vault-TEST-{uuid.uuid4().hex[:8]}"
    user = "vault-key"
    monkeypatch.setattr(pinned_module, "_KEYRING_SERVICE", service)
    monkeypatch.setattr(pinned_module, "_KEYRING_USER", user)
    try:
        yield
    finally:
        with contextlib.suppress(Exception):
            keyring.delete_password(service, user)


class TestRealWindowsBackend:
    def test_windows_credential_manager_backend_is_selected(self) -> None:
        """Sanity check the environment: if some other backend (e.g. a null
        backend under a locked-down CI runner) is active, every other test in
        this module would be validating the wrong thing -- fail loudly rather
        than silently passing against a backend nobody ships against."""
        backend = keyring.get_keyring()
        assert type(backend).__module__.startswith("keyring.backends.Windows"), (
            f"expected the real Windows Credential Manager backend, got {backend!r} -- "
            "this environment can't validate the DPAPI-backed path"
        )

    def test_real_roundtrip_persists_across_instances(
        self, throwaway_keyring_entry: None
    ) -> None:
        first = KeyringKeyProvider().get_or_create_key()
        assert first is not None
        assert len(first) == 32

        second = KeyringKeyProvider().get_or_create_key()  # fresh instance = "restart"
        assert second == first, "key must survive across process-like restarts via DPAPI"

    def test_full_pinned_vault_roundtrip_with_real_backend(
        self, tmp_path: Path, throwaway_keyring_entry: None
    ) -> None:
        path = tmp_path / "vault.bin"

        v1 = PinnedVault(path, KeyringKeyProvider())
        v1.load()
        assert v1.available is True
        token = v1.pin("123-45-6789", "SSN")
        assert token == "[SSN_1]"

        v2 = PinnedVault(path, KeyringKeyProvider())  # simulates a real restart
        v2.load()
        assert v2.available is True
        assert v2.lookup_value("123-45-6789") == "[SSN_1]"
        assert v2.lookup_token("[SSN_1]") == "123-45-6789"


class TestRealBackendFailureDegradesGracefully:
    def test_get_password_failure_returns_none_not_raise(
        self, monkeypatch: pytest.MonkeyPatch, throwaway_keyring_entry: None
    ) -> None:
        def _boom(*_a: object, **_k: object) -> None:
            raise OSError("simulated Credential Manager access failure")

        monkeypatch.setattr(keyring, "get_password", _boom)
        assert KeyringKeyProvider().get_or_create_key() is None

    def test_set_password_failure_returns_none_not_raise(
        self, monkeypatch: pytest.MonkeyPatch, throwaway_keyring_entry: None
    ) -> None:
        monkeypatch.setattr(keyring, "get_password", lambda *a, **k: None)

        def _boom(*_a: object, **_k: object) -> None:
            raise OSError("simulated Credential Manager write failure")

        monkeypatch.setattr(keyring, "set_password", _boom)
        assert KeyringKeyProvider().get_or_create_key() is None

    def test_vault_degrades_when_real_provider_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, throwaway_keyring_entry: None
    ) -> None:
        def _boom(*_a: object, **_k: object) -> None:
            raise OSError("simulated Credential Manager failure")

        monkeypatch.setattr(keyring, "get_password", _boom)

        v = PinnedVault(tmp_path / "vault.bin", KeyringKeyProvider())
        v.load()

        assert v.available is False
        assert v.pin("123-45-6789", "SSN") == ""
        assert v.lookup_value("123-45-6789") is None
        assert v.lookup_token("[SSN_1]") is None
        assert v.values() == {}
        assert v.max_index("SSN") == 0
        assert not (tmp_path / "vault.bin").exists()


class TestSessionRedactionSurvivesPinnedVaultDegradation:
    """The module docstring's central promise: the pinned vault degrading
    NEVER weakens redaction -- session tokens still cover everything. Proven
    one layer up through TokenService, with a real (deliberately failing)
    KeyringKeyProvider rather than a fake, so a Windows-specific quirk in the
    real provider can't silently break this guarantee."""

    def test_tokenize_and_detokenize_work_with_unavailable_pinned_vault(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, throwaway_keyring_entry: None
    ) -> None:
        def _boom(*_a: object, **_k: object) -> None:
            raise OSError("simulated Credential Manager failure")

        monkeypatch.setattr(keyring, "get_password", _boom)

        pinned = PinnedVault(tmp_path / "vault.bin", KeyringKeyProvider())
        pinned.load()
        assert pinned.available is False  # sanity: degradation actually engaged

        service = TokenService(SessionStore(), pinned=pinned)

        token = service.tokenize("123-45-6789", "SSN")
        assert token == "[SSN_1]"  # session minting unaffected by a dead pinned vault

        text, unknown = service.detokenize_text(f"ssn is {token}")
        assert text == "ssn is 123-45-6789"
        assert unknown == []

    def test_pin_is_a_safe_noop_when_pinned_vault_unavailable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, throwaway_keyring_entry: None
    ) -> None:
        def _boom(*_a: object, **_k: object) -> None:
            raise OSError("simulated Credential Manager failure")

        monkeypatch.setattr(keyring, "get_password", _boom)

        pinned = PinnedVault(tmp_path / "vault.bin", KeyringKeyProvider())
        pinned.load()

        service = TokenService(SessionStore(), pinned=pinned)
        assert service.pin("123-45-6789", "SSN") == ""  # no crash, just no persistence

        # the value is still fully redactable this session -- just not pinned
        token = service.tokenize("123-45-6789", "SSN")
        assert token == "[SSN_1]"
