"""The keyring must never be reached when it cannot answer non-interactively.

On macOS `keyring.set_password` hits the Security framework, which looks for
`$HOME/Library/Keychains/login.keychain-db`. With no login keychain it fails
with `A keychain cannot be found to store "vault-key"` and presents a *blocking
system dialog* — the process waits for a human, so try/except cannot save it.
That is the real cause of the pytest hang in #74.
"""

from __future__ import annotations

import sys

import pytest

from domestique.vault.pinned import (
    DISABLE_KEYRING_ENV,
    KeyringKeyProvider,
    _keyring_reachable,
)


def test_opt_out_env_disables_the_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DISABLE_KEYRING_ENV, "1")
    assert _keyring_reachable() is False


@pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
def test_opt_out_env_only_fires_on_truthy(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(DISABLE_KEYRING_ENV, value)
    monkeypatch.setattr(sys, "platform", "linux")  # skip the darwin probe
    assert _keyring_reachable() is True


@pytest.mark.skipif(sys.platform != "darwin", reason="probes the macOS Keychain layout")
def test_macos_home_without_a_login_keychain_is_unreachable(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(DISABLE_KEYRING_ENV, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    assert _keyring_reachable() is False


@pytest.mark.skipif(sys.platform != "darwin", reason="probes the macOS Keychain layout")
def test_macos_home_with_a_keychain_is_reachable(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(DISABLE_KEYRING_ENV, raising=False)
    keychains = tmp_path / "Library" / "Keychains"
    keychains.mkdir(parents=True)
    (keychains / "login.keychain-db").write_bytes(b"")
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    assert _keyring_reachable() is True


def test_provider_never_imports_keyring_when_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    """The guard must short-circuit *before* keyring is touched.

    Catching the error is not enough: the macOS dialog blocks before any
    exception exists, so the only safe behaviour is not to call it at all.
    """
    monkeypatch.setenv(DISABLE_KEYRING_ENV, "1")

    import builtins

    real_import = builtins.__import__

    def _guard(name: str, *args: object, **kwargs: object) -> object:
        if name == "keyring":
            raise AssertionError("keyring was imported despite being unreachable")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", _guard)
    assert KeyringKeyProvider().get_or_create_key() is None
