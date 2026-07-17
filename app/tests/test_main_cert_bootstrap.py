"""Tests for app.main's portable first-run CA generate+trust bootstrap (C7).

``_ensure_cert_generated_portable()`` mirrors macOS's
``AppDelegate._ensure_cert_trusted()``: generate the CA if missing, then
trust it if not already trusted. These tests cover the trust half (the
generation half was already exercised as part of the C1 fix) plus the
Linux honesty behavior called out in the audit: ``is_cert_trusted()``
hardcodes ``True`` on Linux without checking anything real, so this
function must not let that false positive read as "trust verified."
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from app import main


def _fake_browser_proxy_service(*, is_setup: bool) -> MagicMock:
    svc = MagicMock()
    svc.is_setup = is_setup
    return svc


class TestEnsureCertGeneratedPortable:
    def test_generates_ca_when_not_setup(self):
        svc = _fake_browser_proxy_service(is_setup=False)
        with (
            patch("app.server.api.get_browser_proxy_service", return_value=svc),
            patch("app.services.cert_manager.is_cert_trusted", return_value=True),
        ):
            main._ensure_cert_generated_portable()
        svc.setup.assert_called_once()

    def test_skips_generation_when_already_setup(self):
        svc = _fake_browser_proxy_service(is_setup=True)
        with (
            patch("app.server.api.get_browser_proxy_service", return_value=svc),
            patch("app.services.cert_manager.is_cert_trusted", return_value=True),
        ):
            main._ensure_cert_generated_portable()
        svc.setup.assert_not_called()

    def test_trusts_ca_when_not_yet_trusted(self):
        svc = _fake_browser_proxy_service(is_setup=True)
        with (
            patch("app.server.api.get_browser_proxy_service", return_value=svc),
            patch("app.services.cert_manager.is_cert_trusted", return_value=False),
            patch(
                "app.services.cert_manager.install_and_trust", return_value=True
            ) as mock_install,
        ):
            main._ensure_cert_generated_portable()
        mock_install.assert_called_once()

    def test_does_not_reinstall_when_already_trusted(self):
        """Idempotency: an already-trusted CA is never redundantly reinstalled."""
        svc = _fake_browser_proxy_service(is_setup=True)
        with (
            patch("app.server.api.get_browser_proxy_service", return_value=svc),
            patch("app.services.cert_manager.is_cert_trusted", return_value=True),
            patch("app.services.cert_manager.install_and_trust") as mock_install,
        ):
            main._ensure_cert_generated_portable()
        mock_install.assert_not_called()

    def test_trust_failure_is_non_fatal(self):
        """A trust exception must never crash portable startup."""
        svc = _fake_browser_proxy_service(is_setup=True)
        with (
            patch("app.server.api.get_browser_proxy_service", return_value=svc),
            patch("app.services.cert_manager.is_cert_trusted", return_value=False),
            patch("app.services.cert_manager.install_and_trust", side_effect=RuntimeError("boom")),
        ):
            main._ensure_cert_generated_portable()  # must not raise

    def test_trust_returning_false_is_non_fatal_and_logged(self, capsys):
        svc = _fake_browser_proxy_service(is_setup=True)
        with (
            patch("app.server.api.get_browser_proxy_service", return_value=svc),
            patch("app.services.cert_manager.is_cert_trusted", return_value=False),
            patch("app.services.cert_manager.install_and_trust", return_value=False),
        ):
            main._ensure_cert_generated_portable()  # must not raise
        out = capsys.readouterr().out
        # Exact wording differs by platform (Linux says "isn't implemented on
        # Linux yet"; macOS/Windows say "did not complete automatically"), but a
        # returning-False trust attempt must always log the manual fix-cert fallback.
        assert "fix-cert" in out

    def test_setup_failure_is_non_fatal_and_skips_trust(self):
        """If CA generation itself fails, don't even attempt trust."""
        with (
            patch(
                "app.server.api.get_browser_proxy_service",
                side_effect=RuntimeError("setup exploded"),
            ),
            patch("app.services.cert_manager.install_and_trust") as mock_install,
        ):
            main._ensure_cert_generated_portable()  # must not raise
        mock_install.assert_not_called()

    def test_linux_does_not_attempt_install_because_is_trusted_is_hardcoded_true(
        self,
        monkeypatch,
    ):
        """cert_manager.is_cert_trusted() hardcodes True on Linux (a known
        C2 gap), so install_and_trust() is never even called there today --
        confirm this function doesn't try to work around that by calling
        install_and_trust() unconditionally (which would be a Linux no-op
        anyway, per cert_manager.install_and_trust()'s darwin/win32-only
        branches)."""
        monkeypatch.setattr(main.sys, "platform", "linux")
        svc = _fake_browser_proxy_service(is_setup=True)
        with (
            patch("app.server.api.get_browser_proxy_service", return_value=svc),
            patch("app.services.cert_manager.is_cert_trusted", return_value=True),
            patch("app.services.cert_manager.install_and_trust") as mock_install,
        ):
            main._ensure_cert_generated_portable()
        mock_install.assert_not_called()

    def test_linux_prints_manual_trust_hint_instead_of_false_positive(
        self,
        monkeypatch,
        capsys,
    ):
        monkeypatch.setattr(main.sys, "platform", "linux")
        svc = _fake_browser_proxy_service(is_setup=True)
        with (
            patch("app.server.api.get_browser_proxy_service", return_value=svc),
            patch("app.services.cert_manager.is_cert_trusted", return_value=True),
        ):
            main._ensure_cert_generated_portable()
        out = capsys.readouterr().out
        assert "fix-cert.sh" in out
        assert "best-effort" in out

    def test_linux_trust_failure_message_points_to_fix_cert_sh(self, monkeypatch, capsys):
        monkeypatch.setattr(main.sys, "platform", "linux")
        svc = _fake_browser_proxy_service(is_setup=True)
        with (
            patch("app.server.api.get_browser_proxy_service", return_value=svc),
            patch("app.services.cert_manager.is_cert_trusted", return_value=False),
            patch("app.services.cert_manager.install_and_trust", return_value=False),
        ):
            main._ensure_cert_generated_portable()
        out = capsys.readouterr().out
        assert "fix-cert.sh" in out
        assert "manual trust needed" in out
