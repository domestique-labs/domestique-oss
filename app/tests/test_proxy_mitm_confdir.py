"""Tests for `_refresh_mitm_confdir` (audit I7).

mitmdump reads its CA only from its own confdir copy
(`mitmproxy-ca-cert.pem` / `mitmproxy-ca.pem`), which used to be copied
from `~/.llmguard/ca/llmguard-ca.{pem,key}` exactly once
(`if not mitm_cert.exists(): ...`). If the source CA was ever rotated,
regenerated, or restored from a backup, mitmdump kept signing with the
stale copy while the rest of the app considered the new CA trusted --
this refresh (source newer than confdir copy -> recopy) closes that gap.
"""

from __future__ import annotations

import os
import time

from app.services.proxy import _refresh_mitm_confdir


def _touch(path, content, mtime=None):
    path.write_text(content)
    if mtime is not None:
        os.utime(path, (mtime, mtime))


class TestRefreshMitmConfdir:
    def test_copies_when_confdir_missing(self, tmp_path):
        ca_cert = tmp_path / "llmguard-ca.pem"
        ca_key = tmp_path / "llmguard-ca.key"
        _touch(ca_cert, "CERT-V1")
        _touch(ca_key, "KEY-V1")
        confdir = tmp_path / "mitmproxy"

        refreshed = _refresh_mitm_confdir(ca_cert, ca_key, confdir)

        assert refreshed is True
        mitm_cert = confdir / "mitmproxy-ca-cert.pem"
        mitm_key = confdir / "mitmproxy-ca.pem"
        assert mitm_cert.read_text() == "CERT-V1"
        assert "KEY-V1" in mitm_key.read_text()
        assert "CERT-V1" in mitm_key.read_text()

    def test_does_not_recopy_when_unchanged(self, tmp_path):
        ca_cert = tmp_path / "llmguard-ca.pem"
        ca_key = tmp_path / "llmguard-ca.key"
        _touch(ca_cert, "CERT-V1")
        _touch(ca_key, "KEY-V1")
        confdir = tmp_path / "mitmproxy"

        assert _refresh_mitm_confdir(ca_cert, ca_key, confdir) is True

        mitm_cert = confdir / "mitmproxy-ca-cert.pem"
        before = mitm_cert.stat().st_mtime

        # Second call: source unchanged -> must not needlessly recopy.
        refreshed_again = _refresh_mitm_confdir(ca_cert, ca_key, confdir)

        assert refreshed_again is False
        assert mitm_cert.stat().st_mtime == before
        assert mitm_cert.read_text() == "CERT-V1"

    def test_recopies_when_source_ca_is_newer(self, tmp_path):
        ca_cert = tmp_path / "llmguard-ca.pem"
        ca_key = tmp_path / "llmguard-ca.key"
        confdir = tmp_path / "mitmproxy"

        old_time = time.time() - 3600
        _touch(ca_cert, "CERT-OLD", mtime=old_time)
        _touch(ca_key, "KEY-OLD", mtime=old_time)
        _refresh_mitm_confdir(ca_cert, ca_key, confdir)

        mitm_cert = confdir / "mitmproxy-ca-cert.pem"
        assert mitm_cert.read_text() == "CERT-OLD"

        # Simulate CA rotation/regeneration: source rewritten with a
        # newer mtime (this is exactly what generate_ca() does).
        _touch(ca_cert, "CERT-NEW", mtime=time.time())
        _touch(ca_key, "KEY-NEW", mtime=time.time())

        refreshed = _refresh_mitm_confdir(ca_cert, ca_key, confdir)

        assert refreshed is True
        assert mitm_cert.read_text() == "CERT-NEW"
        assert "KEY-NEW" in (confdir / "mitmproxy-ca.pem").read_text()

    def test_recopies_when_confdir_key_missing_even_if_cert_present(self, tmp_path):
        """Guard against a partially-written confdir (e.g. an interrupted
        first copy) being mistaken for a complete, up-to-date one."""
        ca_cert = tmp_path / "llmguard-ca.pem"
        ca_key = tmp_path / "llmguard-ca.key"
        _touch(ca_cert, "CERT-V1")
        _touch(ca_key, "KEY-V1")
        confdir = tmp_path / "mitmproxy"
        confdir.mkdir(parents=True)
        (confdir / "mitmproxy-ca-cert.pem").write_text("CERT-V1")
        # mitmproxy-ca.pem (combined key+cert) deliberately absent.

        refreshed = _refresh_mitm_confdir(ca_cert, ca_key, confdir)

        assert refreshed is True
        assert (confdir / "mitmproxy-ca.pem").exists()
