"""CA certificate management - generation, trust verification, installation.

On macOS the CA cert is added to the user's login keychain and trusted
via ``security trust-settings-import`` into the *user* trust domain.
This requires **no admin password** and no Terminal interaction.
"""

from __future__ import annotations

import hashlib
import logging
import plistlib
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger(__name__)

CA_DIR = Path.home() / ".domestique" / "ca"
CA_CERT = CA_DIR / "domestique-ca.pem"
CA_KEY = CA_DIR / "domestique-ca.key"


def is_cert_generated() -> bool:
    """Check if the CA certificate files exist."""
    return CA_CERT.exists() and CA_KEY.exists()


def is_cert_trusted() -> bool:
    """Return True when the OS trusts our CA for SSL verification."""
    if not CA_CERT.exists():
        return False

    if sys.platform == "darwin":
        result = subprocess.run(  # noqa: S603
            ["security", "verify-cert", "-c", str(CA_CERT)],  # noqa: S607
            capture_output=True,
            text=True,
        )
        return "CSSMERR" not in result.stderr and result.returncode == 0

    if sys.platform == "win32":
        # Check if the CA is in the current user's Root store
        for name in ("Domestique Local CA", "LLM Firewall Local CA"):
            result = subprocess.run(  # noqa: S603
                ["certutil", "-user", "-store", "Root", name],  # noqa: S607
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and name in result.stdout:
                return True
        return False

    # Linux: check if cert is in system CA bundle (best-effort)
    return True


def _extract_issuer_der(cert_path: Path) -> bytes:
    """Extract the DER-encoded issuer DN from a PEM certificate.

    Uses ``openssl asn1parse`` so we don't need the ``cryptography``
    package at runtime (it isn't bundled by py2app).
    """
    import re

    result = subprocess.run(  # noqa: S603
        ["openssl", "asn1parse", "-in", str(cert_path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )
    # Find the 2nd SEQUENCE at depth=2 (issuer DN in X.509 TBSCertificate)
    offsets = []
    for line in result.stdout.strip().split("\n"):
        m = re.match(r"\s*(\d+):d=2\s+hl=\d+\s+l=\s*\d+\s+cons:\s+SEQUENCE", line)
        if m:
            offsets.append(int(m.group(1)))
    if len(offsets) < 2:
        raise ValueError("Cannot locate issuer in certificate ASN.1 structure")

    issuer_offset = offsets[1]
    r = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "openssl",
            "asn1parse",
            "-in",
            str(cert_path),
            "-strparse",
            str(issuer_offset),
            "-out",
            "/dev/stdout",
            "-noout",
        ],
        capture_output=True,
        check=True,
    )
    return r.stdout


def install_and_trust() -> bool:
    """Add the CA to the user's trust store (no admin needed).

    macOS: adds to login keychain and imports trust settings.
    Windows: adds to the current user's Root certificate store via certutil.

    Returns True if the cert is trusted after the operation.
    """
    if not CA_CERT.exists():
        return False

    if sys.platform == "win32":
        return _install_and_trust_windows()

    if sys.platform != "darwin":
        return False

    # --- macOS path ---
    login_kc = Path.home() / "Library" / "Keychains" / "login.keychain-db"

    # Step 1 -- add to login keychain (idempotent)
    subprocess.run(  # noqa: S603
        ["security", "add-certificates", "-k", str(login_kc), str(CA_CERT)],  # noqa: S607
        capture_output=True,
    )

    # Step 2 -- build trust plist
    try:
        cert_der = subprocess.run(  # noqa: S603
            ["openssl", "x509", "-in", str(CA_CERT), "-outform", "DER"],  # noqa: S607
            capture_output=True,
            check=True,
        ).stdout

        # SHA-1 certificate fingerprint: an identity/display value (the standard
        # fingerprint form shown by browsers/openssl), not a security hash.
        sha1 = hashlib.sha1(cert_der).hexdigest().upper()  # noqa: S324

        serial_hex = (
            subprocess.run(  # noqa: S603
                ["openssl", "x509", "-in", str(CA_CERT), "-serial", "-noout"],  # noqa: S607
                capture_output=True,
                text=True,
                check=True,
            )
            .stdout.strip()
            .split("=")[1]
        )
        serial_bytes = bytes.fromhex(serial_hex)

        issuer_der = _extract_issuer_der(CA_CERT)

        plist = {
            "trustVersion": 1,
            "trustList": {
                sha1: {
                    "issuerName": issuer_der,
                    "modDate": datetime.now(UTC),
                    "serialNumber": serial_bytes,
                    "trustSettings": [],  # empty = trusted for all policies
                }
            },
        }

        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as tmp:
            plistlib.dump(plist, tmp, fmt=plistlib.FMT_XML)
            tmp_path = tmp.name

        # Step 3 -- import into user trust domain
        result = subprocess.run(  # noqa: S603
            ["security", "trust-settings-import", "-d", tmp_path],  # noqa: S607
            capture_output=True,
            text=True,
        )
        Path(tmp_path).unlink(missing_ok=True)

        if result.returncode != 0:
            log.error("trust-settings-import failed: %s", result.stderr.strip())
            return False

    except Exception:
        log.exception("Failed to install CA trust")
        return False

    trusted = is_cert_trusted()
    log.info("CA cert trusted: %s", trusted)
    return trusted


def _install_and_trust_windows() -> bool:
    """Add the CA to the current user's Root certificate store on Windows.

    Uses ``certutil -user -addstore Root`` which does NOT require admin
    privileges — it writes to HKCU\\Software\\Microsoft\\SystemCertificates.
    """
    result = subprocess.run(  # noqa: S603
        ["certutil", "-user", "-addstore", "Root", str(CA_CERT)],  # noqa: S607
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log.error("certutil addstore failed: %s", result.stderr.strip())
        return False

    trusted = is_cert_trusted()
    log.info("CA cert trusted (Windows): %s", trusted)
    return trusted


def get_cert_status() -> dict:
    """Return a dict describing the cert status for the API/dashboard."""
    return {
        "generated": is_cert_generated(),
        "trusted": is_cert_trusted(),
        "path": str(CA_CERT) if CA_CERT.exists() else None,
    }
