"""Browser traffic interception via system proxy + MITM.

This module enables the firewall to inspect HTTPS traffic from browsers
and native apps (ChatGPT, Gemini, Claude, etc.) by:

1. Generating a local CA certificate (once, on first run)
2. Installing it in the current user's OS trust store where supported
3. Running a transparent MITM proxy (mitmproxy-based)
4. Configuring OS proxy settings to route traffic through us
5. Using a PAC file to only intercept known LLM API domains

Only traffic to known LLM endpoints is intercepted - all other HTTPS
traffic passes through untouched for zero performance impact on browsing.

Security Model:
    - CA key is stored in ~/.llmguard/ca/ with 0600 permissions
    - CA cert is user-scoped (not system-wide unless IT deploys via MDM)
    - Proxy only binds to 127.0.0.1 (no external exposure)
    - System proxy configuration is PAC-only: we set AutoConfigURL (Windows)
      / -setautoproxyurl (macOS) and ProxyEnable/-setautoproxystate, nothing
      else. The PAC's FindProxyForURL only returns our proxy for domains in
      INTERCEPTED_DOMAINS; every other host resolves to DIRECT. We do NOT
      also configure a blanket ProxyServer / -setsecurewebproxy /
      -setwebproxy, because that would route ALL HTTP/HTTPS traffic through
      mitmproxy - breaking unrelated apps (IDEs, package managers, git,
      corporate tools) whenever they don't trust our CA or mitmproxy isn't
      running, and conflicting with any corporate proxy already configured.
      Tools that don't evaluate the system PAC (some CLIs/daemons) are out
      of scope for this browser-proxy path; point them at
      http://127.0.0.1:<port> directly via the CLI-integration mode instead.
"""

from __future__ import annotations

import json
import os
import subprocess
import shutil
import socket
from pathlib import Path
from typing import Optional

from app.services.runtime import is_macos, is_windows

CA_DIR = Path.home() / ".llmguard" / "ca"
CA_KEY_PATH = CA_DIR / "llmguard-ca.key"
CA_CERT_PATH = CA_DIR / "llmguard-ca.pem"
PAC_PATH = Path.home() / ".llmguard" / "proxy.pac"
WINDOWS_PROXY_BACKUP_PATH = Path.home() / ".llmguard" / "windows_proxy_backup.json"

# Domains to intercept - all major LLM API endpoints
INTERCEPTED_DOMAINS = [
    # OpenAI / ChatGPT
    "api.openai.com",
    "chat.openai.com",
    "chatgpt.com",
    "ab.chatgpt.com",
    # Google / Gemini
    "generativelanguage.googleapis.com",
    "gemini.google.com",
    "aistudio.google.com",
    # Anthropic / Claude
    "api.anthropic.com",
    "claude.ai",
    # Microsoft / Copilot
    "copilot.microsoft.com",
    # GitHub Copilot
    "api.githubcopilot.com",
    "copilot-proxy.githubusercontent.com",
    # Mistral
    "api.mistral.ai",
    "chat.mistral.ai",
    # Cohere
    "api.cohere.com",
    "api.cohere.ai",
    "coral.cohere.com",
    # Perplexity
    "api.perplexity.ai",
    "perplexity.ai",
    # xAI / Grok
    "api.x.ai",
    "grok.com",
    # Groq
    "api.groq.com",
    "groq.com",
    # Together AI
    "api.together.xyz",
    # Fireworks
    "api.fireworks.ai",
    # Replicate
    "api.replicate.com",
    # HuggingFace
    "api-inference.huggingface.co",
    "huggingface.co",
    # DeepSeek
    "api.deepseek.com",
    "chat.deepseek.com",
    # Cursor AI
    "api2.cursor.sh",
    "api3.cursor.sh",
    "api5.cursor.sh",
    # Windsurf / Codeium
    "server.codeium.com",
    # Meta / Llama
    "llama-api.meta.com",
]


def generate_ca() -> tuple[Path, Path]:
    """Generate a local CA certificate for HTTPS interception.

    Creates a self-signed CA certificate and private key used to issue
    per-domain certificates during MITM. Only runs once - subsequent
    calls return existing paths if CA already exists.

    Uses the ``cryptography`` library (bundled with mitmproxy) so no
    external ``openssl`` CLI is needed — works on Windows, macOS, Linux.

    Returns:
        Tuple of (ca_cert_path, ca_key_path).
    """
    if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
        return CA_CERT_PATH, CA_KEY_PATH

    CA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        return _generate_ca_cryptography()
    except ImportError:
        pass

    # Fallback to openssl CLI (macOS/Linux where cryptography may not be installed)
    return _generate_ca_openssl()


def _generate_ca_cryptography() -> tuple[Path, Path]:
    """Generate CA cert + key using the ``cryptography`` library."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LLMGuard Enterprise Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "LLMGuard Local CA"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True, crl_sign=True,
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    CA_KEY_PATH.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CA_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    if not is_windows():
        os.chmod(CA_KEY_PATH, 0o600)
        os.chmod(CA_CERT_PATH, 0o644)

    return CA_CERT_PATH, CA_KEY_PATH


def _generate_ca_openssl() -> tuple[Path, Path]:
    """Generate CA cert + key using the openssl CLI (fallback)."""
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError(
            "Neither the 'cryptography' Python package nor the OpenSSL CLI "
            "is available. Install mitmproxy (pip install llmguard[browser-proxy]) "
            "or install OpenSSL."
        )

    subprocess.run(
        [openssl, "genrsa", "-out", str(CA_KEY_PATH), "4096"],
        check=True, capture_output=True,
    )
    os.chmod(CA_KEY_PATH, 0o600)

    ext_file = CA_DIR / "ca_ext.cnf"
    ext_file.write_text(
        "[req]\n"
        "distinguished_name = req_dn\n"
        "x509_extensions = v3_ca\n"
        "prompt = no\n"
        "\n"
        "[req_dn]\n"
        "CN = LLMGuard Local CA\n"
        "O = LLMGuard Enterprise Security\n"
        "C = US\n"
        "\n"
        "[v3_ca]\n"
        "basicConstraints = critical, CA:TRUE\n"
        "keyUsage = critical, keyCertSign, cRLSign\n"
        "subjectKeyIdentifier = hash\n"
    )
    subprocess.run(
        [
            openssl, "req", "-new", "-x509", "-sha256",
            "-key", str(CA_KEY_PATH),
            "-out", str(CA_CERT_PATH),
            "-days", "3650",
            "-config", str(ext_file),
            "-extensions", "v3_ca",
        ],
        check=True, capture_output=True,
    )
    os.chmod(CA_CERT_PATH, 0o644)

    return CA_CERT_PATH, CA_KEY_PATH


def install_ca_to_keychain(cert_path: Optional[Path] = None) -> bool:
    """Install the CA certificate into the current user's trust store.

    This allows browsers to accept our MITM certificates without warnings.
    On macOS this uses the login keychain; on Windows this uses the current
    user's Root certificate store.

    Args:
        cert_path: Path to the CA certificate. Defaults to the generated one.

    Returns:
        True if installation succeeded.
    """
    cert = cert_path or CA_CERT_PATH
    if not cert.exists():
        return False

    if is_windows():
        result = subprocess.run(
            ["certutil", "-user", "-addstore", "Root", str(cert)],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    if not is_macos():
        return False

    # Add to login keychain
    result = subprocess.run(
        [
            "security", "add-trusted-cert",
            "-r", "trustRoot",
            "-k", os.path.expanduser("~/Library/Keychains/login.keychain-db"),
            str(cert),
        ],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def is_ca_installed() -> bool:
    """Check if our CA certificate is already trusted.

    Checks both the current name and legacy name for backward compatibility.
    """
    for name in ("LLMGuard Local CA", "LLM Firewall Local CA"):
        if is_windows():
            result = subprocess.run(
                ["certutil", "-user", "-store", "Root", name],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and name in result.stdout:
                return True
            continue

        if not is_macos():
            return False

        result = subprocess.run(
            ["security", "find-certificate", "-c", name],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return True
    return False


def generate_pac_file(port: int = 8080) -> Path:
    """Generate a PAC (Proxy Auto-Configuration) file.

    The PAC file tells the browser to route ONLY LLM-related traffic
    through our local proxy. All other traffic goes direct.

    Returns:
        Path to the generated PAC file.
    """
    # Build domain matching conditions (exact + subdomain matching)
    conditions = []
    for domain in INTERCEPTED_DOMAINS:
        conditions.append(
            f'    if (host === "{domain}" || '
            f'dnsDomainIs(host, ".{domain}")) return proxy;'
        )

    pac_content = f"""// LLMGuard - Proxy Auto-Configuration
// Only intercepts traffic to known LLM API endpoints.
// All other traffic goes DIRECT (no proxy overhead).

function FindProxyForURL(url, host) {{
    var proxy = "PROXY 127.0.0.1:{port}";

{chr(10).join(conditions)}

    // Everything else bypasses the proxy
    return "DIRECT";
}}
"""
    PAC_PATH.parent.mkdir(parents=True, exist_ok=True)
    PAC_PATH.write_text(pac_content)
    return PAC_PATH


def enable_system_proxy(port: int = 8080) -> bool:
    """Configure the OS to use our local proxy for LLM traffic.

    macOS uses ``networksetup`` for each active interface. Windows writes the
    current user's Internet Settings registry keys and saves the previous
    values for restoration.

    Args:
        port: The proxy port (must match the MITM proxy port).

    Returns:
        True if configuration succeeded on at least one interface.
    """
    generate_pac_file(port=port)

    if is_windows():
        return _enable_windows_proxy(port)

    if not is_macos():
        return False

    # Apply to ALL active interfaces (not just the first one)
    interfaces = _get_all_active_interfaces()
    if not interfaces:
        return False

    # Serve PAC via HTTP - Safari and other apps may ignore file:// PAC URLs
    pac_url = "http://127.0.0.1:9876/proxy.pac"

    success = False
    for interface in interfaces:
        # PAC-only: this is the ONLY proxy setting we configure. The PAC file
        # (generate_pac_file) routes just the domains in INTERCEPTED_DOMAINS
        # through 127.0.0.1:{port}; every other host evaluates to DIRECT.
        # We deliberately do NOT also call -setsecurewebproxy/-setwebproxy -
        # those set a blanket system proxy that would route ALL HTTP/HTTPS
        # traffic (Cursor's backend, pip, git, corporate tools, etc.) through
        # mitmproxy, breaking those apps whenever they don't trust our CA or
        # mitmproxy isn't running, and conflicting with any corporate proxy
        # already configured on the machine.
        #
        # Tradeoff: some CLIs/daemons don't evaluate the system PAC at all
        # (they read HTTP_PROXY/HTTPS_PROXY env vars or nothing). Those are
        # intentionally NOT covered by this browser-proxy path - they should
        # instead be pointed at our explicit local endpoint
        # (http://127.0.0.1:{port}) via the CLI-integration mode. We do not
        # add a blanket fallback to "catch" them.
        #
        # Note: some browsers may keep reusing already-open HTTP/2 connections
        # made before the PAC took effect, appearing to bypass interception
        # briefly. The existing guidance to restart the browser after
        # enabling interception addresses this; it is a browser-side caching
        # behavior, not something a blanket proxy is needed to fix.
        subprocess.run(
            ["networksetup", "-setautoproxyurl", interface, pac_url],
            capture_output=True,
        )
        subprocess.run(
            ["networksetup", "-setautoproxystate", interface, "on"],
            capture_output=True,
        )

    # Flush DNS cache to force fresh lookups (PAC host resolution, etc.)
    subprocess.run(["dscacheutil", "-flushcache"], capture_output=True)

    # Verify at least one interface has the PAC enabled
    for interface in interfaces:
        check = subprocess.run(
            ["networksetup", "-getautoproxyurl", interface],
            capture_output=True, text=True,
        )
        if pac_url in check.stdout and "Enabled: Yes" in check.stdout:
            success = True
            break

    return success


def disable_system_proxy() -> bool:
    """Remove our proxy configuration from system settings.

    Restores the prior Windows user proxy settings when a backup exists.
    Clears PAC and explicit proxy on all active macOS interfaces.

    Returns:
        True if cleanup succeeded.
    """
    if is_windows():
        return _restore_windows_proxy()

    if not is_macos():
        return False

    interfaces = _get_all_active_interfaces()
    if not interfaces:
        return False

    for interface in interfaces:
        # We only ever turn the PAC (autoproxy) on, so that's all we need to
        # turn off. The securewebproxy/webproxy -off calls are kept as
        # defensive no-ops in case an older LLMGuard version left one of
        # those set on this machine (pre PAC-only fix).
        subprocess.run(
            ["networksetup", "-setsecurewebproxystate", interface, "off"],
            capture_output=True,
        )
        subprocess.run(
            ["networksetup", "-setwebproxystate", interface, "off"],
            capture_output=True,
        )
        subprocess.run(
            ["networksetup", "-setautoproxystate", interface, "off"],
            capture_output=True,
        )
    return True


def _get_all_active_interfaces() -> list[str]:
    """Find all active network interfaces (Wi-Fi, Ethernet, etc.).

    Returns a list of interface names that have an IP address assigned.
    """
    if not is_macos():
        return _get_non_macos_interfaces()

    result = subprocess.run(
        ["networksetup", "-listallnetworkservices"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return ["Wi-Fi"]  # Fallback

    active = []
    for line in result.stdout.strip().split("\n")[1:]:  # Skip header
        line = line.strip()
        if line.startswith("*"):
            continue  # Disabled interface
        # Check if this interface has an IP
        status = subprocess.run(
            ["networksetup", "-getinfo", line],
            capture_output=True,
            text=True,
        )
        if "IP address" in status.stdout and "0.0.0.0" not in status.stdout:
            active.append(line)

    return active if active else ["Wi-Fi"]


def _get_non_macos_interfaces() -> list[str]:
    """Return stable placeholder interface names for non-macOS platforms."""
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(socket.gethostname(), None)
            if item[4][0] not in ("127.0.0.1", "::1")
        }
    except OSError:
        addresses = set()
    if is_windows():
        return ["Windows"] if addresses else ["Windows"]
    return ["default"] if addresses else ["default"]


def _enable_windows_proxy(port: int) -> bool:
    """Enable PAC and explicit proxy settings for the current Windows user."""
    import winreg

    pac_url = "http://127.0.0.1:9876/proxy.pac"
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    _backup_windows_proxy_settings(key_path)

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(
            key,
            "ProxyServer",
            0,
            winreg.REG_SZ,
            f"http=127.0.0.1:{port};https=127.0.0.1:{port}",
        )
        winreg.SetValueEx(
            key,
            "ProxyOverride",
            0,
            winreg.REG_SZ,
            "localhost;127.0.0.1;<local>",
        )

    _refresh_windows_proxy_settings()
    return _windows_proxy_points_to_llmguard(key_path, port)


def _backup_windows_proxy_settings(key_path: str) -> None:
    """Save the user's existing proxy values once so disable can restore them."""
    if WINDOWS_PROXY_BACKUP_PATH.exists():
        return

    import winreg

    backup = {}
    names = ("AutoConfigURL", "ProxyEnable", "ProxyServer", "ProxyOverride")
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
    except FileNotFoundError:
        for name in names:
            backup[name] = None
    else:
        with key:
            for name in names:
                try:
                    value, kind = winreg.QueryValueEx(key, name)
                    backup[name] = {"value": value, "kind": kind}
                except FileNotFoundError:
                    backup[name] = None

    WINDOWS_PROXY_BACKUP_PATH.parent.mkdir(parents=True, exist_ok=True)
    WINDOWS_PROXY_BACKUP_PATH.write_text(json.dumps(backup, indent=2))


def _restore_windows_proxy() -> bool:
    """Restore Windows proxy values saved by _backup_windows_proxy_settings."""
    import winreg

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    backup = None
    if WINDOWS_PROXY_BACKUP_PATH.exists():
        try:
            backup = json.loads(WINDOWS_PROXY_BACKUP_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            backup = None

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        if backup:
            for name, entry in backup.items():
                if entry is None:
                    _delete_winreg_value(key, name)
                else:
                    winreg.SetValueEx(key, name, 0, entry["kind"], entry["value"])
        else:
            _delete_winreg_value(key, "AutoConfigURL")
            _delete_winreg_value(key, "ProxyServer")
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)

    if WINDOWS_PROXY_BACKUP_PATH.exists():
        WINDOWS_PROXY_BACKUP_PATH.unlink()
    _refresh_windows_proxy_settings()
    return True


def _delete_winreg_value(key, name: str) -> None:
    import winreg

    try:
        winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass


def _windows_proxy_points_to_llmguard(key_path: str, port: int) -> bool:
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
        try:
            proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
        except FileNotFoundError:
            return False
    return f"127.0.0.1:{port}" in str(proxy_server)


def _refresh_windows_proxy_settings() -> None:
    """Notify Windows that the current user's proxy settings changed."""
    try:
        import ctypes

        internet_option_settings_changed = 39
        internet_option_refresh = 37
        ctypes.windll.Wininet.InternetSetOptionW(0, internet_option_settings_changed, 0, 0)
        ctypes.windll.Wininet.InternetSetOptionW(0, internet_option_refresh, 0, 0)
    except Exception:
        pass


def get_intercepted_domains() -> list[str]:
    """Return the list of domains being intercepted."""
    return INTERCEPTED_DOMAINS.copy()


def add_custom_domain(domain: str) -> None:
    """Add a custom domain to the interception list.

    Args:
        domain: Fully qualified domain name to intercept.
    """
    if domain not in INTERCEPTED_DOMAINS:
        INTERCEPTED_DOMAINS.append(domain)
        generate_pac_file()  # Regenerate
