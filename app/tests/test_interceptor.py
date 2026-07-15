"""Unit tests for the browser interception module.

Tests cover:
- CA certificate generation
- PAC file generation and content
- Domain matching logic
- Content extraction from different LLM API formats
- System proxy enable/disable
"""

from __future__ import annotations

import os
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from app.services.interceptor import (
    INTERCEPTED_DOMAINS,
    add_custom_domain,
    disable_system_proxy,
    enable_system_proxy,
    generate_ca,
    generate_pac_file,
    get_intercepted_domains,
)
from app.services.mitm_addon import (
    _extract_anthropic_content,
    _extract_generic_content,
    _extract_google_content,
    _extract_openai_content,
)
from app.services.proxy import BrowserProxyService

# --- CA Generation Tests ---------------------------------------------


class TestCAGeneration:
    """Tests for CA certificate generation."""

    def test_generate_ca_creates_files(self, tmp_path):
        key_path = tmp_path / "ca.key"
        cert_path = tmp_path / "ca.pem"
        with (
            patch("app.services.interceptor.CA_DIR", tmp_path),
            patch("app.services.interceptor.CA_KEY_PATH", key_path),
            patch("app.services.interceptor.CA_CERT_PATH", cert_path),
        ):
            result_cert, result_key = generate_ca()
            assert result_cert.exists()
            assert result_key.exists()
            # Key should be private
            if os.name != "nt":
                assert oct(os.stat(result_key).st_mode)[-3:] == "600"

    def test_generate_ca_idempotent(self, tmp_path):
        """Second call doesn't regenerate if files exist."""
        key_path = tmp_path / "ca.key"
        cert_path = tmp_path / "ca.pem"
        key_path.write_text("existing key")
        cert_path.write_text("existing cert")

        with (
            patch("app.services.interceptor.CA_DIR", tmp_path),
            patch("app.services.interceptor.CA_KEY_PATH", key_path),
            patch("app.services.interceptor.CA_CERT_PATH", cert_path),
        ):
            result_cert, result_key = generate_ca()
            # Should return existing paths without regenerating
            assert result_cert.read_text() == "existing cert"


# --- PAC File Tests --------------------------------------------------


class TestPACFile:
    """Tests for PAC file generation."""

    def test_generate_pac_file(self, tmp_path):
        pac_path = tmp_path / "proxy.pac"
        with patch("app.services.interceptor.PAC_PATH", pac_path):
            result = generate_pac_file()
            assert result.exists()
            content = result.read_text()
            # Should be a valid PAC file
            assert "FindProxyForURL" in content
            assert "function" in content

    def test_pac_file_includes_known_domains(self, tmp_path):
        pac_path = tmp_path / "proxy.pac"
        with patch("app.services.interceptor.PAC_PATH", pac_path):
            generate_pac_file()
            content = pac_path.read_text()
            assert "api.openai.com" in content
            assert "claude.ai" in content
            assert "gemini.google.com" in content
            # Qwen-cloud + DeepSeek (T11)
            assert "chat.qwen.ai" in content
            assert "dashscope.aliyuncs.com" in content
            assert "api.deepseek.com" in content

    def test_pac_file_has_direct_fallback(self, tmp_path):
        pac_path = tmp_path / "proxy.pac"
        with patch("app.services.interceptor.PAC_PATH", pac_path):
            generate_pac_file()
            content = pac_path.read_text()
            assert '"DIRECT"' in content

    def test_pac_routes_to_correct_proxy(self, tmp_path):
        pac_path = tmp_path / "proxy.pac"
        with patch("app.services.interceptor.PAC_PATH", pac_path):
            generate_pac_file()
            content = pac_path.read_text()
            assert "127.0.0.1:8080" in content


# --- Domain Management Tests -----------------------------------------


class TestDomainManagement:
    """Tests for intercepted domain management."""

    def test_get_intercepted_domains(self):
        domains = get_intercepted_domains()
        assert "api.openai.com" in domains
        assert "claude.ai" in domains
        assert "gemini.google.com" in domains
        assert len(domains) > 10  # Should have many domains

    def test_qwen_and_deepseek_domains_intercepted(self):
        # T11: Qwen-cloud (destination) + DeepSeek coverage. Qwen-cloud is
        # distinct from the local `qwen3` classifier used for detection.
        domains = get_intercepted_domains()
        for host in (
            "chat.qwen.ai",
            "dashscope.aliyuncs.com",
            "dashscope-intl.aliyuncs.com",
            "api.deepseek.com",
            "chat.deepseek.com",
        ):
            assert host in domains, f"{host} should be intercepted"

    def test_add_custom_domain(self):
        with patch("app.services.interceptor.generate_pac_file"):
            add_custom_domain("custom-llm.internal.corp.com")
            assert "custom-llm.internal.corp.com" in INTERCEPTED_DOMAINS
        # Cleanup
        INTERCEPTED_DOMAINS.remove("custom-llm.internal.corp.com")

    def test_add_duplicate_domain_ignored(self):
        original_count = len(INTERCEPTED_DOMAINS)
        add_custom_domain("api.openai.com")  # Already exists
        assert len(INTERCEPTED_DOMAINS) == original_count


# --- Content Extraction Tests ----------------------------------------


class TestContentExtraction:
    """Tests for extracting user content from LLM API request bodies."""

    def test_openai_simple(self):
        body = {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "My SSN is 123-45-6789"},
            ],
        }
        result = _extract_openai_content(body)
        assert result == "My SSN is 123-45-6789"

    def test_openai_multimodal(self):
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "What's in this image?"},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}},
                    ],
                },
            ],
        }
        result = _extract_openai_content(body)
        assert result == "What's in this image?"

    def test_openai_empty_messages(self):
        body = {"messages": []}
        assert _extract_openai_content(body) is None

    def test_anthropic_with_system(self):
        body = {
            "system": "Be concise.",
            "messages": [
                {"role": "user", "content": "My password is hunter2"},
            ],
        }
        result = _extract_anthropic_content(body)
        assert "Be concise." in result
        assert "My password is hunter2" in result

    def test_anthropic_block_format(self):
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Here's my API key: sk-abc123"},
                    ],
                },
            ],
        }
        result = _extract_anthropic_content(body)
        assert "sk-abc123" in result

    def test_google_format(self):
        body = {
            "contents": [
                {"parts": [{"text": "Translate: my email is john@corp.com"}]},
            ],
        }
        result = _extract_google_content(body)
        assert "john@corp.com" in result

    def test_google_empty_contents(self):
        body = {"contents": []}
        assert _extract_google_content(body) is None

    def test_generic_prompt_field(self):
        body = {"prompt": "Complete this: my credit card is 4111-1111-1111-1111"}
        result = _extract_generic_content(body)
        assert "4111-1111-1111-1111" in result

    def test_generic_input_field(self):
        body = {"input": "Summarize this document containing SSN 555-12-3456"}
        result = _extract_generic_content(body)
        assert "555-12-3456" in result


# --- Browser Proxy Service Tests -------------------------------------


class TestBrowserProxyService:
    """Tests for BrowserProxyService lifecycle."""

    def test_initial_state(self):
        svc = BrowserProxyService()
        assert svc.is_running is False

    @patch("subprocess.Popen")
    def test_start_requires_ca(self, mock_popen):
        svc = BrowserProxyService()
        with patch("app.services.interceptor.CA_CERT_PATH") as mock_path:
            mock_path.exists.return_value = False
            with pytest.raises(RuntimeError, match="CA not generated"):
                svc.start()

    def test_setup_generates_ca(self, tmp_path):
        svc = BrowserProxyService()
        with (
            patch("app.services.interceptor.CA_DIR", tmp_path),
            patch("app.services.interceptor.CA_KEY_PATH", tmp_path / "ca.key"),
            patch("app.services.interceptor.CA_CERT_PATH", tmp_path / "ca.pem"),
            patch("app.services.interceptor.PAC_PATH", tmp_path / "proxy.pac"),
            patch("app.services.interceptor.is_ca_installed", return_value=True),
        ):
            results = svc.setup()
            assert results["ca_generated"] is True
            assert results["pac_generated"] is True


# --- System Proxy Tests: PAC-only scoping (no blanket proxy) ---------
#
# These tests verify the fix for collateral damage caused by ALSO setting a
# blanket system proxy (ProxyServer on Windows / -setsecurewebproxy and
# -setwebproxy on macOS) in addition to the scoped PAC. Only the PAC-driven
# AutoConfigURL / -setautoproxyurl path should be configured; non-AI traffic
# must never be forced through mitmproxy.
#
# A fake winreg module is injected into sys.modules so these tests run on
# any platform (winreg is Windows-only stdlib) without touching the real
# Windows registry.


def _install_fake_winreg(monkeypatch) -> dict:
    """Install an in-memory fake `winreg` module and return its backing store.

    The interceptor module does `import winreg` locally inside each
    function, which just looks the name up in ``sys.modules`` - so injecting
    a fake module there is enough to intercept every registry call, on
    Windows or not.
    """
    store: dict = {}

    class _FakeKey:
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

    def create_key_ex(root, path, reserved, access):
        return _FakeKey()

    def open_key(root, path, reserved, access):
        return _FakeKey()

    def set_value_ex(key, name, reserved, kind, value):
        store[name] = {"value": value, "kind": kind}

    def query_value_ex(key, name):
        if name not in store:
            raise FileNotFoundError(name)
        entry = store[name]
        return entry["value"], entry["kind"]

    def delete_value(key, name):
        if name not in store:
            raise FileNotFoundError(name)
        del store[name]

    fake = types.ModuleType("winreg")
    fake.HKEY_CURRENT_USER = "HKCU"
    fake.KEY_SET_VALUE = 1
    fake.KEY_READ = 2
    fake.REG_SZ = 1
    fake.REG_DWORD = 4
    fake.CreateKeyEx = create_key_ex
    fake.OpenKey = open_key
    fake.SetValueEx = set_value_ex
    fake.QueryValueEx = query_value_ex
    fake.DeleteValue = delete_value

    monkeypatch.setitem(sys.modules, "winreg", fake)
    return store


class TestWindowsSystemProxyPACOnly:
    """Windows: enable/disable must be PAC-only (no blanket ProxyServer)."""

    def _patch_platform(self, monkeypatch, tmp_path):
        monkeypatch.setattr("app.services.interceptor.is_windows", lambda: True)
        monkeypatch.setattr("app.services.interceptor.is_macos", lambda: False)
        monkeypatch.setattr(
            "app.services.interceptor.WINDOWS_PROXY_BACKUP_PATH",
            tmp_path / "windows_proxy_backup.json",
        )
        monkeypatch.setattr("app.services.interceptor.PAC_PATH", tmp_path / "proxy.pac")

    def test_enable_sets_autoconfig_and_proxyenable_only(self, tmp_path, monkeypatch):
        store = _install_fake_winreg(monkeypatch)
        self._patch_platform(monkeypatch, tmp_path)

        result = enable_system_proxy(port=8080)

        assert result is True
        assert store["AutoConfigURL"]["value"] == "http://127.0.0.1:9876/proxy.pac"
        assert store["ProxyEnable"]["value"] == 1
        # PAC-only: no blanket proxy values should ever be written.
        assert "ProxyServer" not in store
        assert "ProxyOverride" not in store

    def test_enable_backs_up_and_disable_restores_existing_corporate_pac(
        self, tmp_path, monkeypatch
    ):
        store = _install_fake_winreg(monkeypatch)
        self._patch_platform(monkeypatch, tmp_path)

        # Simulate a machine that already had a corporate PAC configured by IT.
        store["AutoConfigURL"] = {
            "value": "http://corp-proxy.example.com/corp.pac",
            "kind": 1,
        }
        store["ProxyEnable"] = {"value": 1, "kind": 4}

        enable_system_proxy(port=8080)
        assert store["AutoConfigURL"]["value"] == "http://127.0.0.1:9876/proxy.pac"

        result = disable_system_proxy()

        assert result is True
        assert store["AutoConfigURL"]["value"] == "http://corp-proxy.example.com/corp.pac"
        assert store["ProxyEnable"]["value"] == 1
        assert "ProxyServer" not in store

    def test_disable_with_no_prior_settings_clears_autoconfigurl(self, tmp_path, monkeypatch):
        store = _install_fake_winreg(monkeypatch)
        self._patch_platform(monkeypatch, tmp_path)

        enable_system_proxy(port=8080)
        disable_system_proxy()

        # Backup recorded every value as previously-absent, so restore
        # deletes them all rather than writing an explicit ProxyEnable=0 -
        # an absent ProxyEnable is equivalent to "disabled" on Windows.
        assert "AutoConfigURL" not in store
        assert "ProxyEnable" not in store
        assert "ProxyServer" not in store

    def test_enable_clears_stale_blanket_proxy_from_prior_install(self, tmp_path, monkeypatch):
        """Regression test for the merge-blocking bug: a machine that already
        has a blanket proxy configured (e.g. left over from a pre-PAC-only
        Domestique install, especially one whose process was killed before its
        normal disable/atexit cleanup ran) must have that blanket proxy
        cleared when enable_system_proxy() runs - not just left in place
        alongside the new PAC. Previously only disable_system_proxy() (on
        explicit stop/atexit) cleared ProxyServer/ProxyOverride, so a user
        who upgraded and relaunched without a clean prior shutdown kept the
        stale blanket proxy active indefinitely.
        """
        store = _install_fake_winreg(monkeypatch)
        self._patch_platform(monkeypatch, tmp_path)

        # Simulate the stale state left by an old blanket-era install.
        store["ProxyServer"] = {"value": "127.0.0.1:8080", "kind": 1}
        store["ProxyOverride"] = {"value": "<local>", "kind": 1}

        result = enable_system_proxy(port=8080)

        assert result is True
        assert store["AutoConfigURL"]["value"] == "http://127.0.0.1:9876/proxy.pac"
        assert store["ProxyEnable"]["value"] == 1
        # The stale blanket proxy must be gone after enable, not merely
        # left in place until an eventual disable.
        assert "ProxyServer" not in store
        assert "ProxyOverride" not in store

    def test_enable_clears_stale_blanket_is_noop_on_fresh_install(self, tmp_path, monkeypatch):
        """Fresh install (ProxyServer/ProxyOverride never set) must not
        error and must not introduce them - the delete is a pure no-op."""
        store = _install_fake_winreg(monkeypatch)
        self._patch_platform(monkeypatch, tmp_path)

        result = enable_system_proxy(port=8080)

        assert result is True
        assert "ProxyServer" not in store
        assert "ProxyOverride" not in store


class TestMacOSSystemProxyPACOnly:
    """macOS: enable/disable must be PAC-only (no blanket web proxy)."""

    def _patch_platform(self, monkeypatch):
        monkeypatch.setattr("app.services.interceptor.is_windows", lambda: False)
        monkeypatch.setattr("app.services.interceptor.is_macos", lambda: True)
        monkeypatch.setattr(
            "app.services.interceptor._get_all_active_interfaces", lambda: ["Wi-Fi"]
        )

    def test_enable_sets_autoproxy_only_no_blanket_webproxy(self, tmp_path, monkeypatch):
        self._patch_platform(monkeypatch)
        monkeypatch.setattr("app.services.interceptor.PAC_PATH", tmp_path / "proxy.pac")

        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            result = MagicMock()
            result.returncode = 0
            if "-getautoproxyurl" in cmd:
                result.stdout = "URL: http://127.0.0.1:9876/proxy.pac\nEnabled: Yes\n"
            else:
                result.stdout = ""
            return result

        with patch("app.services.interceptor.subprocess.run", side_effect=fake_run):
            result = enable_system_proxy(port=8080)

        assert result is True
        joined = [" ".join(c) for c in calls]
        assert any("-setautoproxyurl" in c for c in joined)
        assert any("-setautoproxystate" in c and c.endswith(" on") for c in joined)
        # PAC-only: the blanket web proxy must never be turned ON, and the
        # value-setting commands (-setsecurewebproxy/-setwebproxy, which take
        # a host+port, as opposed to ...state which takes on/off) must never
        # be issued at all. Defensively turning the *state* OFF (to clear
        # stale config from an old blanket-era install) is fine and is
        # covered by a dedicated test below.
        assert not any(cmd[1] in ("-setsecurewebproxy", "-setwebproxy") for cmd in calls)
        assert not any(
            cmd[1] in ("-setsecurewebproxystate", "-setwebproxystate") and cmd[-1] == "on"
            for cmd in calls
        )

    def test_disable_turns_off_autoproxy(self, monkeypatch):
        self._patch_platform(monkeypatch)

        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            result = MagicMock()
            result.returncode = 0
            result.stdout = ""
            return result

        with patch("app.services.interceptor.subprocess.run", side_effect=fake_run):
            result = disable_system_proxy()

        assert result is True
        joined = [" ".join(c) for c in calls]
        assert any("-setautoproxystate" in c and " off" in c for c in joined)

    def test_enable_clears_stale_blanket_webproxy_from_prior_install(self, monkeypatch):
        """Regression test for the merge-blocking bug: a machine that already
        has a blanket web proxy configured (e.g. left over from a pre-PAC-only
        Domestique install, especially one whose process was killed before its
        normal disable/atexit cleanup ran) must have it turned off by
        enable_system_proxy() - not just left active until an eventual
        disable. Previously only disable_system_proxy() (on explicit
        stop/atexit) cleared it.
        """
        self._patch_platform(monkeypatch)

        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            result = MagicMock()
            result.returncode = 0
            if "-getautoproxyurl" in cmd:
                result.stdout = "URL: http://127.0.0.1:9876/proxy.pac\nEnabled: Yes\n"
            else:
                result.stdout = ""
            return result

        with patch("app.services.interceptor.subprocess.run", side_effect=fake_run):
            result = enable_system_proxy(port=8080)

        assert result is True
        # The active interface(s) must have the stale blanket web proxy
        # explicitly turned off as part of enable, for every active interface.
        assert ["networksetup", "-setsecurewebproxystate", "Wi-Fi", "off"] in calls
        assert ["networksetup", "-setwebproxystate", "Wi-Fi", "off"] in calls
