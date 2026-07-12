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
from unittest.mock import patch, MagicMock

import pytest

from app.services.interceptor import (
    generate_ca,
    generate_pac_file,
    get_intercepted_domains,
    add_custom_domain,
    enable_system_proxy,
    disable_system_proxy,
    INTERCEPTED_DOMAINS,
)
from app.services.mitm_addon import (
    _extract_openai_content,
    _extract_anthropic_content,
    _extract_google_content,
    _extract_generic_content,
)
from app.services.proxy import BrowserProxyService


# --- CA Generation Tests ---------------------------------------------


class TestCAGeneration:
    """Tests for CA certificate generation."""

    def test_generate_ca_creates_files(self, tmp_path):
        key_path = tmp_path / "ca.key"
        cert_path = tmp_path / "ca.pem"
        with patch("app.services.interceptor.CA_DIR", tmp_path), \
             patch("app.services.interceptor.CA_KEY_PATH", key_path), \
             patch("app.services.interceptor.CA_CERT_PATH", cert_path):
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

        with patch("app.services.interceptor.CA_DIR", tmp_path), \
             patch("app.services.interceptor.CA_KEY_PATH", key_path), \
             patch("app.services.interceptor.CA_CERT_PATH", cert_path):
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
                {"role": "user", "content": [
                    {"type": "text", "text": "What's in this image?"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}
                ]},
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
                {"role": "user", "content": [
                    {"type": "text", "text": "Here's my API key: sk-abc123"},
                ]},
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
        with patch("app.services.interceptor.CA_DIR", tmp_path), \
             patch("app.services.interceptor.CA_KEY_PATH", tmp_path / "ca.key"), \
             patch("app.services.interceptor.CA_CERT_PATH", tmp_path / "ca.pem"), \
             patch("app.services.interceptor.PAC_PATH", tmp_path / "proxy.pac"), \
             patch("app.services.interceptor.is_ca_installed", return_value=True):
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


class TestMacOSSystemProxyPACOnly:
    """macOS: enable/disable must be PAC-only (no blanket web proxy)."""

    def _patch_platform(self, monkeypatch):
        monkeypatch.setattr("app.services.interceptor.is_windows", lambda: False)
        monkeypatch.setattr("app.services.interceptor.is_macos", lambda: True)
        monkeypatch.setattr(
            "app.services.interceptor._get_all_active_interfaces", lambda: ["Wi-Fi"]
        )

    def test_enable_sets_autoproxy_only_no_blanket_webproxy(
        self, tmp_path, monkeypatch
    ):
        self._patch_platform(monkeypatch)
        monkeypatch.setattr("app.services.interceptor.PAC_PATH", tmp_path / "proxy.pac")

        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            result = MagicMock()
            result.returncode = 0
            if "-getautoproxyurl" in cmd:
                result.stdout = (
                    "URL: http://127.0.0.1:9876/proxy.pac\nEnabled: Yes\n"
                )
            else:
                result.stdout = ""
            return result

        with patch("app.services.interceptor.subprocess.run", side_effect=fake_run):
            result = enable_system_proxy(port=8080)

        assert result is True
        joined = [" ".join(c) for c in calls]
        assert any("-setautoproxyurl" in c for c in joined)
        assert any("-setautoproxystate" in c for c in joined)
        # PAC-only: the blanket web proxy calls must never be issued.
        assert not any("-setsecurewebproxy" in c for c in joined)
        assert not any("-setwebproxy" in c for c in joined)

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
