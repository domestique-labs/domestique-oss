"""Tests for code and IP detection."""

import pytest

from domestique_app.services.code_detection import CodeDetector, OrgConfig


@pytest.fixture
def detector():
    config = OrgConfig(
        internal_domains=["git.acme.io", "jira.acme.internal"],
        package_prefixes=["@acme/", "com.acme.", "acme_internal."],
        project_codenames=["ProjectFalcon", "Nighthawk"],
    )
    return CodeDetector(config)


@pytest.fixture
def default_detector():
    return CodeDetector()


class TestInternalUrls:
    """Tests for internal URL detection."""

    def test_internal_domain(self, default_detector):
        result = default_detector.scan("Check http://api.internal/v1/users")
        assert result.is_sensitive is True
        assert "internal_url" in result.categories

    def test_corp_domain(self, default_detector):
        result = default_detector.scan("See https://dashboard.corp/admin")
        assert result.is_sensitive is True

    def test_localhost(self, default_detector):
        result = default_detector.scan("Running on http://localhost:8080/api")
        assert result.is_sensitive is True

    def test_public_url_safe(self, default_detector):
        result = default_detector.scan("Visit https://github.com/repo")
        assert result.is_sensitive is False

    def test_org_specific_domain(self, detector):
        result = detector.scan("Push to git.acme.io/repo/main")
        assert result.is_sensitive is True
        assert "internal_domain" in result.categories


class TestPrivateIPs:
    """Tests for private IP detection."""

    def test_10_range(self, default_detector):
        result = default_detector.scan("Server at 10.0.1.50")
        assert result.is_sensitive is True
        assert "private_ip" in result.categories

    def test_172_range(self, default_detector):
        result = default_detector.scan("Database at 172.16.0.1")
        assert result.is_sensitive is True

    def test_192_168_range(self, default_detector):
        result = default_detector.scan("Router: 192.168.1.1")
        assert result.is_sensitive is True

    def test_public_ip_safe(self, default_detector):
        result = default_detector.scan("DNS: 8.8.8.8")
        assert result.is_sensitive is False


class TestImports:
    """Tests for proprietary import detection."""

    def test_python_import(self, detector):
        result = detector.scan("from acme_internal.auth import client")
        assert result.is_sensitive is True
        assert "proprietary_import" in result.categories

    def test_javascript_import(self, detector):
        result = detector.scan('import { Button } from "@acme/ui-components"')
        assert result.is_sensitive is True

    def test_java_import(self, detector):
        result = detector.scan("import com.acme.secrets.VaultClient;")
        assert result.is_sensitive is True

    def test_public_import_safe(self, detector):
        result = detector.scan("import numpy as np")
        assert result.is_sensitive is False

    def test_no_org_config(self, default_detector):
        # Without org config, no import detection
        result = default_detector.scan("from acme_internal.auth import client")
        assert not any(f.category == "proprietary_import" for f in result.findings)


class TestConnectionStrings:
    """Tests for connection string detection."""

    def test_jdbc(self, default_detector):
        result = default_detector.scan("jdbc:postgresql://db.internal:5432/production")
        assert result.is_sensitive is True
        assert "connection_string" in result.categories

    def test_mongodb(self, default_detector):
        result = default_detector.scan("mongodb://admin:pass@10.0.1.5/mydb")
        assert result.is_sensitive is True

    def test_redis(self, default_detector):
        result = default_detector.scan("redis://cache.corp:6379/0")
        assert result.is_sensitive is True


class TestCodenames:
    """Tests for project codename detection."""

    def test_codename_detected(self, detector):
        result = detector.scan("The ProjectFalcon deployment schedule")
        assert result.is_sensitive is True
        assert "project_codename" in result.categories

    def test_codename_case_insensitive(self, detector):
        result = detector.scan("nighthawk is launching next month")
        assert result.is_sensitive is True

    def test_no_codename_match(self, detector):
        result = detector.scan("The eagle has landed")
        assert not any(f.category == "project_codename" for f in result.findings)


class TestFilePaths:
    """Tests for file path detection."""

    def test_unix_path(self, default_detector):
        result = default_detector.scan("Config at /opt/company/secrets/prod.yaml")
        assert result.is_sensitive is True
        assert "file_path" in result.categories

    def test_windows_path(self, default_detector):
        result = default_detector.scan(
            r"Located at C:\Users\admin\Projects\secret-api\config.json"
        )
        assert result.is_sensitive is True


class TestInternalHostnames:
    """Tests for internal hostname detection."""

    def test_staging_host(self, default_detector):
        result = default_detector.scan("Deploy to app-server.staging first")
        assert result.is_sensitive is True
        assert "internal_hostname" in result.categories

    def test_preprod_host(self, default_detector):
        result = default_detector.scan("Test on api.preprod before release")
        assert result.is_sensitive is True


class TestCombinedDetection:
    """Tests for multiple findings in one text."""

    def test_multiple_findings(self, detector):
        text = (
            "Connect to jdbc:postgresql://10.0.1.5:5432/prod "
            "and check git.acme.io for ProjectFalcon code"
        )
        result = detector.scan(text)
        assert result.is_sensitive is True
        assert len(result.findings) >= 3

    def test_empty_text(self, detector):
        result = detector.scan("")
        assert result.is_sensitive is False

    def test_safe_text(self, detector):
        result = detector.scan("What is the capital of France?")
        assert result.is_sensitive is False
