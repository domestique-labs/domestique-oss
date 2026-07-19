"""Tests for file_scanner module - text extraction and sensitive data detection."""

from __future__ import annotations

import io
from unittest.mock import patch

import pytest

pytest.importorskip("PIL")  # requires the [file-scanning] extra; skip cleanly when absent

from PIL import Image, ImageDraw

from domestique_app.services.file_scanner import (
    FileType,
    _default_detector,
    detect_file_type,
    extract_text,
    extract_text_from_code,
    extract_text_from_image,
    extract_text_from_spreadsheet,
    scan_base64,
    scan_file,
)

# ---------------------------------------------------------------------------
# File type detection
# ---------------------------------------------------------------------------


class TestDetectFileType:
    def test_png_magic_bytes(self):
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        assert detect_file_type(data) == FileType.IMAGE

    def test_jpeg_magic_bytes(self):
        data = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        assert detect_file_type(data) == FileType.IMAGE

    def test_pdf_magic_bytes(self):
        data = b"%PDF-1.4 " + b"\x00" * 100
        assert detect_file_type(data) == FileType.PDF

    def test_xlsx_magic_bytes(self):
        data = b"PK\x03\x04" + b"\x00" * 100
        assert detect_file_type(data, "report.xlsx") == FileType.SPREADSHEET

    def test_extension_csv(self):
        data = b"name,email,phone\n"
        assert detect_file_type(data, "data.csv") == FileType.SPREADSHEET

    def test_extension_python(self):
        data = b"import os\nprint('hello')\n"
        assert detect_file_type(data, "main.py") == FileType.CODE

    def test_extension_env(self):
        data = b"API_KEY=abc123\n"
        assert detect_file_type(data, ".env") == FileType.CODE

    def test_plain_text_fallback(self):
        data = b"Just some regular text content here"
        assert detect_file_type(data, "notes.txt") == FileType.TEXT

    def test_utf8_fallback(self):
        data = b"Hello world, this is text without extension"
        assert detect_file_type(data) == FileType.TEXT

    def test_binary_unknown(self):
        data = bytes(range(256)) * 4
        assert detect_file_type(data) == FileType.UNKNOWN


# ---------------------------------------------------------------------------
# Text extraction
# ---------------------------------------------------------------------------


class TestExtractTextFromCode:
    def test_python_file(self):
        code = b'API_KEY = "sk-abc123"\nprint("hello")\n'
        result = extract_text_from_code(code)
        assert "API_KEY" in result.text
        assert "sk-abc123" in result.text
        assert result.method == "direct"
        assert result.time_ms < 5  # Should be near-instant

    def test_env_file(self):
        env = b"DATABASE_URL=postgres://user:pass@host/db\nSECRET=mysecret\n"
        result = extract_text_from_code(env)
        assert "DATABASE_URL" in result.text
        assert "mysecret" in result.text


class TestExtractTextFromSpreadsheet:
    def test_csv_extraction(self):
        data = b"name,email,ssn\nJohn,john@corp.com,123-45-6789\n"
        result = extract_text_from_spreadsheet(data, "test.csv")
        assert "john@corp.com" in result.text
        assert "123-45-6789" in result.text
        assert result.method == "csv"

    def test_csv_with_quotes(self):
        data = b'name,note\n"Smith, John","Has SSN 999-88-7777"\n'
        result = extract_text_from_spreadsheet(data, "test.csv")
        assert "999-88-7777" in result.text


class TestExtractTextFromImage:
    @patch("domestique_app.services.file_scanner._apple_vision_ocr")
    def test_uses_apple_vision(self, mock_ocr):
        mock_ocr.return_value = ("Hello World", 0.95)
        img = _make_test_image("Hello World")
        result = extract_text_from_image(img)
        assert result.text == "Hello World"
        assert result.method == "apple_vision"
        assert result.confidence == 0.95

    @patch("domestique_app.services.file_scanner._apple_vision_ocr")
    @patch("domestique_app.services.file_scanner._tesseract_ocr")
    def test_falls_back_to_tesseract(self, mock_tess, mock_vision):
        mock_vision.side_effect = RuntimeError("Vision unavailable")
        mock_tess.return_value = "Fallback text"
        img = _make_test_image("Test")
        result = extract_text_from_image(img)
        assert result.text == "Fallback text"
        assert result.method == "tesseract"

    @patch("domestique_app.services.file_scanner._apple_vision_ocr")
    @patch("domestique_app.services.file_scanner._tesseract_ocr")
    def test_both_fail(self, mock_tess, mock_vision):
        mock_vision.side_effect = RuntimeError("no")
        mock_tess.side_effect = RuntimeError("no")
        img = _make_test_image("Test")
        result = extract_text_from_image(img)
        assert result.text == ""
        assert result.method == "failed"


# ---------------------------------------------------------------------------
# Default detector
# ---------------------------------------------------------------------------


class TestDefaultDetector:
    def test_detects_email(self):
        detections = _default_detector("Send to john@company.com please")
        categories = [d["category"] for d in detections]
        assert "email" in categories

    def test_detects_ssn(self):
        detections = _default_detector("SSN: 123-45-6789")
        categories = [d["category"] for d in detections]
        assert "SSN" in categories

    def test_detects_credit_card(self):
        detections = _default_detector("Card: 4111-2222-3333-4444")
        categories = [d["category"] for d in detections]
        assert "credit_card" in categories

    def test_detects_api_key(self):
        detections = _default_detector("key = sk-abcdefghijklmnopqrstuvwxyz12345")
        categories = [d["category"] for d in detections]
        assert "api_key" in categories

    def test_detects_aws_key(self):
        detections = _default_detector("AWS_KEY=AKIAIOSFODNN7EXAMPLE1234")
        categories = [d["category"] for d in detections]
        assert "api_key" in categories

    def test_detects_credential(self):
        detections = _default_detector('password = "SuperS3cret!123"')
        categories = [d["category"] for d in detections]
        assert "credential" in categories

    def test_clean_text_no_detections(self):
        detections = _default_detector("The weather is nice today. Let's go for a walk.")
        # Should not have high-confidence detections
        # (phone regex might match some numbers, but no SSN/email/api_key)
        high_confidence = [d for d in detections if d["category"] in ("email", "SSN", "api_key")]
        assert len(high_confidence) == 0


# ---------------------------------------------------------------------------
# Full scan pipeline
# ---------------------------------------------------------------------------


class TestScanFile:
    def test_scan_code_with_secrets(self):
        code = b'API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz12"\n'
        result = scan_file(code, filename="config.py")
        assert result.contains_sensitive
        assert "api_key" in result.categories
        assert result.file_type == FileType.CODE
        assert result.total_time_ms < 10

    def test_scan_csv_with_pii(self):
        data = b"name,email\nJohn,john@acme.com\n"
        result = scan_file(data, filename="users.csv")
        assert result.contains_sensitive
        assert "email" in result.categories

    def test_scan_clean_text(self):
        data = b"This is a completely normal document about cooking recipes."
        result = scan_file(data, filename="notes.txt")
        assert not result.contains_sensitive
        assert result.categories == []

    def test_scan_empty_file(self):
        result = scan_file(b"", filename="empty.txt")
        assert not result.contains_sensitive

    def test_custom_detector(self):
        def custom(text):
            return [{"category": "custom", "value": "x"}] if "secret" in text else []
        data = b"This has a secret word"
        result = scan_file(data, filename="test.txt", detector_fn=custom)
        assert result.contains_sensitive
        assert "custom" in result.categories


class TestScanBase64:
    def test_scan_base64_text(self):
        import base64

        content = b"My SSN is 111-22-3333"
        encoded = base64.b64encode(content).decode()
        result = scan_base64(encoded, filename="note.txt")
        assert result.contains_sensitive
        assert "SSN" in result.categories

    def test_scan_base64_with_data_uri(self):
        import base64

        content = b"email: test@corp.com"
        encoded = "data:text/plain;base64," + base64.b64encode(content).decode()
        result = scan_base64(encoded, filename="data.txt")
        assert result.contains_sensitive

    def test_invalid_base64(self):
        result = scan_base64("not valid base64!!!", filename="bad.bin")
        assert not result.contains_sensitive
        assert result.error is not None


# ---------------------------------------------------------------------------
# Integration: extract_text router
# ---------------------------------------------------------------------------


class TestExtractTextRouter:
    def test_routes_code(self):
        data = b"print('hello')"
        result = extract_text(data, "main.py")
        assert result.method == "direct"
        assert "print" in result.text

    def test_routes_csv(self):
        data = b"a,b,c\n1,2,3\n"
        result = extract_text(data, "data.csv")
        assert result.method == "csv"
        assert "1" in result.text

    @patch("domestique_app.services.file_scanner._apple_vision_ocr")
    def test_routes_image(self, mock_ocr):
        mock_ocr.return_value = ("OCR text", 0.9)
        img_data = _make_test_image("test")
        result = extract_text(img_data, "screenshot.png")
        assert result.method == "apple_vision"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_test_image(text: str) -> bytes:
    """Create a minimal PNG image with text."""
    img = Image.new("RGB", (200, 50), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((10, 10), text, fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
