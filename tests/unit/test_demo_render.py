from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from domestique.cli import _render_canned, _render_config_header, _render_ledger, _truncate
from domestique.config import Settings
from domestique.gateway import build_cli_pipeline
from domestique.policy import PolicyEngine

if TYPE_CHECKING:
    from domestique.detectors.registry import Finding, InspectionResult


class TestConfigHeader:
    def test_shows_active_preset_and_regex_on(self) -> None:
        settings = Settings()  # regex on, preset default "balanced"
        out = _render_config_header(settings, PolicyEngine.from_yaml_default(), color=False)
        assert "Regex" in out
        assert "[balanced]" in out  # active preset bracketed
        assert "redact on" in out
        assert "block on" in out  # wedge policy blocks crown-jewels
        assert "\033[" not in out  # color=False -> no ANSI

    def test_disabled_tiers_marked(self) -> None:
        out = _render_config_header(Settings(), PolicyEngine.from_yaml_default(), color=False)
        assert "GLiNER" in out


class TestCanned:
    def _run(self, text: str) -> InspectionResult:
        return asyncio.run(build_cli_pipeline().inspect(text))

    def test_shows_before_after_and_findings(self) -> None:
        text = "my aws key AKIAIOSFODNN7EXAMPLE and email a@b.com"
        res = self._run(text)
        out = _render_canned(text, res.redacted_text or text, res.findings, color=False)
        assert "BEFORE" in out
        assert "AFTER" in out
        assert "[AWS_ACCESS_KEY_REDACTED]" in out  # token present in AFTER
        assert "AWS access key" in out  # finding label
        assert "\033[" not in out  # no color when color=False

    def test_color_highlights_when_enabled(self) -> None:
        text = "key AKIAIOSFODNN7EXAMPLE"
        res = self._run(text)
        out = _render_canned(text, res.redacted_text or text, res.findings, color=True)
        assert "\033[31m" in out  # red used for a leaked secret
        assert "\033[32m" in out  # green used for a token


class TestLedger:
    def _findings(self, text: str) -> list[Finding]:
        return asyncio.run(build_cli_pipeline().inspect(text)).findings

    def test_pairs_leaked_value_to_token(self) -> None:
        text = "my aws key AKIAIOSFODNN7EXAMPLE and phone 555-123-4567"
        res = asyncio.run(build_cli_pipeline().inspect(text))
        out = _render_ledger(text, res.redacted_text or text, res.findings, color=False)
        assert "redacted 2 secret" in out
        assert "AKIAIOSFODNN7EXAMPLE" in out
        assert "[AWS_ACCESS_KEY_REDACTED]" in out
        assert "555-123-4567" in out
        assert "[PHONE_NUMBER_REDACTED]" in out

    def test_shows_full_redacted_after_below_rows(self) -> None:
        text = "my aws key AKIAIOSFODNN7EXAMPLE and email a@b.com"
        res = asyncio.run(build_cli_pipeline().inspect(text))
        after = res.redacted_text or text
        out = _render_ledger(text, after, res.findings, color=False)
        # per-finding rows still present
        assert "redacted" in out
        assert "AKIAIOSFODNN7EXAMPLE" in out
        # the full sent-to-model text is shown, not just per-finding tokens
        assert "AFTER" in out
        assert after in out
        # and it appears BELOW the per-finding rows
        assert out.index("AKIAIOSFODNN7EXAMPLE") < out.index("AFTER")

    def test_no_after_block_when_nothing_detected(self) -> None:
        text = "just a normal sentence about the weather"
        findings = self._findings(text)
        out = _render_ledger(text, text, findings, color=False)
        assert "nothing sensitive detected" in out
        assert "AFTER" not in out  # nothing redacted -> no redundant AFTER echo

    def test_clean_input_says_nothing_detected(self) -> None:
        text = "just a normal sentence about the weather"
        out = _render_ledger(text, text, self._findings(text), color=False)
        assert "nothing sensitive detected" in out

    def test_truncate_shortens_long_values_with_ellipsis(self) -> None:
        # unit-test _truncate directly — deterministic, no detector dependency
        long_value = "A" * 60
        result = _truncate(long_value, 22)
        assert len(result) <= 22
        assert "…" in result
        # keeps head and tail context, drops the middle
        assert result.startswith("A") and result.endswith("A")

    def test_truncate_leaves_short_values_unchanged(self) -> None:
        assert _truncate("short", 22) == "short"
