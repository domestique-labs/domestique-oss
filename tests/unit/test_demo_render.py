from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

from domestique.cli import _render_canned, _render_config_header, _render_ledger, _truncate
from domestique.config import Settings
from domestique.detectors.registry import Finding
from domestique.gateway import build_cli_pipeline
from domestique.models import Action, Span
from domestique.policy import PolicyEngine

if TYPE_CHECKING:
    from domestique.detectors.registry import InspectionResult


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

    def test_hides_zero_length_diagnostic_sentinel(self) -> None:
        # A gliner_not_cached / detector_error sentinel is a zero-length Span(0,0)
        # diagnostic that policy uses but which is NOT a redacted secret; it must
        # never show up in the Findings list as a "detection".
        before = "key AKIAIOSFODNN7EXAMPLE"
        findings = [
            Finding(
                detector="regex", category="aws_access_key", confidence=0.99, span=Span(4, 24)
            ),
            Finding(
                detector="gliner", category="gliner_not_cached", confidence=1.0, span=Span(0, 0)
            ),
        ]
        after = "key [AWS_ACCESS_KEY_REDACTED]"
        out = _render_canned(before, after, findings, color=False)
        assert "AWS access key" in out  # the real finding still shown
        assert "Gliner not cached" not in out  # sentinel suppressed
        assert "gliner_not_cached" not in out


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

    def test_clean_input_says_nothing_detected(self) -> None:
        text = "just a normal sentence about the weather"
        out = _render_ledger(text, text, self._findings(text), color=False)
        assert "nothing sensitive detected" in out

    def test_shows_after_redacted_text(self) -> None:
        # Bug 1: the interactive prompt path must show the AFTER redacted text,
        # not only the leaked->token ledger rows.
        before = "key AKIAIOSFODNN7EXAMPLE"
        after = "key [AWS_ACCESS_KEY_REDACTED]"
        findings = [
            Finding(
                detector="regex", category="aws_access_key", confidence=0.99, span=Span(4, 24)
            ),
        ]
        out = _render_ledger(before, after, findings, color=False)
        assert "AFTER" in out
        assert "key [AWS_ACCESS_KEY_REDACTED]" in out  # full redacted text shown

    def test_hides_zero_length_diagnostic_sentinel(self) -> None:
        # Bug 2: a gliner_not_cached / detector_error zero-length sentinel must
        # not appear as a redacted "[..._REDACTED]" ledger row.
        before = "key AKIAIOSFODNN7EXAMPLE"
        after = "key [AWS_ACCESS_KEY_REDACTED]"
        findings = [
            Finding(
                detector="regex", category="aws_access_key", confidence=0.99, span=Span(4, 24)
            ),
            Finding(
                detector="gliner", category="gliner_not_cached", confidence=1.0, span=Span(0, 0)
            ),
        ]
        out = _render_ledger(before, after, findings, color=False)
        assert "redacted 1 secret" in out  # only the real one counted
        assert "[GLINER_NOT_CACHED_REDACTED]" not in out

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


class TestDemoEnumeratesTokens:
    """The demo must showcase the same reversible tokens the wedge sends.

    `domestique start` passes a TokenService, so distinct values get distinct
    numbered tokens ([EMAIL_1], [EMAIL_2]). `run_demo` built its pipeline
    without one and fell back to the legacy flat [CATEGORY_REDACTED]
    placeholder, so two different emails rendered identically - looking like a
    collision, and hiding the taxonomy's compact prefixes.
    """

    def test_distinct_values_get_distinct_tokens(self, capsys, monkeypatch) -> None:
        from unittest.mock import MagicMock

        from domestique.cli import run_demo

        monkeypatch.setattr(
            "builtins.input",
            MagicMock(side_effect=["mail a@corp.com and also b@corp.com", ""]),
        )
        run_demo(interactive=True)
        out = capsys.readouterr().out
        assert "[EMAIL_1]" in out and "[EMAIL_2]" in out, "distinct emails not enumerated"
        assert "[EMAIL_ADDRESS_REDACTED]" not in out, "legacy flat placeholder still used"

    def test_ledger_token_matches_the_after_text(self, capsys, monkeypatch) -> None:
        # the ledger row used to synthesise "[CATEGORY_REDACTED]" itself, which
        # would disagree with the real minted token shown in AFTER.
        from unittest.mock import MagicMock

        from domestique.cli import run_demo

        monkeypatch.setattr("builtins.input", MagicMock(side_effect=["my ssn is 123-45-6789", ""]))
        run_demo(interactive=True)
        out = capsys.readouterr().out
        assert "[SSN_1]" in out
        assert "[US_SSN_REDACTED]" not in out


class TestBlockVerdictNeverPrintsCleartext:
    """A blocked prompt must not be echoed under "AFTER -> sent to the model".

    On BLOCK the pipeline returns redacted_text=None, so `after = redacted_text
    or text` fell back to the ORIGINAL text - printing the raw secret to the
    terminal and claiming it was sent, when nothing was sent at all.
    """

    def test_ledger_reports_blocked_instead_of_the_secret(self) -> None:
        secret = "-----BEGIN RSA PRIVATE KEY-----"
        before = f"here is my key {secret}"
        findings = [
            Finding(
                detector="regex",
                category="private_key",
                confidence=0.99,
                span=Span(15, 15 + len(secret)),
            ),
        ]
        out = _render_ledger(before, None, findings, color=False, action=Action.BLOCK)
        assert secret not in out.split("AFTER")[-1] if "AFTER" in out else True
        assert "blocked" in out.lower()
        assert "sent to the model" not in out.lower()

    def test_canned_reports_blocked_instead_of_the_secret(self) -> None:
        secret = "-----BEGIN RSA PRIVATE KEY-----"
        before = f"here is my key {secret}"
        findings = [
            Finding(
                detector="regex",
                category="private_key",
                confidence=0.99,
                span=Span(15, 15 + len(secret)),
            ),
        ]
        out = _render_canned(before, None, findings, color=False, action=Action.BLOCK)
        assert "blocked" in out.lower()
        # the BEFORE block legitimately shows it; the AFTER block must not exist
        assert "sent to the model" not in out.lower()


class TestLedgerNeverMintsTokens:
    """Rendering must not mutate the vault.

    `_redact_text` merges overlapping spans into one token, but the ledger
    deduped by raw span - so a sub-span got its own FRESH token via tokenize().
    That row then contradicted the AFTER text (the token appears nowhere in it)
    and inflated the category counter with a bogus vault entry.
    """

    def test_overlapping_subspan_does_not_mint_a_new_token(self) -> None:
        from domestique.gateway import build_cli_pipeline
        from domestique.vault import build_default_token_service

        ts = build_default_token_service(pinned=False)
        text = "SSN 123-45-6789 now"
        res = asyncio.run(build_cli_pipeline(token_service=ts).inspect(text))
        before_entries = dict(ts.session.entries())

        findings = list(res.findings) + [
            Finding(detector="x", category="us_ssn", confidence=0.9, span=Span(10, 19))
        ]
        out = _render_ledger(text, res.redacted_text, findings, color=False, token_service=ts)

        assert ts.session.entries() == before_entries, "rendering minted a new token"
        # every token shown must actually appear in the AFTER text
        for token in re.findall(r"\[[A-Z0-9_]+_\d+\]", out):
            assert token in (res.redacted_text or ""), f"{token} shown but never sent"


class TestBlockedLedgerStillListsFindings:
    """A blocked prompt must never render as "nothing sensitive detected".

    On BLOCK the pipeline mints no tokens, so the token lookup skipped every
    row and the ledger claimed nothing was found - for a prompt blocked because
    it contained a private key.
    """

    def test_blocked_with_token_service_lists_the_finding(self) -> None:
        from domestique.vault import build_default_token_service

        ts = build_default_token_service(pinned=False)
        secret = "-----BEGIN RSA PRIVATE KEY-----"
        before = f"here is my key {secret}"
        findings = [
            Finding(
                detector="regex",
                category="private_key",
                confidence=0.99,
                span=Span(15, 15 + len(secret)),
            )
        ]
        out = _render_ledger(
            before, None, findings, color=False, token_service=ts, action=Action.BLOCK
        )
        assert "nothing sensitive detected" not in out
        assert "Private key" in out
        assert "blocked" in out.lower()
