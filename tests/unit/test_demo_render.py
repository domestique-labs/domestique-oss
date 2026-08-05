from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

from domestique import console
from domestique.cli import (
    _highlight_tokens,
    _render_canned,
    _render_config_header,
    _render_ledger,
    _truncate,
)
from domestique.config import Settings
from domestique.detectors import status as st
from domestique.detectors.registry import Finding
from domestique.gateway import build_cli_pipeline
from domestique.models import Action, Span
from domestique.policy import PolicyEngine

if TYPE_CHECKING:
    from domestique.detectors.registry import InspectionResult


def _provision(tmp_path, monkeypatch) -> None:
    """Give the header a config.json so a preset counts as chosen.

    Without this the header correctly reports "none chosen", and these tests
    only passed because they read the *developer's* real ~/.domestique (see
    issue #70) — on a scratch HOME they failed.
    """
    home = tmp_path / "home" / ".domestique"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.json").write_text('{"detection_stack": {"regex": true}}')
    monkeypatch.setattr("domestique.config_loader.DOMESTIQUE_HOME", home)


class TestConfigHeader:
    def test_shows_active_preset_and_regex_on(self, tmp_path, monkeypatch) -> None:
        _provision(tmp_path, monkeypatch)
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


class TestConfigHeaderReportsAvailability:
    """Issue #60: the header claimed a tier was on because a bool said so.

    `enable_gliner=True` with the `gliner` package absent still printed
    `✔ GLiNER`, so a clean wheel install advertised PII coverage it could not
    perform. The header must consume `detector_status`, which actually probes.
    """

    def _header(self, settings: Settings, *, color: bool = False) -> str:
        return _render_config_header(settings, PolicyEngine.from_yaml_default(), color=color)

    def test_configured_but_missing_module_is_not_a_checkmark(self, monkeypatch) -> None:
        monkeypatch.setattr(st, "_module_available", lambda name: False)
        g = console.glyphs()
        out = self._header(Settings(enable_gliner=True))
        assert f"{g['check']} GLiNER" not in out, "claimed available while uninstalled"
        assert f"{g['cross']} GLiNER" in out
        assert "domestique[ner]" in out, "install hint missing"

    def test_configured_and_available_is_a_checkmark(self, monkeypatch) -> None:
        monkeypatch.setattr(st, "_module_available", lambda name: True)
        g = console.glyphs()
        out = self._header(Settings(enable_gliner=True))
        assert f"{g['check']} GLiNER" in out
        assert f"{g['cross']} GLiNER" not in out

    def test_unconfigured_tier_stays_dim_dot(self, monkeypatch) -> None:
        monkeypatch.setattr(st, "_module_available", lambda name: True)
        g = console.glyphs()
        out = self._header(Settings(enable_gliner=False))
        assert f"{g['dot']} GLiNER" in out

    def test_no_ansi_when_color_disabled(self, monkeypatch) -> None:
        monkeypatch.setattr(st, "_module_available", lambda name: False)
        out = self._header(Settings(enable_gliner=True, enable_pii_detection=True))
        assert "\033[" not in out

    def test_local_llm_unreachable_daemon_is_not_a_checkmark(self, monkeypatch) -> None:
        monkeypatch.setattr(st, "_ollama_tags", lambda base, timeout: None)
        g = console.glyphs()
        out = self._header(Settings(enable_local_llm=True))
        assert f"{g['cross']} LLM:" in out
        assert f"{g['check']} LLM:" not in out

    def test_local_llm_present_model_is_a_checkmark(self, monkeypatch) -> None:
        settings = Settings(enable_local_llm=True)
        monkeypatch.setattr(st, "_ollama_tags", lambda base, timeout: {settings.local_llm_model})
        g = console.glyphs()
        out = self._header(settings)
        assert f"{g['check']} LLM:{settings.local_llm_model}" in out

    def test_header_does_not_probe_the_network_when_llm_disabled(self, monkeypatch) -> None:
        def _boom(base: str, timeout: float) -> set[str]:
            raise AssertionError("probed the daemon for a tier that is switched off")

        monkeypatch.setattr(st, "_ollama_tags", _boom)
        assert "Detection stack" in self._header(Settings())

    def test_keeps_the_labels_other_tests_assert_on(self, tmp_path, monkeypatch) -> None:
        _provision(tmp_path, monkeypatch)  # else the preset row reads "none chosen"
        monkeypatch.setattr(st, "_module_available", lambda name: False)
        out = self._header(Settings())
        for label in ("Active configuration", "Detection stack", "[balanced]", "Regex", "GLiNER"):
            assert label in out


class TestHighlightTokens:
    """Issue #61 §3: #59 changed tokens to `[AWSKEY_1]`, the regex still
    required a literal `_REDACTED]`, so the demo's AFTER line stopped painting
    the very tokens it exists to show off."""

    def test_numbered_token_is_painted(self) -> None:
        paint = console.Palette(enabled=True)
        out = _highlight_tokens("sent [AWSKEY_1] onward", paint)
        assert "\033[32m[AWSKEY_1]\033[0m" in out

    def test_multiword_numbered_token_is_painted(self) -> None:
        paint = console.Palette(enabled=True)
        out = _highlight_tokens("ssn [US_SSN_12] here", paint)
        assert "\033[32m[US_SSN_12]\033[0m" in out

    def test_legacy_redacted_token_still_painted(self) -> None:
        paint = console.Palette(enabled=True)
        out = _highlight_tokens("key [AWS_ACCESS_KEY_REDACTED]", paint)
        assert "\033[32m[AWS_ACCESS_KEY_REDACTED]\033[0m" in out

    def test_ordinary_bracketed_prose_is_not_painted(self) -> None:
        paint = console.Palette(enabled=True)
        for prose in ("[see note 1]", "[TODO]", "[2026-08-03]", "[a_b_1]"):
            assert _highlight_tokens(prose, paint) == prose, prose

    def test_no_color_leaves_text_untouched(self) -> None:
        paint = console.Palette(enabled=False)
        assert _highlight_tokens("sent [AWSKEY_1]", paint) == "sent [AWSKEY_1]"


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


class TestPresetHonesty:
    """A preset is only 'active' when the user actually chose one.

    Settings defaults local_llm_preset to "balanced", so a bare install
    highlighted [balanced] while the stack below showed regex and nothing
    else — announcing a provisioned profile that did not exist. Same class of
    defect as #60, one row up.
    """

    def _header(self, tmp_path, monkeypatch, *, config: dict | None) -> str:
        import json as _json

        from domestique.cli import _render_config_header
        from domestique.config import Settings
        from domestique.policy import PolicyEngine

        home = tmp_path / "home"
        (home / ".domestique").mkdir(parents=True)
        if config is not None:
            (home / ".domestique" / "config.json").write_text(_json.dumps(config))
        monkeypatch.setattr("domestique.config_loader.DOMESTIQUE_HOME", home / ".domestique")
        return _render_config_header(
            Settings(), PolicyEngine.from_yaml_default(), color=False
        )

    def test_bare_install_claims_no_preset(self, tmp_path, monkeypatch):
        out = self._header(tmp_path, monkeypatch, config=None)
        assert "none chosen" in out
        assert "domestique setup" in out
        assert "[balanced]" not in out, "a bare install must not claim a provisioned preset"

    def test_provisioned_install_highlights_the_chosen_preset(self, tmp_path, monkeypatch):
        out = self._header(
            tmp_path, monkeypatch, config={"detection_stack": {"regex": True}}
        )
        assert "[balanced]" in out
        assert "none chosen" not in out
