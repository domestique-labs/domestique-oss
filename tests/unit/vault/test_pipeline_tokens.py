"""Wedge pipeline mints numbered reversible tokens (M1) and honors the
pinned-vault guaranteed-recall fast path (M4)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from domestique.gateway import build_cli_pipeline
from domestique.models import Action
from domestique.vault.pinned import PinnedVault
from domestique.vault.service import TokenService
from domestique.vault.session import SessionStore


class FakeKeyProvider:
    def __init__(self) -> None:
        self._key = os.urandom(32)

    def get_or_create_key(self) -> bytes | None:
        return self._key


def _service(tmp_path: Path) -> TokenService:
    vault = PinnedVault(tmp_path / "vault.bin", FakeKeyProvider())
    vault.load()
    return TokenService(SessionStore(), vault)


@pytest.mark.asyncio
async def test_round_trip_two_ssns_and_two_emails(tmp_path: Path) -> None:
    svc = _service(tmp_path)
    pipeline = build_cli_pipeline(token_service=svc)
    original = (
        "First 123-45-6789 then 987-65-4321; mail a@b.com and c@d.com "
        "plus key AKIAIOSFODNN7EXAMPLE"
    )
    result = await pipeline.inspect(original)

    assert result.action is Action.REDACT
    assert result.redacted_text is not None
    # M2: no pigeonhole — the two SSNs map to different tokens
    assert "123-45-6789" not in result.redacted_text
    assert "987-65-4321" not in result.redacted_text
    tokens = {t for t in result.redacted_text.split() if t.startswith("[")}
    assert len(tokens) >= 4  # distinct tokens for distinct values

    # M1: detokenize restores the exact original
    restored, unknown = svc.detokenize_text(result.redacted_text)
    assert restored == original
    assert unknown == []


@pytest.mark.asyncio
async def test_same_value_same_token_across_requests(tmp_path: Path) -> None:
    svc = _service(tmp_path)
    pipeline = build_cli_pipeline(token_service=svc)
    r1 = await pipeline.inspect("ssn 123-45-6789")
    r2 = await pipeline.inspect("again 123-45-6789 ok")
    assert r1.redacted_text is not None and r2.redacted_text is not None
    token1 = [w for w in r1.redacted_text.split() if w.startswith("[")][0]
    assert token1 in r2.redacted_text  # M3 consistency


@pytest.mark.asyncio
async def test_pinned_value_caught_even_when_detectors_miss(tmp_path: Path) -> None:
    """M4: an arbitrary pinned string no regex/NER would flag still gets redacted."""
    svc = _service(tmp_path)
    assert svc.pinned is not None
    svc.pinned.pin("project-bluebird-internal", "codename")
    svc.sync_counter_floors()
    pipeline = build_cli_pipeline(token_service=svc)

    result = await pipeline.inspect("status of project-bluebird-internal is green")

    assert result.action is Action.REDACT
    assert result.redacted_text is not None
    assert "project-bluebird-internal" not in result.redacted_text
    assert "[CODENAME_1]" in result.redacted_text
    restored, _ = svc.detokenize_text(result.redacted_text)
    assert restored == "status of project-bluebird-internal is green"


@pytest.mark.asyncio
async def test_pipeline_without_service_keeps_legacy_placeholders(tmp_path: Path) -> None:
    pipeline = build_cli_pipeline()
    result = await pipeline.inspect("ssn 123-45-6789")
    assert result.redacted_text is not None
    assert "_REDACTED]" in result.redacted_text
