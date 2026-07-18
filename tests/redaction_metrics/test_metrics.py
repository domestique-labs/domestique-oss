"""Deterministic exit-gate metrics for the reversible redaction engine.

Spec: domestique-notes/2-Technical/2026-07-17-reversible-redaction-design.md
Each test is one metric (M1–M5, M10). Latency metrics (M6–M9) live in
``bench/redaction_bench.py`` because wall-clock thresholds don't belong in
the always-on unit suite.
"""

from __future__ import annotations

import os
import random
import re
from pathlib import Path

import pytest

from domestique.detectors.registry import DetectorPipeline
from domestique.detectors.secrets import SecretDetector
from domestique.gateway import _WEDGE_POLICY
from domestique.models import Action
from domestique.policy import PolicyEngine
from domestique.vault.pinned import PinnedVault
from domestique.vault.service import TokenService
from domestique.vault.session import SessionStore
from domestique.vault.stream import StreamDetokenizer


class FakeKeyProvider:
    def __init__(self) -> None:
        self._key = os.urandom(32)

    def get_or_create_key(self) -> bytes | None:
        return self._key


def _service(tmp_path: Path) -> TokenService:
    vault = PinnedVault(tmp_path / "vault.bin", FakeKeyProvider())
    vault.load()
    return TokenService(SessionStore(), vault)


def _pipeline(service: TokenService) -> DetectorPipeline:
    return DetectorPipeline(
        detectors=[SecretDetector()],
        policy=PolicyEngine.from_yaml(_WEDGE_POLICY),
        token_service=service,
    )


# Corpus with same-category multiplicity — the pigeonhole cases.
M1_CORPUS = [
    "one ssn 123-45-6789 in text",
    "two ssns 123-45-6789 and 987-65-4321 must differ",
    "emails a@b.com, c@d.com, and again a@b.com",
    "mixed 123-45-6789 a@b.com AKIAIOSFODNN7EXAMPLE 987-65-4321",
    "key sk-proj-abcdefghijklmnopqrstuvwxyz123456 plus mail x@y.io",
    "cards 4111-1111-1111-1111 and 5500 0000 0000 0004",
    "phones 555-123-4567 then (555) 987-6543",
    "github ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 token",
]


@pytest.mark.asyncio
async def test_m1_round_trip_fidelity(tmp_path: Path) -> None:
    """M1: detokenize(redact(x)) == x for 100% of the corpus."""
    svc = _service(tmp_path)
    pipeline = _pipeline(svc)
    for text in M1_CORPUS:
        result = await pipeline.inspect(text)
        assert result.redacted_text is not None, text
        restored, unknown = svc.detokenize_text(result.redacted_text)
        assert restored == text, f"M1 loss for: {text!r}"
        assert unknown == []


@pytest.mark.asyncio
async def test_m2_distinct_values_distinct_tokens(tmp_path: Path) -> None:
    """M2: N distinct same-category values → N distinct tokens."""
    svc = _service(tmp_path)
    pipeline = _pipeline(svc)
    ssns = [f"{i:03d}-45-678{i % 10}" for i in range(1, 21)]
    result = await pipeline.inspect(" and ".join(ssns))
    assert result.redacted_text is not None
    tokens = set(result.redacted_text.split(" and "))
    assert len(tokens) == len(ssns)
    for ssn in ssns:
        assert ssn not in result.redacted_text


@pytest.mark.asyncio
async def test_m3_consistency_within_session_and_across_restart(tmp_path: Path) -> None:
    """M3: same value → same token across requests; pinned across reload."""
    provider = FakeKeyProvider()
    vault = PinnedVault(tmp_path / "vault.bin", provider)
    vault.load()
    vault.pin("123-45-6789", "us_ssn")
    svc = TokenService(SessionStore(), vault)
    pipeline = _pipeline(svc)

    r1 = await pipeline.inspect("ssn 123-45-6789")
    r2 = await pipeline.inspect("later 123-45-6789 again")
    assert r1.redacted_text is not None and r2.redacted_text is not None
    token = r1.redacted_text.split()[-1]
    assert token in r2.redacted_text

    # restart: fresh session, same vault file
    vault2 = PinnedVault(tmp_path / "vault.bin", provider)
    vault2.load()
    svc2 = TokenService(SessionStore(), vault2)
    r3 = await _pipeline(svc2).inspect("post-restart 123-45-6789")
    assert r3.redacted_text is not None
    assert token in r3.redacted_text


@pytest.mark.asyncio
async def test_m4_pinned_recall_without_detectors(tmp_path: Path) -> None:
    """M4: pinned values are caught even when every detector misses."""
    svc = _service(tmp_path)
    assert svc.pinned is not None
    svc.pinned.pin("wholly-unpatterned-secret-name", "codename")
    svc.pinned.pin("second secret phrase", "codename")
    svc.sync_counter_floors()
    pipeline = DetectorPipeline(
        detectors=[],  # no detectors at all
        policy=PolicyEngine.from_yaml(_WEDGE_POLICY),
        token_service=svc,
    )
    text = "wholly-unpatterned-secret-name and second secret phrase, twice: second secret phrase"
    result = await pipeline.inspect(text)
    assert result.action is Action.REDACT
    assert result.redacted_text is not None
    assert "wholly-unpatterned-secret-name" not in result.redacted_text
    assert "second secret phrase" not in result.redacted_text
    restored, _ = svc.detokenize_text(result.redacted_text)
    assert restored == text


def test_m5_streaming_matches_nonstreaming_for_all_splits(tmp_path: Path) -> None:
    """M5: every 2-way split + seeded multiway splits are byte-identical to
    non-streaming detokenization; unknown tokens pass through flagged."""
    svc = _service(tmp_path)
    for value, cat in [
        ("123-45-6789", "us_ssn"),
        ("987-65-4321", "us_ssn"),
        ("a@b.com", "email_address"),
    ]:
        svc.tokenize(value, cat)

    corpus = [
        "[SSN_1] then [SSN_2] then [EMAIL_1]",
        "hallucinated [SSN_9] amid [SSN_1]",
        "adjacent [SSN_1][SSN_2] and partial [SSN trailing",
        "ends on token [EMAIL_1]",
    ]
    rng = random.Random(7)
    for text in corpus:
        expected, _ = svc.detokenize_text(text)
        for i in range(len(text) + 1):
            st = StreamDetokenizer(svc)
            assert st.feed(text[:i]) + st.feed(text[i:]) + st.flush() == expected
        for _ in range(50):
            st = StreamDetokenizer(svc)
            out, pos = [], 0
            while pos < len(text):
                step = rng.randint(1, 6)
                out.append(st.feed(text[pos : pos + step]))
                pos += step
            out.append(st.flush())
            assert "".join(out) == expected

    st = StreamDetokenizer(svc)
    result = st.feed("[SSN_9]") + st.flush()
    assert result == "[SSN_9]"
    assert st.unknown_tokens == ["[SSN_9]"]


@pytest.mark.asyncio
async def test_m11_token_compactness(tmp_path: Path) -> None:
    """M11: redaction markers stay cheap for the LLM — every rendered token
    ≤ 14 chars, corpus average ≤ 10 chars (short semantic aliases)."""
    svc = _service(tmp_path)
    pipeline = _pipeline(svc)
    lengths: list[int] = []
    for text in M1_CORPUS:
        result = await pipeline.inspect(text)
        assert result.redacted_text is not None
        for prefix, number in re.findall(r"\[([A-Z0-9_]+)_(\d+)\]", result.redacted_text):
            lengths.append(len(f"[{prefix}_{number}]"))
    assert lengths, "corpus produced no tokens"
    assert max(lengths) <= 14, f"oversized token: max {max(lengths)}"
    assert sum(lengths) / len(lengths) <= 10, f"avg {sum(lengths) / len(lengths):.1f} > 10"


def test_m10_security_properties(tmp_path: Path) -> None:
    """M10: no plaintext at rest; no key → feature off, never plaintext."""
    provider = FakeKeyProvider()
    vault = PinnedVault(tmp_path / "vault.bin", provider)
    vault.load()
    secrets = ["123-45-6789", "hunter2-passphrase", "corp-vpn-psk-9911"]
    for s in secrets:
        vault.pin(s, "secret")
    raw = (tmp_path / "vault.bin").read_bytes()
    for s in secrets:
        assert s.encode() not in raw
        assert s.encode("utf-16-le") not in raw

    class NoKey:
        def get_or_create_key(self) -> bytes | None:
            return None

    dead = PinnedVault(tmp_path / "vault2.bin", NoKey())
    dead.load()
    assert dead.available is False
    assert dead.pin("x", "SSN") == ""
    assert not (tmp_path / "vault2.bin").exists()
