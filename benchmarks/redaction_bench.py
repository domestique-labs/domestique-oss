"""Latency metrics M6–M9 for the reversible redaction engine.

Run:  python bench/redaction_bench.py [--json]
Exit code 0 only when every threshold passes. Thresholds come from the
design spec (2026-07-17-reversible-redaction-design.md) and carry headroom
against the industry 15–25 ms gateway envelope.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import statistics
import sys
import tempfile
import time
from pathlib import Path

from domestique.detectors.registry import DetectorPipeline
from domestique.detectors.secrets import SecretDetector
from domestique.gateway import _WEDGE_POLICY
from domestique.policy import PolicyEngine
from domestique.vault.pinned import PinnedVault
from domestique.vault.service import TokenService
from domestique.vault.session import SessionStore
from domestique.vault.stream import StreamDetokenizer


class _StaticKey:
    def __init__(self) -> None:
        self._key = os.urandom(32)

    def get_or_create_key(self) -> bytes | None:
        return self._key


def _percentile(samples: list[float], pct: float) -> float:
    ordered = sorted(samples)
    idx = min(len(ordered) - 1, int(len(ordered) * pct / 100))
    return ordered[idx]


def _prompt_1kb_with_findings() -> str:
    filler = "the quick brown fox jumps over the lazy dog " * 12
    findings = (
        "123-45-6789 987-65-4321 a@b.com c@d.com AKIAIOSFODNN7EXAMPLE "
        "555-123-4567 4111-1111-1111-1111 x@y.io ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
        "111-22-3333"
    )
    return (filler + findings)[:1024].ljust(1024, "x")


async def bench_m6_redact(service: TokenService, n: int = 300) -> dict[str, float]:
    pipeline = DetectorPipeline(
        detectors=[SecretDetector()],
        policy=PolicyEngine.from_yaml(_WEDGE_POLICY),
        token_service=service,
    )
    text = _prompt_1kb_with_findings()
    await pipeline.inspect(text)  # warm
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        await pipeline.inspect(text)
        samples.append((time.perf_counter() - t0) * 1000)
    return {"p50_ms": statistics.median(samples), "p95_ms": _percentile(samples, 95)}


def bench_m7_detokenize(service: TokenService, n: int = 300) -> dict[str, float]:
    tokens = [service.tokenize(f"{i:03d}-45-6789", "us_ssn") for i in range(20)]
    body = (" filler text " * 16).join(tokens)
    body = body.ljust(4096, "y")
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        service.detokenize_text(body)
        samples.append((time.perf_counter() - t0) * 1000)
    return {"p50_ms": statistics.median(samples), "p95_ms": _percentile(samples, 95)}


def bench_m8_stream(service: TokenService) -> dict[str, float]:
    service.tokenize("123-45-6789", "us_ssn")
    chunks = []
    for i in range(200):
        chunks.append(f"delta {i} [SSN" if i % 5 == 0 else f"_1] plain piece {i} ")
    samples: list[float] = []
    st = StreamDetokenizer(service)
    max_held = 0
    for chunk in chunks:
        t0 = time.perf_counter()
        st.feed(chunk)
        samples.append((time.perf_counter() - t0) * 1000)
        max_held = max(max_held, len(st.held))
    st.flush()
    return {"p95_ms": _percentile(samples, 95), "max_held_chars": float(max_held)}


#: Fixed corpus for the deterministic token-usage metric (mirrors the
#: M1 corpus shape: same-category multiplicity + mixed categories).
TOKEN_CORPUS = [
    "one ssn 123-45-6789 in text",
    "two ssns 123-45-6789 and 987-65-4321 must differ",
    "emails a@b.com, c@d.com, and again a@b.com",
    "mixed 123-45-6789 a@b.com AKIAIOSFODNN7EXAMPLE 987-65-4321",
    "key sk-proj-abcdefghijklmnopqrstuvwxyz123456 plus mail x@y.io",
    "cards 4111-1111-1111-1111 and 5500 0000 0000 0004",
    "phones 555-123-4567 then (555) 987-6543",
    "github ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 token",
]

_TOKEN_RE = re.compile(r"\[[A-Z0-9_]+_\d+\]")


async def bench_token_usage() -> dict[str, float]:
    """LLM-facing marker cost over the fixed corpus. Fully deterministic —
    a fresh service per run, no timing involved."""
    service = TokenService(SessionStore(), None)
    pipeline = DetectorPipeline(
        detectors=[SecretDetector()],
        policy=PolicyEngine.from_yaml(_WEDGE_POLICY),
        token_service=service,
    )
    markers: list[str] = []
    for text in TOKEN_CORPUS:
        result = await pipeline.inspect(text)
        if result.redacted_text is not None:
            markers.extend(_TOKEN_RE.findall(result.redacted_text))
    total = sum(len(m) for m in markers)
    return {
        "markers": float(len(markers)),
        "total_chars": float(total),
        "avg_chars": total / len(markers) if markers else 0.0,
    }


def bench_m9_vault(tmp: Path) -> dict[str, float]:
    provider = _StaticKey()
    vault = PinnedVault(tmp / "bench-vault.bin", provider)
    vault.load()
    for i in range(1000):
        vault.pin(f"value-{i:04d}@corp.example", "email_address")

    t0 = time.perf_counter()
    reloaded = PinnedVault(tmp / "bench-vault.bin", provider)
    reloaded.load()
    load_ms = (time.perf_counter() - t0) * 1000
    assert len(reloaded.values()) == 1000

    t0 = time.perf_counter()
    reloaded.pin("one-more@corp.example", "email_address")
    pin_ms = (time.perf_counter() - t0) * 1000
    return {"load_1k_ms": load_ms, "pin_write_ms": pin_ms}


def main() -> int:
    # Keep stdout pure JSON/scoreboard: library logs (e.g. policy_loaded)
    # must go to stderr or they corrupt `--json > file.json` in CI.
    import structlog

    structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))

    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--no-gate",
        action="store_true",
        help="always exit 0 (CI compare mode: deltas are the signal, "
        "absolute thresholds on shared runners are noise)",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        vault = PinnedVault(tmp / "vault.bin", _StaticKey())
        vault.load()
        service = TokenService(SessionStore(), vault)

        m6 = asyncio.run(bench_m6_redact(service))
        m7 = bench_m7_detokenize(service)
        m8 = bench_m8_stream(service)
        m9 = bench_m9_vault(tmp)
        token_usage = asyncio.run(bench_token_usage())

    checks = {
        "M6 redact p50 < 1ms": m6["p50_ms"] < 1.0,
        "M6 redact p95 < 3ms": m6["p95_ms"] < 3.0,
        "M7 detokenize p50 < 0.5ms": m7["p50_ms"] < 0.5,
        "M8 stream p95 < 0.2ms/chunk": m8["p95_ms"] < 0.2,
        "M8 holdback <= 32 chars": m8["max_held_chars"] <= 32,
        "M9 vault load 1k <= 100ms": m9["load_1k_ms"] <= 100,
        "M9 pin write <= 20ms": m9["pin_write_ms"] <= 20,
    }
    scoreboard = {
        "M6": m6,
        "M7": m7,
        "M8": m8,
        "M9": m9,
        "token_usage": token_usage,
        "pass": all(checks.values()),
        "checks": checks,
    }
    if args.json:
        print(json.dumps(scoreboard, indent=2))
    else:
        for name, ok in checks.items():
            print(f"{'PASS' if ok else 'FAIL'}  {name}")
        keys = ("M6", "M7", "M8", "M9", "token_usage")
        print(f"\nnumbers: {json.dumps({k: scoreboard[k] for k in keys})}")
    if args.no_gate:
        return 0
    return 0 if scoreboard["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
