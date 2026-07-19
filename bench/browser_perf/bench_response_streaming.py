"""Browser-mode response-scanning performance benchmark.

Measures TIME-TO-FIRST-BYTE (TTFB) and total delivery time for a
STREAMING LLM response (ChatGPT-style token-by-token SSE) as it passes
through ``DomestiqueAddon`` -- the mitmproxy addon in
``domestique_app/services/mitm_addon.py`` that inspects browser-intercepted traffic.

Why this exists
----------------
Response scanning used to call ``flow.response.content`` in the
``response()`` hook. Reading ``.content`` forces mitmproxy to buffer the
ENTIRE response before releasing anything to the browser -- which breaks
ChatGPT's token streaming and makes replies feel like they "took too
long." The fix makes response scanning async and non-blocking: the body
streams straight through to the browser via ``flow.response.stream``
(set in the new ``responseheaders()`` hook), while a background task
scans a teed COPY afterward. See the fix report for the full writeup.

How this benchmark proves it
-----------------------------
This drives the REAL addon hooks (``responseheaders`` / ``response``)
against a REAL mitmproxy flow (``mitmproxy.test.tflow`` / ``tutils``) --
not a reimplementation of them -- through a simulated chunked upstream
(many small SSE chunks, each with a short delay, mimicking real
token-by-token generation pace). It does NOT special-case "before" vs
"after": it simply calls whatever hooks the addon currently exposes and
observes the real behavior. That means the exact same, unmodified script
produces the "before" numbers when run against the pre-fix addon (no
``responseheaders`` hook -> mitmproxy would have buffered -> this
benchmark's chunk-delivery loop falls back to buffering the same way)
and the "after" numbers when run against the fixed addon (streaming tee
installed -> each chunk is "delivered" as it arrives) -- see
``run_scenario()``.

Two numbers are reported:

  TTFB          Time from the first upstream byte until the first byte
                would reach the browser. This is what makes ChatGPT feel
                laggy or snappy.
  TOTAL DELIVERY Time until the full reply text has reached the browser
                (independent of any background scan still running).

Usage
-----
    .venv/Scripts/python.exe -m bench.browser_perf.bench_response_streaming
    .venv/Scripts/python.exe -m bench.browser_perf.bench_response_streaming \\
        --chunks 60 --delay-ms 15 --scan-delay-ms 5 --runs 5

To capture a real BEFORE/AFTER comparison, run this once against the
pre-fix commit (e.g. `git stash` the mitm_addon.py change) and once
against the fixed commit -- both invocations use this identical command.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import statistics
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mitmproxy import http as mitm_http
from mitmproxy.test import tflow, tutils

from domestique_app.services.mitm_addon import DomestiqueAddon


# --- Deterministic stub detection pipeline -----------------------------
#
# Mirrors the contract of domestique.detectors.registry.DetectorPipeline
# (async ``inspect(text) -> InspectionResult``) without pulling in
# GLiNER/torch/etc, so the benchmark is fast and has zero external
# dependencies. ``scan_delay_s`` simulates realistic detector latency
# (the regex tier is documented as sub-millisecond; a few ms is a
# generous stand-in). The point this benchmark makes holds regardless of
# scan speed: buffering forces waiting for the ENTIRE upstream body, not
# just for the scan.

class _BenchPipeline:
    def __init__(self, scan_delay_s: float = 0.003):
        self._scan_delay_s = scan_delay_s

    async def inspect(self, text: str):
        from domestique.detectors.registry import Finding, InspectionResult
        from domestique.models import Action

        if self._scan_delay_s:
            await asyncio.sleep(self._scan_delay_s)

        findings = []
        if "123-45-6789" in text:
            findings.append(Finding(detector="bench", category="us_ssn", confidence=0.99))
        if not findings:
            return InspectionResult(action=Action.ALLOW, reason="clean")
        return InspectionResult(action=Action.BLOCK, reason="bench: sensitive content", findings=findings)


def _make_sse_chunks(num_chunks: int, leak_in_last_chunk: bool) -> list[bytes]:
    """Build a ChatGPT-style OpenAI streaming SSE body, split into
    ``num_chunks`` wire chunks (as if the upstream flushed one small
    piece of the reply at a time)."""
    words = ["The ", "quick ", "brown ", "fox ", "jumps ", "over ", "the ", "lazy ", "dog. "]
    chunks = []
    for i in range(num_chunks):
        token = words[i % len(words)]
        if leak_in_last_chunk and i == num_chunks - 1:
            token = "SSN on file: 123-45-6789."
        payload = (
            '{"choices":[{"delta":{"content":%r}}]}' % token
        ).replace("'", '"')
        chunks.append(f"data: {payload}\n\n".encode())
    chunks.append(b"data: [DONE]\n\n")
    return chunks


def _build_flow():
    """A real mitmproxy flow for a ChatGPT-style streaming completion
    request/response, built with mitmproxy's own test helpers (not a
    MagicMock) so the addon's real hook mechanics apply."""
    req = tutils.treq(
        host="api.openai.com",
        method=b"POST",
        path=b"/v1/chat/completions",
        headers=mitm_http.Headers(((b"content-type", b"application/json"),)),
        content=b'{"messages":[{"role":"user","content":"hi"}]}',
    )
    flow = tflow.tflow(req=req)
    flow.response = tutils.tresp(
        headers=mitm_http.Headers(((b"content-type", b"text/event-stream"),)),
        content=b"",
    )
    return flow


def _build_addon(scan_delay_s: float) -> DomestiqueAddon:
    from domestique_app.services.pipeline_config import config_hash, config_mtime_ns, load_config_dict

    addon = DomestiqueAddon()
    addon._detector = _BenchPipeline(scan_delay_s=scan_delay_s)
    # Pin the hot-reload fingerprint so _inspect() doesn't try to rebuild
    # the real (heavy) pipeline from ~/.domestique/config.json mid-benchmark.
    addon._config_mtime = config_mtime_ns()
    addon._config_hash = config_hash(load_config_dict())
    return addon


async def run_scenario(
    addon: DomestiqueAddon,
    *,
    num_chunks: int,
    chunk_delay_s: float,
    leak_in_last_chunk: bool = True,
) -> dict:
    """Drive one simulated streaming response through the addon's real
    hooks and measure delivery timing.

    Calls ``responseheaders()`` if the addon defines it (it does, post-
    fix; it doesn't, pre-fix -- this is what makes the same function
    produce correct before/after numbers with no special-casing). Then
    feeds simulated upstream chunks one at a time, respecting
    ``chunk_delay_s`` between arrivals, exactly mirroring mitmproxy's own
    per-chunk state machine (see ``proxy/layers/http/__init__.py``,
    ``state_stream_response_body`` / ``state_consume_response_body``):
    if ``flow.response.stream`` is a callable, each chunk is "delivered"
    to the browser as soon as it arrives (its return value is what
    mitmproxy would forward immediately); otherwise chunks are buffered
    and NOTHING is delivered until the full body is assembled and the
    ``response()`` hook has resolved.
    """
    flow = _build_flow()

    responseheaders_hook = getattr(addon, "responseheaders", None)
    start = time.perf_counter()
    if responseheaders_hook is not None:
        result = responseheaders_hook(flow)
        if inspect.isawaitable(result):
            await result

    chunks = _make_sse_chunks(num_chunks, leak_in_last_chunk=leak_in_last_chunk)
    buffered = bytearray()
    delivery_offsets_s: list[float] = []

    for chunk in chunks:
        await asyncio.sleep(chunk_delay_s)
        stream_cb = getattr(flow.response, "stream", False)
        if callable(stream_cb):
            stream_cb(chunk)
            delivery_offsets_s.append(time.perf_counter() - start)
        else:
            buffered.extend(chunk)

    stream_cb = getattr(flow.response, "stream", False)
    streamed = callable(stream_cb)
    if streamed:
        stream_cb(b"")  # mitmproxy calls the stream callable once more, empty, at end-of-body
    else:
        flow.response.content = bytes(buffered)

    # response(): for the streamed case this only schedules a background
    # scan and must return immediately (nothing left for it to gate --
    # the bytes above are already "with the browser"). For the buffered
    # case, this call IS the scan, and only once it resolves would
    # mitmproxy release anything to the client -- so the release happens
    # AFTER this line, all at once.
    await addon.response(flow)
    if not streamed:
        delivery_offsets_s = [time.perf_counter() - start]

    # Let any background scan task run to completion so we can report how
    # long it took -- purely informational, it never gated delivery above.
    pending = [
        t for t in asyncio.all_tasks()
        if not t.done() and t is not asyncio.current_task()
    ]
    if pending:
        await asyncio.gather(*pending)
    scan_complete_s = time.perf_counter() - start

    return {
        "streamed": streamed,
        "ttfb_s": delivery_offsets_s[0] if delivery_offsets_s else scan_complete_s,
        "total_delivery_s": delivery_offsets_s[-1] if delivery_offsets_s else scan_complete_s,
        "scan_complete_s": scan_complete_s,
        "response_alerts": addon._stats.get("response_alerts", 0),
    }


async def run_benchmark(*, num_chunks: int, chunk_delay_s: float, scan_delay_s: float, runs: int) -> dict:
    fake_ctx = SimpleNamespace(log=SimpleNamespace(
        info=lambda *a, **k: None, warn=lambda *a, **k: None,
        error=lambda *a, **k: None, debug=lambda *a, **k: None,
    ))
    results = []
    with patch("domestique_app.services.mitm_addon.ctx", fake_ctx):
        addon = _build_addon(scan_delay_s)
        for _ in range(runs):
            results.append(
                await run_scenario(addon, num_chunks=num_chunks, chunk_delay_s=chunk_delay_s)
            )

    streamed = results[0]["streamed"]
    ttfb = [r["ttfb_s"] for r in results]
    total = [r["total_delivery_s"] for r in results]
    scan = [r["scan_complete_s"] for r in results]
    return {
        "streamed": streamed,
        "runs": runs,
        "ttfb_ms": {"mean": statistics.mean(ttfb) * 1000, "min": min(ttfb) * 1000, "max": max(ttfb) * 1000},
        "total_delivery_ms": {"mean": statistics.mean(total) * 1000, "min": min(total) * 1000, "max": max(total) * 1000},
        "scan_complete_ms": {"mean": statistics.mean(scan) * 1000},
        "response_alerts_seen": results[-1]["response_alerts"],
    }


def _print_report(stats: dict, *, num_chunks: int, chunk_delay_s: float, scan_delay_s: float) -> None:
    mode = "STREAMED (async, non-blocking)" if stats["streamed"] else "BUFFERED (pre-fix / legacy)"
    print("=" * 72)
    print("Browser-mode response-scanning perf benchmark")
    print("=" * 72)
    print(f"Simulated upstream: {num_chunks} SSE chunks, {chunk_delay_s * 1000:.1f}ms apart "
          f"(~{num_chunks * chunk_delay_s * 1000:.0f}ms full reply)")
    print(f"Simulated scan cost per response: {scan_delay_s * 1000:.1f}ms")
    print(f"Runs averaged: {stats['runs']}")
    print(f"Detected response-scanning mode: {mode}")
    print("-" * 72)
    t = stats["ttfb_ms"]
    d = stats["total_delivery_ms"]
    s = stats["scan_complete_ms"]
    print(f"TTFB (time to first byte reaching the browser):")
    print(f"    mean={t['mean']:.1f}ms  min={t['min']:.1f}ms  max={t['max']:.1f}ms")
    print(f"TOTAL DELIVERY (full reply text reaches the browser):")
    print(f"    mean={d['mean']:.1f}ms  min={d['min']:.1f}ms  max={d['max']:.1f}ms")
    print(f"Background scan wall-clock (informational only -- never gates delivery above):")
    print(f"    mean={s['mean']:.1f}ms")
    print(f"Response leaks detected across runs: {stats['response_alerts_seen']}")
    print("=" * 72)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chunks", type=int, default=40, help="Number of simulated SSE chunks (default: 40)")
    parser.add_argument("--delay-ms", type=float, default=12.0, help="Delay between chunks in ms (default: 12, ~ChatGPT token pace)")
    parser.add_argument("--scan-delay-ms", type=float, default=3.0, help="Simulated detector scan cost in ms (default: 3)")
    parser.add_argument("--runs", type=int, default=5, help="Number of runs to average (default: 5)")
    args = parser.parse_args()

    stats = asyncio.run(run_benchmark(
        num_chunks=args.chunks,
        chunk_delay_s=args.delay_ms / 1000.0,
        scan_delay_s=args.scan_delay_ms / 1000.0,
        runs=args.runs,
    ))
    _print_report(stats, num_chunks=args.chunks, chunk_delay_s=args.delay_ms / 1000.0, scan_delay_s=args.scan_delay_ms / 1000.0)


if __name__ == "__main__":
    main()
