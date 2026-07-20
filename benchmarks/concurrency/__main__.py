"""Measure event-loop responsiveness while the detector pipeline scans.

Why this exists
---------------
``benchmarks/eval`` is a *correctness* harness: it drives one request at a
time through the proxy and scores detection quality. It cannot observe the
failure mode measured here, because that failure mode only appears under
concurrency.

The detectors expose ``async def scan()`` but several do purely synchronous
CPU work in the coroutine body. A coroutine that never awaits runs to
completion without yielding, so ``asyncio.gather`` over such detectors does
not overlap them -- and the event loop is frozen for the duration. Every
other in-flight request (streaming relays, the dashboard API) stalls behind
it.

The headline metric is **loop availability**: a heartbeat coroutine ticks
every 1 ms while scans run, and we report observed ticks as a percentage of
the ticks the wall clock allowed. 100% means the loop stayed responsive; 5%
means it was starved.

Three profiles run, and the contrast between them is the point:

``regex-inline``
    The real ``SecretDetector``. Pure ``re`` work, run on the loop thread.

``native-inline``
    A stand-in for Presidio/GLiNER: blocking work that *releases* the GIL,
    run on the loop thread. The control case.

``native-offload``
    The same GIL-releasing work routed through ``detectors._offload.offload``.

``native-offload`` should hold high availability and near-flat wall clock as
concurrency rises -- that is real parallelism, and it is why the ML tiers are
offloaded. Offloading ``regex-inline`` was measured and deliberately NOT
adopted: CPython's ``re`` holds the GIL inside a single C call, so a worker
thread cannot relieve the loop. See ``domestique/detectors/_offload.py``.

Usage::

    python -m benchmarks.concurrency
    python -m benchmarks.concurrency --tasks 1 4 16 --json out.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from domestique.detectors._offload import offload
from domestique.detectors.secrets import SecretDetector

_HEARTBEAT_INTERVAL_S = 0.001

# Chosen so one scan costs a few milliseconds -- the same order as a real
# Presidio analyse call, which is what this profile stands in for.
_NATIVE_WORK_S = 0.013


@dataclass(frozen=True)
class Result:
    profile: str
    tasks: int
    wall_ms: float
    loop_availability_pct: float
    stall_max_ms: float
    heartbeats: int
    expected_heartbeats: int


def build_text(chars: int) -> str:
    """Benign filler with no secrets, so the scan walks the whole string.

    A planted secret could let a scan exit early and make the measurement
    depend on where the match landed.
    """
    base = "The quick brown fox jumps over the lazy dog. Please review the attached notes. "
    return (base * (chars // len(base) + 1))[:chars]


def _native_blocking_work() -> list[None]:
    """Blocking work that releases the GIL, standing in for native ML libs.

    ``time.sleep`` drops the GIL exactly as Presidio/spaCy and GLiNER/PyTorch
    do during native inference. Using a real model here would make the
    benchmark depend on the heavy ``[pii]``/``[ner]`` extras.
    """
    time.sleep(_NATIVE_WORK_S)
    return []


class _Heartbeat:
    """Ticks on a fixed interval; records how late each tick actually was."""

    def __init__(self) -> None:
        self.gaps_ms: list[float] = []
        self._stop = False

    async def run(self) -> None:
        last = time.perf_counter()
        while not self._stop:
            await asyncio.sleep(_HEARTBEAT_INTERVAL_S)
            now = time.perf_counter()
            # Subtract the interval we asked for; what remains is delay
            # attributable to the loop being unable to reschedule us.
            self.gaps_ms.append(max(0.0, (now - last - _HEARTBEAT_INTERVAL_S) * 1000))
            last = now

    def stop(self) -> None:
        self._stop = True


async def _probe(profile: str, make_scan, tasks: int) -> Result:
    heartbeat = _Heartbeat()
    hb_task = asyncio.create_task(heartbeat.run())
    await asyncio.sleep(0.02)  # let the heartbeat establish a clean baseline
    heartbeat.gaps_ms.clear()

    t0 = time.perf_counter()
    await asyncio.gather(*(make_scan() for _ in range(tasks)))
    wall_ms = (time.perf_counter() - t0) * 1000

    heartbeat.stop()
    hb_task.cancel()
    try:
        await hb_task
    except asyncio.CancelledError:
        pass

    expected = max(1, int(wall_ms / (_HEARTBEAT_INTERVAL_S * 1000)))
    # When the loop is starved hard enough the heartbeat never ticks at all.
    # Reporting max(gaps, default=0) would then read as "no stall", which is
    # exactly backwards -- the loop was frozen for the whole run.
    stall_max = max(heartbeat.gaps_ms) if heartbeat.gaps_ms else wall_ms
    return Result(
        profile=profile,
        tasks=tasks,
        wall_ms=round(wall_ms, 2),
        loop_availability_pct=round(100.0 * len(heartbeat.gaps_ms) / expected, 1),
        stall_max_ms=round(stall_max, 2),
        heartbeats=len(heartbeat.gaps_ms),
        expected_heartbeats=expected,
    )


async def run_all(task_counts: list[int], chars: int) -> list[Result]:
    detector = SecretDetector()
    text = build_text(chars)
    await detector.scan(text[:512])  # warm the regex cache

    profiles = {
        "regex-inline": lambda: detector.scan(text),
        "native-inline": lambda: _as_coro(_native_blocking_work),
        "native-offload": lambda: offload(_native_blocking_work),
    }

    results: list[Result] = []
    for name, make_scan in profiles.items():
        for n in task_counts:
            results.append(await _probe(name, make_scan, n))
    return results


async def _as_coro(fn):
    """Call *fn* inline on the loop thread, matching the awaitable shape."""
    return fn()


def main() -> int:
    parser = argparse.ArgumentParser(prog="benchmarks.concurrency")
    parser.add_argument("--tasks", type=int, nargs="+", default=[1, 4, 16])
    parser.add_argument("--chars", type=int, default=65536)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()

    results = asyncio.run(run_all(args.tasks, args.chars))

    print(f"text = {args.chars} chars    heartbeat = {_HEARTBEAT_INTERVAL_S * 1000:.0f} ms\n")
    print(f"{'profile':16} {'tasks':>5} {'wall_ms':>9} {'loop_avail':>11} {'max_stall_ms':>13}")
    print("-" * 58)
    last_profile = None
    for r in results:
        if last_profile and r.profile != last_profile:
            print()
        print(
            f"{r.profile:16} {r.tasks:>5} {r.wall_ms:>9.1f} "
            f"{r.loop_availability_pct:>10.1f}% {r.stall_max_ms:>13.1f}"
        )
        last_profile = r.profile

    print(
        "\nHigher loop_avail is better. native-offload should stay high with "
        "near-flat\nwall_ms as tasks rise; regex-inline degrades because "
        "CPython's re holds the GIL."
    )

    if args.json:
        args.json.write_text(
            json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8"
        )
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
