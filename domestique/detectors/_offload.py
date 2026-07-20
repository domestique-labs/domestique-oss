"""Keep CPU-bound detector work off the asyncio event loop.

Several detectors declare ``async def scan()`` but do entirely synchronous
work in the body. A coroutine that never awaits runs to completion without
yielding, so ``asyncio.gather`` over such detectors does not overlap them and
the event loop cannot serve anything else -- streaming relays, other in-flight
requests, the dashboard API -- until the scan returns.

Offloading to a worker thread fixes that **only for detectors whose heavy
work releases the GIL.** This distinction is the whole reason this module is
small and opinionated rather than a blanket "wrap every scan" helper.

Measured with ``benchmarks/concurrency`` (64 KB input, macOS, CPython 3.12),
event-loop availability while N scans run concurrently:

    work in the worker thread          N=1     N=4    N=16
    ---------------------------------------------------------
    GIL-holding (CPython ``re``)      100%     25%     6%
    GIL-releasing (native/BLAS)        92%     88%    88%

Wall-clock for the GIL-releasing case stayed flat (13.8 ms -> 17.1 ms from
N=1 to N=16), i.e. real parallelism. The GIL-holding case scaled linearly
(1.7 ms -> 17.4 ms): threads bought nothing.

So:

* **Offload** Presidio/spaCy, GLiNER/PyTorch, sentence-transformers. Their
  inference is native code that drops the GIL, so worker threads deliver both
  loop relief and genuine overlap.
* **Do not offload** the regex/entropy tiers. ``re.finditer`` over a large
  string is a single C call with no bytecode boundaries, so the worker thread
  holds the GIL end-to-end and the loop stalls exactly as it did inline --
  now with an extra ~31 us hop per call. Relieving that tier requires
  yielding between bounded chunks, which is a correctness-sensitive change
  for a security control and is tracked separately.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

_T = TypeVar("_T")


async def offload(fn: Callable[[], _T]) -> _T:
    """Run *fn* on a worker thread.

    Intended for detectors backed by native, GIL-releasing libraries. Do not
    use it to wrap pure-Python or ``re`` work: see the module docstring for
    why that is measurably pointless.
    """
    return await asyncio.to_thread(fn)
