"""LLM Firewall - Detector protocol and base types.

Every detector implements the ``Detector`` protocol. This allows the pipeline
to run all detectors in parallel without caring about internals.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from llmguard.models import Detection


@runtime_checkable
class Detector(Protocol):
    """Interface that all content detectors must satisfy.

    Detectors are stateless after initialization. The ``scan`` method is
    called concurrently for every text field in a request - implementations
    must be safe for concurrent use (no shared mutable state).
    """

    @property
    def name(self) -> str:
        """Unique identifier for this detector (e.g. ``secret_scanner``)."""
        ...

    async def scan(self, text: str) -> list[Detection]:
        """Scan *text* and return zero or more findings.

        Must complete quickly (target < 2 ms for regex detectors, < 10 ms for
        NLP detectors). Heavy models should be loaded once at startup.
        """
        ...
