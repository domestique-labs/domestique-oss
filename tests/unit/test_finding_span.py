from __future__ import annotations

import asyncio

from domestique.config import Settings
from domestique.detectors.registry import DetectorPipeline, build_detectors
from domestique.models import Span
from domestique.policy import PolicyEngine


def test_inspect_populates_finding_span() -> None:
    pipe = DetectorPipeline(build_detectors(Settings()), PolicyEngine.from_yaml_default())
    text = "my key AKIAIOSFODNN7EXAMPLE end"
    result = asyncio.run(pipe.inspect(text))
    assert result.findings, "expected at least one finding"
    f = result.findings[0]
    assert isinstance(f.span, Span)
    # the span must point at the leaked substring in the original text
    assert text[f.span.start : f.span.end] == "AKIAIOSFODNN7EXAMPLE"


def test_finding_span_defaults_to_none() -> None:
    from domestique.detectors.registry import Finding

    assert Finding(detector="d", category="c", confidence=0.9).span is None
