"""Tests for wedge live feedback + metadata-only audit logging (UX-1)."""

from __future__ import annotations

import httpx

from domestique.detectors.registry import Finding, InspectionResult
from domestique.gateway import _scan_and_redact, build_cli_pipeline, create_gateway
from domestique.models import Action
from domestique.report import aggregate, default_audit_path, load_events
from benchmarks.eval.mock_upstream import serve

_AWS = "key AKIAIOSFODNN7EXAMPLE"


class _StubPipeline:
    """Minimal DetectorPipeline stand-in returning a fixed verdict."""

    def __init__(self, result: InspectionResult) -> None:
        self._result = result

    @property
    def policy(self) -> object:
        return object()

    async def inspect(self, text: str) -> InspectionResult:
        return self._result


async def test_scan_and_redact_returns_driving_categories() -> None:
    pipeline = build_cli_pipeline()
    body = {"model": "m", "messages": [{"role": "user", "content": _AWS}]}
    action, _reason, _out, categories = await _scan_and_redact(pipeline, body, "openai_chat")
    assert action is Action.REDACT
    assert "aws_access_key" in categories


def test_on_decision_called_on_redact(mock_openai) -> None:
    calls: list[tuple] = []
    app = create_gateway(on_decision=lambda a, c, h: calls.append((a, c, h)))
    with serve(app) as gw:
        httpx.post(
            f"{gw}/v1/chat/completions",
            headers={"Authorization": "Bearer sk"},
            json={"model": "m", "messages": [{"role": "user", "content": _AWS}]},
        )
    assert calls, "on_decision was never invoked"
    action, categories, host = calls[-1]
    assert action is Action.REDACT
    assert "aws_access_key" in categories
    assert isinstance(host, str) and host


def test_audit_event_written_on_redact(mock_openai) -> None:
    app = create_gateway()
    with serve(app) as gw:
        httpx.post(
            f"{gw}/v1/chat/completions",
            headers={"Authorization": "Bearer sk"},
            json={"model": "m", "messages": [{"role": "user", "content": _AWS}]},
        )
    data = aggregate(load_events(default_audit_path()))
    assert data.by_category.get("aws_access_key", {}).get("redact", 0) >= 1


def test_audit_log_never_contains_raw_prompt_text(mock_openai) -> None:
    app = create_gateway()
    with serve(app) as gw:
        httpx.post(
            f"{gw}/v1/chat/completions",
            headers={"Authorization": "Bearer sk"},
            json={"model": "m", "messages": [{"role": "user", "content": _AWS}]},
        )
    raw = default_audit_path().read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in raw


def test_block_notifies_and_logs(mock_openai) -> None:
    result = InspectionResult(
        action=Action.BLOCK,
        reason="private key",
        findings=[Finding(detector="secret_scanner", category="private_key", confidence=1.0)],
    )
    calls: list[tuple] = []
    app = create_gateway(
        pipeline=_StubPipeline(result),
        on_decision=lambda a, c, h: calls.append((a, c, h)),
    )
    with serve(app) as gw:
        resp = httpx.post(
            f"{gw}/v1/chat/completions",
            headers={"Authorization": "Bearer sk"},
            json={"model": "m", "messages": [{"role": "user", "content": "anything"}]},
        )
    assert resp.status_code == 403
    assert calls[-1][0] is Action.BLOCK
    assert "private_key" in calls[-1][1]
    data = aggregate(load_events(default_audit_path()))
    assert data.by_category.get("private_key", {}).get("block", 0) >= 1


def test_clean_prompt_does_not_notify_or_log(mock_openai) -> None:
    calls: list[tuple] = []
    app = create_gateway(on_decision=lambda *a: calls.append(a))
    with serve(app) as gw:
        httpx.post(
            f"{gw}/v1/chat/completions",
            headers={"Authorization": "Bearer sk"},
            json={"model": "m", "messages": [{"role": "user", "content": "hello clean"}]},
        )
    assert calls == []
    assert load_events(default_audit_path()) == []
