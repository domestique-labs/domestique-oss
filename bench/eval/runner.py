from __future__ import annotations

import os
import time
from dataclasses import dataclass

import httpx

from bench.eval.corpus import CorpusRow
from bench.eval.mock_upstream import MockUpstreamHandle, running_mock, serve


@dataclass(frozen=True)
class Observation:
    row_id: str
    observed_action: str
    status_code: int
    latency_ms: float


def classify_action(status_code: int, sent_text: str, upstream_text: str | None) -> str:
    """Map the HTTP-boundary evidence to a verdict (language-agnostic)."""
    if status_code == 403:
        return "block"
    if status_code == 200:
        if upstream_text is None:
            return "block"  # nothing reached upstream despite 200 → treat as blocked
        return "allow" if upstream_text == sent_text else "redact"
    raise RuntimeError(f"unexpected firewall status {status_code}")


def _configure_determinism(handle: MockUpstreamHandle) -> None:
    # litellm/openai read either of these for the upstream base URL.
    os.environ["OPENAI_API_BASE"] = handle.base_url
    os.environ["OPENAI_BASE_URL"] = handle.base_url
    os.environ["OPENAI_API_KEY"] = "sk-test"
    os.environ["LLMGUARD_OPENAI_API_KEY"] = "sk-test"
    os.environ["LLMGUARD_FAIL_MODE"] = "closed"
    os.environ["PYTHONHASHSEED"] = "0"


def observe_corpus(rows: list[CorpusRow]) -> tuple[list[Observation], dict[str, str]]:
    observations: list[Observation] = []
    observed: dict[str, str] = {}

    with running_mock() as handle:
        # Env must be set BEFORE create_app/Settings/LLMProxy read it.
        _configure_determinism(handle)
        # Import after env is set so litellm/Settings pick up the mock upstream.
        from llmguard.app import create_app
        from llmguard.config import Settings

        firewall_app = create_app(Settings())  # detector flags default False → regex-only gate
        with serve(firewall_app) as fw_url:
            with httpx.Client(base_url=fw_url, timeout=30) as client:
                for row in rows:
                    before = len(handle.mock.received)
                    payload = {"model": "gpt-4o-mini",
                               "messages": [{"role": "user", "content": row.text}]}
                    t0 = time.perf_counter()
                    resp = client.post("/v1/chat/completions", json=payload)
                    latency_ms = (time.perf_counter() - t0) * 1000
                    upstream_text: str | None = None
                    if len(handle.mock.received) > before:
                        body = handle.mock.received[-1]
                        upstream_text = body["messages"][-1]["content"]
                    action = classify_action(resp.status_code, row.text, upstream_text)
                    observations.append(
                        Observation(row.id, action, resp.status_code, round(latency_ms, 3))
                    )
                    observed[row.id] = action

    return observations, observed
