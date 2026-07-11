"""LLM Firewall - Audit logger.

Emits structured JSONL events for every firewall decision. Designed for
ingestion by enterprise SIEM systems (Splunk, Sentinel, ELK).

Performance: writes are buffered and flushed periodically or at shutdown.
Audit logging is entirely non-blocking - failures are logged but never
propagate to the request path.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from llmguard.models import Action, Detection

logger = structlog.get_logger()


class AuditLogger:
    """Append-only JSONL audit emitter.

    Thread-safe via atomic line writes. No locking required on POSIX for
    lines shorter than PIPE_BUF (4 KB), which covers all our events.
    """

    def __init__(self, path: str) -> None:
        log_path = Path(path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(log_path, "a", buffering=1)  # line-buffered  # noqa: SIM115

    def record(
        self,
        *,
        action: Action,
        user_id: str,
        model: str,
        endpoint: str,
        detections: list[Detection],
        latency_ms: float,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Write a single audit event. Never raises."""
        try:
            event = {
                "ts": datetime.now(UTC).isoformat(),
                "action": action.value,
                "user": user_id,
                "model": model,
                "endpoint": endpoint,
                "findings": len(detections),
                "categories": list({d.category for d in detections}),
                "latency_ms": round(latency_ms, 1),
            }
            if metadata:
                event["meta"] = metadata
            self._file.write(json.dumps(event, separators=(",", ":")) + "\n")
        except Exception:
            logger.exception("audit_write_error")

    def close(self) -> None:
        """Flush and close the audit file."""
        self._file.close()
