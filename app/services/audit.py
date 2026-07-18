"""Audit logging with structured events, rotation, and retention.

Provides a comprehensive audit trail for compliance (SOC 2, HIPAA, GDPR Art 30):
- Structured JSON events with UUID request IDs
- SQLite persistence for efficient querying and retention
- JSONL file output for SIEM ingestion
- Configurable log rotation and retention policies
- Non-blocking writes via buffered queue
- Thread-safe for concurrent proxy handlers

Architecture:
    Request path -> AuditEvent created -> enqueued to background writer
    Background writer -> SQLite INSERT + JSONL append (non-blocking to caller)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from queue import Full, Queue
from typing import Any

logger = logging.getLogger("domestique.audit")


class AuditAction(Enum):
    """Actions the firewall can take on a request."""

    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    ERROR = "error"


class AuditSeverity(Enum):
    """Severity levels for audit events."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class AuditEvent:
    """A single audit event representing one firewall decision.

    Immutable and serializable. Contains all fields needed for
    compliance reporting and SIEM ingestion.
    """

    request_id: str
    timestamp: str
    action: str
    severity: str
    user: str
    source_ip: str
    destination: str
    method: str
    path: str
    detectors_triggered: list[str]
    pii_categories: list[str]
    latency_ms: float
    model_requested: str
    content_length: int
    content_preview: str
    proxy_mode: str  # "browser" or "api"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize to compact JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))


@dataclass
class RetentionPolicy:
    """Configuration for audit log retention."""

    max_age_days: int = 90
    max_size_mb: int = 500
    max_events: int = 1_000_000
    rotation_check_interval: int = 3600  # seconds


class AuditStore:
    """SQLite-backed audit event store with JSONL mirror.

    Provides:
    - Durable storage with ACID guarantees
    - Efficient querying by time, action, destination, etc.
    - JSONL file for SIEM forwarders to tail
    - Automatic rotation and retention enforcement

    Thread-safe: uses a background writer thread with a bounded queue.
    Callers never block on disk I/O.
    """

    QUEUE_MAX = 10_000
    FLUSH_INTERVAL = 1.0  # seconds

    def __init__(
        self,
        data_dir: Path | None = None,
        retention: RetentionPolicy | None = None,
    ) -> None:
        self._data_dir = data_dir or (Path.home() / ".domestique" / "audit")
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._retention = retention or RetentionPolicy()
        self._queue: Queue[AuditEvent | None] = Queue(maxsize=self.QUEUE_MAX)
        self._running = False
        self._writer_thread: threading.Thread | None = None
        self._db_path = self._data_dir / "audit.db"
        self._jsonl_path = self._data_dir / "events.jsonl"
        self._last_rotation_check = 0.0
        self._lock = threading.Lock()
        self._event_count = 0

    def start(self) -> None:
        """Start the background writer thread."""
        if self._running:
            return
        self._running = True
        self._init_db()
        self._writer_thread = threading.Thread(
            target=self._writer_loop, daemon=True, name="audit-writer"
        )
        self._writer_thread.start()
        logger.info(f"Audit store started: {self._data_dir}")

    def stop(self) -> None:
        """Flush remaining events and stop the writer."""
        if not self._running:
            return
        self._running = False
        # Signal writer to exit
        self._queue.put(None)
        if self._writer_thread:
            self._writer_thread.join(timeout=5.0)
        logger.info("Audit store stopped")

    def record(self, event: AuditEvent) -> None:
        """Enqueue an audit event for writing. Never blocks or raises."""
        if not self._running:
            return
        try:
            self._queue.put_nowait(event)
        except Full:
            logger.warning("Audit queue full - dropping event")

    def query(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        action: AuditAction | None = None,
        destination: str | None = None,
        user: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query audit events from SQLite store.

        Args:
            since: Start time filter (inclusive).
            until: End time filter (exclusive).
            action: Filter by action type.
            destination: Filter by destination host (exact or LIKE).
            user: Filter by user identifier.
            limit: Maximum results to return.
            offset: Pagination offset.

        Returns:
            List of event dictionaries, ordered by timestamp descending.
        """
        conditions = []
        params: list[Any] = []

        if since:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())
        if until:
            conditions.append("timestamp < ?")
            params.append(until.isoformat())
        if action:
            conditions.append("action = ?")
            params.append(action.value)
        if destination:
            if "%" in destination:
                conditions.append("destination LIKE ?")
            else:
                conditions.append("destination = ?")
            params.append(destination)
        if user:
            conditions.append("user = ?")
            params.append(user)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        # noqa justification: `where` is assembled only from hardcoded condition
        # fragments (e.g. "user = ?"); all user values are bound via ? params below.
        sql = f"SELECT * FROM audit_events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"  # noqa: S608
        params.extend([limit, offset])

        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_stats(
        self,
        since: datetime | None = None,
    ) -> dict[str, Any]:
        """Get aggregate statistics from the audit store.

        Returns counts by action, top destinations, and event volume.
        """
        if not since:
            since = datetime.now(UTC) - timedelta(hours=24)

        conn = sqlite3.connect(str(self._db_path))
        try:
            # Action counts
            rows = conn.execute(
                "SELECT action, COUNT(*) as cnt FROM audit_events "
                "WHERE timestamp >= ? GROUP BY action",
                (since.isoformat(),),
            ).fetchall()
            action_counts = {row[0]: row[1] for row in rows}

            # Top blocked destinations
            top_blocked = conn.execute(
                "SELECT destination, COUNT(*) as cnt FROM audit_events "
                "WHERE timestamp >= ? AND action = 'block' "
                "GROUP BY destination ORDER BY cnt DESC LIMIT 10",
                (since.isoformat(),),
            ).fetchall()

            # Top PII categories
            top_categories = conn.execute(
                "SELECT pii_categories, COUNT(*) as cnt FROM audit_events "
                "WHERE timestamp >= ? AND action IN ('block', 'redact') "
                "GROUP BY pii_categories ORDER BY cnt DESC LIMIT 10",
                (since.isoformat(),),
            ).fetchall()

            # Average latency
            avg_latency = conn.execute(
                "SELECT AVG(latency_ms) FROM audit_events WHERE timestamp >= ?",
                (since.isoformat(),),
            ).fetchone()

            return {
                "period_start": since.isoformat(),
                "action_counts": action_counts,
                "top_blocked_destinations": [
                    {"destination": r[0], "count": r[1]} for r in top_blocked
                ],
                "top_pii_categories": [
                    {"categories": r[0], "count": r[1]} for r in top_categories
                ],
                "avg_latency_ms": round(avg_latency[0] or 0, 2),
                "total_events": sum(action_counts.values()),
            }
        finally:
            conn.close()

    @property
    def event_count(self) -> int:
        """Total events written since start."""
        return self._event_count

    # --- Internal ----------------------------------------------------

    def _init_db(self) -> None:
        """Create the SQLite schema if it doesn't exist."""
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                request_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                severity TEXT NOT NULL,
                user TEXT,
                source_ip TEXT,
                destination TEXT NOT NULL,
                method TEXT,
                path TEXT,
                detectors_triggered TEXT,
                pii_categories TEXT,
                latency_ms REAL,
                model_requested TEXT,
                content_length INTEGER,
                content_preview TEXT,
                proxy_mode TEXT,
                metadata TEXT
            )
        """)
        # Indexes for common query patterns
        conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_action ON audit_events(action)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_destination ON audit_events(destination)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_user ON audit_events(user)")
        conn.commit()
        conn.close()

    def _writer_loop(self) -> None:
        """Background thread that drains the queue and writes to storage."""
        batch: list[AuditEvent] = []
        last_flush = time.time()

        while self._running or not self._queue.empty():
            try:
                event = self._queue.get(timeout=self.FLUSH_INTERVAL)
                if event is None:
                    break  # Shutdown signal
                batch.append(event)
            except Exception:  # noqa: S110
                pass  # Queue.get timeout - flush what we have

            # Flush batch if interval elapsed or batch is large
            now = time.time()
            if batch and (now - last_flush >= self.FLUSH_INTERVAL or len(batch) >= 50):
                self._flush_batch(batch)
                batch = []
                last_flush = now

        # Final flush on shutdown
        if batch:
            self._flush_batch(batch)

    def _flush_batch(self, batch: list[AuditEvent]) -> None:
        """Write a batch of events to SQLite and JSONL."""
        if not batch:
            return

        try:
            # SQLite batch insert
            conn = sqlite3.connect(str(self._db_path))
            conn.executemany(
                """INSERT OR IGNORE INTO audit_events
                   (request_id, timestamp, action, severity, user, source_ip,
                    destination, method, path, detectors_triggered,
                    pii_categories, latency_ms, model_requested,
                    content_length, content_preview, proxy_mode, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        e.request_id,
                        e.timestamp,
                        e.action,
                        e.severity,
                        e.user,
                        e.source_ip,
                        e.destination,
                        e.method,
                        e.path,
                        json.dumps(e.detectors_triggered),
                        json.dumps(e.pii_categories),
                        e.latency_ms,
                        e.model_requested,
                        e.content_length,
                        e.content_preview,
                        e.proxy_mode,
                        json.dumps(e.metadata) if e.metadata else None,
                    )
                    for e in batch
                ],
            )
            conn.commit()
            conn.close()

            # JSONL append (for SIEM tailing)
            with open(self._jsonl_path, "a") as f:
                for event in batch:
                    f.write(event.to_json() + "\n")

            self._event_count += len(batch)
            logger.debug(f"Flushed {len(batch)} audit events")

        except Exception as e:
            logger.error(f"Failed to flush audit batch: {e}")

        # Periodic rotation check
        now = time.time()
        if now - self._last_rotation_check > self._retention.rotation_check_interval:
            self._last_rotation_check = now
            self._enforce_retention()

    def _enforce_retention(self) -> None:
        """Apply retention policy: delete old events, rotate files."""
        try:
            conn = sqlite3.connect(str(self._db_path))

            # Delete events older than max_age_days
            cutoff = (datetime.now(UTC) - timedelta(days=self._retention.max_age_days)).isoformat()
            conn.execute("DELETE FROM audit_events WHERE timestamp < ?", (cutoff,))

            # Enforce max_events
            count = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            if count > self._retention.max_events:
                excess = count - self._retention.max_events
                conn.execute(
                    "DELETE FROM audit_events WHERE request_id IN "
                    "(SELECT request_id FROM audit_events ORDER BY timestamp ASC LIMIT ?)",
                    (excess,),
                )

            conn.execute("PRAGMA optimize")
            conn.commit()
            conn.close()

            # Rotate JSONL if too large
            if self._jsonl_path.exists():
                size_mb = self._jsonl_path.stat().st_size / (1024 * 1024)
                if size_mb > self._retention.max_size_mb / 2:
                    rotated = self._jsonl_path.with_suffix(".jsonl.1")
                    if rotated.exists():
                        rotated.unlink()
                    self._jsonl_path.rename(rotated)
                    logger.info(f"Rotated audit JSONL ({size_mb:.1f} MB)")

        except Exception as e:
            logger.error(f"Retention enforcement failed: {e}")


def create_audit_event(
    *,
    action: AuditAction,
    destination: str,
    method: str = "POST",
    path: str = "",
    detectors: list[str] | None = None,
    categories: list[str] | None = None,
    latency_ms: float = 0.0,
    model: str = "",
    content_length: int = 0,
    content_preview: str = "",
    proxy_mode: str = "browser",
    user: str = "local",
    source_ip: str = "127.0.0.1",
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    """Factory function to create an AuditEvent with defaults.

    Simplifies event creation for common cases.
    """
    severity = AuditSeverity.INFO
    if action == AuditAction.BLOCK:
        severity = AuditSeverity.CRITICAL
    elif action == AuditAction.REDACT:
        severity = AuditSeverity.WARNING

    return AuditEvent(
        request_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC).isoformat(),
        action=action.value,
        severity=severity.value,
        user=user,
        source_ip=source_ip,
        destination=destination,
        method=method,
        path=path,
        detectors_triggered=detectors or [],
        pii_categories=categories or [],
        latency_ms=latency_ms,
        model_requested=model,
        content_length=content_length,
        content_preview=content_preview,
        proxy_mode=proxy_mode,
        metadata=metadata or {},
    )


# --- Module-level singleton ---------------------------------------------

_global_store: AuditStore | None = None
_store_lock = threading.Lock()


def get_audit_store() -> AuditStore:
    """Get or create the global audit store singleton.

    Lazily initializes and starts the background writer on first access.
    """
    global _global_store
    if _global_store is None:
        with _store_lock:
            if _global_store is None:
                _global_store = AuditStore()
                _global_store.start()
    return _global_store


def shutdown_audit() -> None:
    """Gracefully shut down the global audit store."""
    global _global_store
    if _global_store:
        _global_store.stop()
        _global_store = None
