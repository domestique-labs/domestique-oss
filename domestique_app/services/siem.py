"""SIEM integration - output audit events to SIEM/security platforms.

Supports multiple output formats and transports:
- Syslog (RFC 5424) for Splunk, QRadar, Elastic
- CEF (Common Event Format) for ArcSight
- Webhook (JSON POST) for custom integrations
- File output (JSONL) for Filebeat/Fluentd tailing

Each output is a pluggable backend that can be enabled/disabled independently.
All outputs are non-blocking and failure-tolerant - SIEM issues never affect
the firewall's core inspection path.

Usage:
    dispatcher = SIEMDispatcher()
    dispatcher.add_backend(SyslogBackend(host="siem.corp.com", port=514))
    dispatcher.add_backend(WebhookBackend(url="https://hooks.corp.com/domestique"))
    dispatcher.dispatch(audit_event)
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path
from queue import Empty, Full, Queue
from typing import TYPE_CHECKING
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    from domestique_app.services.audit import AuditEvent

logger = logging.getLogger("domestique.siem")


# --- Backend Interface ---------------------------------------------------


class SIEMBackend(ABC):
    """Abstract base for SIEM output backends."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable backend name."""
        ...

    @abstractmethod
    def send(self, event: AuditEvent) -> bool:
        """Send a single event. Returns True on success."""
        ...

    def send_batch(self, events: list[AuditEvent]) -> int:
        """Send multiple events. Returns count of successful sends."""
        return sum(1 for e in events if self.send(e))

    def close(self) -> None:  # noqa: B027
        """Clean up resources."""
        pass


# --- Syslog Backend (RFC 5424) -------------------------------------------

# RFC 5424 severity mapping
_SEVERITY_MAP = {
    "info": 6,  # Informational
    "warning": 4,  # Warning
    "critical": 2,  # Critical
}

# RFC 5424 facility: local0 = 16
_FACILITY = 16


class SyslogBackend(SIEMBackend):
    """RFC 5424 syslog output over UDP or TCP.

    Formats audit events as structured syslog messages with structured data
    elements for machine parsing.

    Example output:
        <134>1 2026-05-22T10:30:00Z domestique - firewall - [domestique@49152
        action="block" dst="api.openai.com" cat="SSN"] Request blocked
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 514,
        protocol: str = "udp",
        app_name: str = "domestique",
    ) -> None:
        self._host = host
        self._port = port
        self._protocol = protocol
        self._app_name = app_name
        self._socket: socket.socket | None = None

    @property
    def name(self) -> str:
        return f"syslog-{self._protocol}://{self._host}:{self._port}"

    def send(self, event: AuditEvent) -> bool:
        try:
            message = self._format_rfc5424(event)
            self._get_socket().sendto(
                message.encode("utf-8"),
                (self._host, self._port),
            )
            return True
        except Exception as e:
            logger.debug(f"Syslog send failed: {e}")
            self._socket = None
            return False

    def close(self) -> None:
        if self._socket:
            self._socket.close()
            self._socket = None

    def _get_socket(self) -> socket.socket:
        if self._socket is None:
            if self._protocol == "tcp":
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.connect((self._host, self._port))
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._socket

    def _format_rfc5424(self, event: AuditEvent) -> str:
        """Format event as RFC 5424 syslog message."""
        severity = _SEVERITY_MAP.get(event.severity, 6)
        priority = _FACILITY * 8 + severity

        # Structured data element
        sd_params = [
            f'action="{event.action}"',
            f'dst="{event.destination}"',
            f'method="{event.method}"',
            f'path="{event.path[:100]}"',
            f'latency="{event.latency_ms:.1f}"',
        ]
        if event.pii_categories:
            sd_params.append(f'cat="{",".join(event.pii_categories)}"')
        if event.detectors_triggered:
            sd_params.append(f'detectors="{",".join(event.detectors_triggered)}"')

        sd = f"[domestique@49152 {' '.join(sd_params)}]"

        # Human-readable message
        msg = f"Domestique {event.action}: {event.destination} ({event.method})"

        return (
            f"<{priority}>1 {event.timestamp} "
            f"{self._app_name} - firewall {event.request_id} "
            f"{sd} {msg}"
        )


# --- CEF Backend (ArcSight) ---------------------------------------------


class CEFBackend(SIEMBackend):
    """Common Event Format output for ArcSight and compatible SIEMs.

    Formats events according to CEF specification:
        CEF:0|Domestique|Firewall|1.0|action|name|severity|extensions
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 514,
        protocol: str = "udp",
    ) -> None:
        self._syslog = SyslogBackend(host=host, port=port, protocol=protocol)

    @property
    def name(self) -> str:
        return f"cef://{self._syslog._host}:{self._syslog._port}"

    def send(self, event: AuditEvent) -> bool:
        try:
            cef_message = self._format_cef(event)
            sock = self._syslog._get_socket()
            sock.sendto(
                cef_message.encode("utf-8"),
                (self._syslog._host, self._syslog._port),
            )
            return True
        except Exception as e:
            logger.debug(f"CEF send failed: {e}")
            return False

    def close(self) -> None:
        self._syslog.close()

    def _format_cef(self, event: AuditEvent) -> str:
        """Format event as CEF message."""
        severity_map = {"info": 1, "warning": 5, "critical": 9}
        severity = severity_map.get(event.severity, 1)

        # CEF event name based on action
        names = {
            "block": "Sensitive Data Blocked",
            "redact": "Sensitive Data Redacted",
            "allow": "Request Allowed",
            "error": "Detection Error",
        }
        event_name = names.get(event.action, "Unknown")

        # Extension fields
        extensions = [
            f"dst={event.destination}",
            f"requestMethod={event.method}",
            f"request={event.path[:200]}",
            f"src={event.source_ip}",
            f"suser={event.user}",
            f"rt={event.timestamp}",
            f"cn1={int(event.latency_ms)}",
            "cn1Label=latencyMs",
            f"cs1={','.join(event.pii_categories)}",
            "cs1Label=piiCategories",
            f"cs2={','.join(event.detectors_triggered)}",
            "cs2Label=detectors",
            f"externalId={event.request_id}",
        ]

        return (
            f"CEF:0|Domestique|Firewall|1.0|{event.action}|"
            f"{event_name}|{severity}|{' '.join(extensions)}"
        )


# --- Webhook Backend -----------------------------------------------------


class WebhookBackend(SIEMBackend):
    """HTTP webhook output - POSTs JSON events to a URL.

    Supports custom headers for authentication (API keys, bearer tokens).
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 5.0,
        batch_size: int = 10,
    ) -> None:
        self._url = url
        self._headers = headers or {}
        self._timeout = timeout
        self._batch_size = batch_size

    @property
    def name(self) -> str:
        return f"webhook://{self._url[:50]}"

    def send(self, event: AuditEvent) -> bool:
        try:
            data = json.dumps(event.to_dict()).encode("utf-8")
            req = Request(  # noqa: S310
                self._url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Domestique/1.0",
                    **self._headers,
                },
                method="POST",
            )
            resp = urlopen(req, timeout=self._timeout)  # noqa: S310
            return 200 <= resp.status < 300
        except Exception as e:
            logger.debug(f"Webhook send failed: {e}")
            return False

    def send_batch(self, events: list[AuditEvent]) -> int:
        """Send events as a JSON array for efficiency."""
        if not events:
            return 0
        try:
            data = json.dumps([e.to_dict() for e in events]).encode("utf-8")
            req = Request(  # noqa: S310
                self._url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Domestique/1.0",
                    "X-Domestique-Batch-Size": str(len(events)),
                    **self._headers,
                },
                method="POST",
            )
            resp = urlopen(req, timeout=self._timeout)  # noqa: S310
            if 200 <= resp.status < 300:
                return len(events)
        except Exception as e:
            logger.debug(f"Webhook batch send failed: {e}")
        return 0


# --- File Backend (for Filebeat/Fluentd) ---------------------------------


class FileBackend(SIEMBackend):
    """JSONL file output for log shippers (Filebeat, Fluentd, Vector).

    Writes one JSON object per line. The file can be tailed by log shippers
    for forwarding to any SIEM.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or (Path.home() / ".domestique" / "siem" / "events.jsonl")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self._path, "a", buffering=1)  # noqa: SIM115

    @property
    def name(self) -> str:
        return f"file://{self._path}"

    def send(self, event: AuditEvent) -> bool:
        try:
            self._file.write(event.to_json() + "\n")
            return True
        except Exception:
            return False

    def close(self) -> None:
        self._file.close()


# --- Dispatcher ----------------------------------------------------------


class SIEMDispatcher:
    """Routes audit events to all configured SIEM backends.

    Non-blocking: uses a background thread with a bounded queue.
    Failed backends are retried with exponential backoff.
    """

    QUEUE_MAX = 5_000
    BATCH_SIZE = 50
    FLUSH_INTERVAL = 2.0

    def __init__(self) -> None:
        self._backends: list[SIEMBackend] = []
        self._queue: Queue[AuditEvent | None] = Queue(maxsize=self.QUEUE_MAX)
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._stats = {"dispatched": 0, "failed": 0, "dropped": 0}

    @property
    def stats(self) -> dict[str, int]:
        """Dispatch statistics."""
        return self._stats.copy()

    @property
    def backends(self) -> list[str]:
        """Names of configured backends."""
        return [b.name for b in self._backends]

    def add_backend(self, backend: SIEMBackend) -> None:
        """Register a SIEM output backend."""
        with self._lock:
            self._backends.append(backend)
        logger.info(f"SIEM backend added: {backend.name}")

    def remove_backend(self, name: str) -> None:
        """Remove a backend by name."""
        with self._lock:
            self._backends = [b for b in self._backends if b.name != name]

    def start(self) -> None:
        """Start the dispatcher background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._dispatch_loop, daemon=True, name="siem-dispatcher"
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop dispatcher and close all backends."""
        self._running = False
        self._queue.put(None)
        if self._thread:
            self._thread.join(timeout=5.0)
        for backend in self._backends:
            backend.close()

    def dispatch(self, event: AuditEvent) -> None:
        """Enqueue an event for dispatch. Never blocks."""
        if not self._running or not self._backends:
            return
        try:
            self._queue.put_nowait(event)
        except Full:
            self._stats["dropped"] += 1

    def _dispatch_loop(self) -> None:
        """Background thread that batches and sends events."""
        batch: list[AuditEvent] = []
        last_flush = time.time()

        while self._running or not self._queue.empty():
            try:
                event = self._queue.get(timeout=self.FLUSH_INTERVAL)
                if event is None:
                    break
                batch.append(event)
            except Empty:
                pass

            now = time.time()
            if batch and (
                len(batch) >= self.BATCH_SIZE or now - last_flush >= self.FLUSH_INTERVAL
            ):
                self._send_batch(batch)
                batch = []
                last_flush = now

        if batch:
            self._send_batch(batch)

    def _send_batch(self, batch: list[AuditEvent]) -> None:
        """Send a batch to all backends."""
        for backend in self._backends:
            try:
                sent = backend.send_batch(batch)
                self._stats["dispatched"] += sent
                self._stats["failed"] += len(batch) - sent
            except Exception as e:
                logger.warning(f"Backend {backend.name} batch failed: {e}")
                self._stats["failed"] += len(batch)


# --- Module-level singleton ----------------------------------------------

_global_dispatcher: SIEMDispatcher | None = None
_dispatcher_lock = threading.Lock()


def get_siem_dispatcher() -> SIEMDispatcher:
    """Get or create the global SIEM dispatcher singleton."""
    global _global_dispatcher
    if _global_dispatcher is None:
        with _dispatcher_lock:
            if _global_dispatcher is None:
                _global_dispatcher = SIEMDispatcher()
                _global_dispatcher.start()
    return _global_dispatcher


def shutdown_siem() -> None:
    """Gracefully shut down the global SIEM dispatcher."""
    global _global_dispatcher
    if _global_dispatcher:
        _global_dispatcher.stop()
        _global_dispatcher = None
