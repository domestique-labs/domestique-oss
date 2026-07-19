"""Approval manager for pending PII-flagged requests.

When approval_mode is enabled, requests that would normally be blocked are
held in a pending queue. The user can approve or deny them via the dashboard
or desktop notification. If no decision is made within the timeout, the request
is automatically denied.

Architecture:
    mitm_addon (subprocess) --HTTP POST--▶ API server --▶ ApprovalManager
    mitm_addon polls GET /api/approvals/{id} until decision or timeout
    Dashboard polls GET /api/approvals to show pending list
    User clicks approve/deny -> POST /api/approvals/{id}/approve|deny

Thread safety:
    All mutations are protected by a threading.Lock. The ApprovalManager
    lives in the API server process only.

Privacy:
    Only redacted previews are stored - never raw PII values. Expired
    entries are cleaned up automatically.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import asdict, dataclass
from enum import Enum


class ApprovalStatus(str, Enum):  # noqa: UP042  # str-mixin str() semantics kept intentionally
    """Lifecycle states for a pending approval."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass
class PendingApproval:
    """A request awaiting user approval.

    Fields are intentionally minimal to avoid storing sensitive data.
    content_preview should be redacted before being stored here.
    """

    id: str
    """Unguessable token (URL-safe random)."""

    created_at: float
    """Unix timestamp when the request was flagged."""

    host: str
    """Destination host (e.g., 'api.openai.com')."""

    path: str
    """Request path, truncated to 100 chars."""

    findings: list[str]
    """PII categories detected (e.g., ['SSN', 'email'])."""

    content_preview: str
    """Redacted preview of the flagged content (max 300 chars)."""

    timeout_seconds: int
    """Seconds before auto-deny."""

    status: ApprovalStatus = ApprovalStatus.PENDING
    """Current state in the approval lifecycle."""

    decided_at: float | None = None
    """Unix timestamp when the decision was made (or expired)."""

    def to_dict(self) -> dict:
        """Serialize for API responses."""
        d = asdict(self)
        d["status"] = self.status.value
        d["remaining_seconds"] = max(0, self.timeout_seconds - (time.time() - self.created_at))
        return d

    @property
    def is_expired(self) -> bool:
        """Check if this approval has passed its timeout."""
        return time.time() - self.created_at > self.timeout_seconds


class ApprovalManager:
    """Thread-safe manager for pending approval requests.

    Singleton - use get_approval_manager() to access.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[str, PendingApproval] = {}
        self._csrf_token: str = secrets.token_urlsafe(32)

    @property
    def csrf_token(self) -> str:
        """CSRF token for protecting approval endpoints."""
        return self._csrf_token

    def submit(
        self,
        *,
        host: str,
        path: str,
        findings: list[str],
        content_preview: str,
        timeout_seconds: int = 30,
    ) -> PendingApproval:
        """Submit a new request for approval.

        Args:
            host: Destination host.
            path: Request path (truncated).
            findings: List of PII categories detected.
            content_preview: Redacted preview (max 300 chars).
            timeout_seconds: Auto-deny timeout.

        Returns:
            The created PendingApproval with a unique ID.
        """
        approval = PendingApproval(
            id=secrets.token_urlsafe(16),
            created_at=time.time(),
            host=host,
            path=path[:100],
            findings=findings,
            content_preview=content_preview[:300],
            timeout_seconds=timeout_seconds,
        )

        with self._lock:
            self._cleanup_expired_locked()
            self._pending[approval.id] = approval

        return approval

    def get(self, approval_id: str) -> PendingApproval | None:
        """Get an approval by ID, expiring it if past timeout.

        Returns None if not found.
        """
        with self._lock:
            approval = self._pending.get(approval_id)
            if approval is None:
                return None

            # Auto-expire if past timeout
            if approval.status == ApprovalStatus.PENDING and approval.is_expired:
                approval.status = ApprovalStatus.EXPIRED
                approval.decided_at = time.time()

            return approval

    def decide(self, approval_id: str, decision: ApprovalStatus) -> PendingApproval | None:
        """Record a decision (approve or deny) for a pending approval.

        Atomic transition: only PENDING -> APPROVED/DENIED is allowed.
        Returns the updated approval, or None if not found.
        Raises ValueError if the approval is no longer pending.
        """
        if decision not in (ApprovalStatus.APPROVED, ApprovalStatus.DENIED):
            raise ValueError(f"Invalid decision: {decision}")

        with self._lock:
            approval = self._pending.get(approval_id)
            if approval is None:
                return None

            # Check if already decided or expired
            if approval.status != ApprovalStatus.PENDING:
                raise ValueError(f"Approval {approval_id} is already {approval.status.value}")

            # Check timeout before accepting decision
            if approval.is_expired:
                approval.status = ApprovalStatus.EXPIRED
                approval.decided_at = time.time()
                raise ValueError(f"Approval {approval_id} has expired")

            approval.status = decision
            approval.decided_at = time.time()
            return approval

    def list_pending(self) -> list[PendingApproval]:
        """List all pending (non-expired) approvals, newest first."""
        with self._lock:
            self._cleanup_expired_locked()
            return sorted(
                [a for a in self._pending.values() if a.status == ApprovalStatus.PENDING],
                key=lambda a: a.created_at,
                reverse=True,
            )

    def list_recent(self, limit: int = 20) -> list[PendingApproval]:
        """List recent approvals (all statuses), newest first."""
        with self._lock:
            self._cleanup_expired_locked()
            return sorted(
                self._pending.values(),
                key=lambda a: a.created_at,
                reverse=True,
            )[:limit]

    def pending_count(self) -> int:
        """Number of currently pending approvals."""
        with self._lock:
            self._cleanup_expired_locked()
            return sum(1 for a in self._pending.values() if a.status == ApprovalStatus.PENDING)

    def _cleanup_expired_locked(self) -> None:
        """Mark expired approvals and remove old decided ones.

        Must be called with self._lock held.
        """
        now = time.time()

        for approval in self._pending.values():
            if approval.status == ApprovalStatus.PENDING and approval.is_expired:
                approval.status = ApprovalStatus.EXPIRED
                approval.decided_at = now

        # Remove entries older than 5 minutes (decided or expired)
        cutoff = now - 300
        to_remove = [
            aid
            for aid, a in self._pending.items()
            if a.status != ApprovalStatus.PENDING and a.decided_at and a.decided_at < cutoff
        ]
        for aid in to_remove:
            del self._pending[aid]


# --- Singleton --------------------------------------------------------

_manager: ApprovalManager | None = None
_manager_lock = threading.Lock()


def get_approval_manager() -> ApprovalManager:
    """Get or create the singleton ApprovalManager."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = ApprovalManager()
    return _manager
