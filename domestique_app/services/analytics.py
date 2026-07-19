"""Behavioral analytics for anomaly detection and risk scoring.

Tracks per-user usage patterns to detect anomalous behavior that may
indicate data exfiltration attempts.

Features:
    - Usage baseline: track normal request frequency, data volume, timing
    - Anomaly detection: flag deviations from established baselines
    - Risk scoring: combine signals into a composite user risk score
    - Alert generation: configurable thresholds for notifications

Architecture:
    - UserProfile: maintains rolling statistics per user/session
    - AnomalyDetector: compares current behavior against baseline
    - RiskScorer: aggregates multiple signals into [0, 1] score

Usage:
    from domestique_app.services.analytics import UserProfile, AnomalyDetector, RiskScorer

    profile = UserProfile("user@corp.com")
    profile.record_request(destination="api.openai.com", content_length=500)

    detector = AnomalyDetector()
    anomalies = detector.check(profile)
    if anomalies:
        print(f"Anomalous behavior: {anomalies}")

    scorer = RiskScorer()
    risk = scorer.score(profile)
    print(f"Risk score: {risk.score:.2f} ({risk.level})")
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):  # noqa: UP042  # str-mixin str() semantics kept intentionally
    """Risk level classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RequestRecord:
    """A single recorded request event."""

    timestamp: float
    destination: str
    content_length: int
    was_blocked: bool = False
    categories_triggered: list[str] = field(default_factory=list)


@dataclass
class Anomaly:
    """A detected anomaly in user behavior."""

    signal: str
    description: str
    severity: float  # 0.0 to 1.0
    current_value: float
    baseline_value: float


@dataclass
class RiskScore:
    """Composite risk assessment for a user."""

    score: float  # 0.0 (safe) to 1.0 (critical)
    level: RiskLevel
    signals: list[str] = field(default_factory=list)
    anomalies: list[Anomaly] = field(default_factory=list)


class UserProfile:
    """Tracks behavioral statistics for a single user/session.

    Maintains a rolling window of request history for analysis.
    Thread-safe for concurrent updates.

    Args:
        user_id: Unique user identifier.
        window_seconds: Rolling window duration (default: 1 hour).
        max_history: Maximum records to retain.
    """

    def __init__(
        self,
        user_id: str,
        window_seconds: float = 3600.0,
        max_history: int = 1000,
    ) -> None:
        self.user_id = user_id
        self._window = window_seconds
        self._max_history = max_history
        self._history: deque[RequestRecord] = deque(maxlen=max_history)
        self._lock = threading.Lock()
        self._total_requests = 0
        self._total_blocked = 0
        self._first_seen: float | None = None

    def record_request(
        self,
        destination: str,
        content_length: int,
        was_blocked: bool = False,
        categories: list[str] | None = None,
    ) -> None:
        """Record a new request event.

        Args:
            destination: Target LLM endpoint.
            content_length: Size of request body.
            was_blocked: Whether the request was blocked.
            categories: PII categories detected.
        """
        record = RequestRecord(
            timestamp=time.time(),
            destination=destination,
            content_length=content_length,
            was_blocked=was_blocked,
            categories_triggered=categories or [],
        )
        with self._lock:
            if self._first_seen is None:
                self._first_seen = record.timestamp
            self._history.append(record)
            self._total_requests += 1
            if was_blocked:
                self._total_blocked += 1

    def get_recent(self, seconds: float | None = None) -> list[RequestRecord]:
        """Get records within the specified time window.

        Args:
            seconds: Time window (defaults to profile's window_seconds).
        """
        cutoff = time.time() - (seconds or self._window)
        with self._lock:
            return [r for r in self._history if r.timestamp > cutoff]

    @property
    def request_rate(self) -> float:
        """Requests per minute in the current window."""
        recent = self.get_recent(60.0)
        return len(recent)

    @property
    def block_rate(self) -> float:
        """Fraction of requests that were blocked (in window)."""
        recent = self.get_recent()
        if not recent:
            return 0.0
        blocked = sum(1 for r in recent if r.was_blocked)
        return blocked / len(recent)

    @property
    def avg_content_length(self) -> float:
        """Average content length in the current window."""
        recent = self.get_recent()
        if not recent:
            return 0.0
        return sum(r.content_length for r in recent) / len(recent)

    @property
    def unique_destinations(self) -> int:
        """Number of unique destinations in the window."""
        recent = self.get_recent()
        return len({r.destination for r in recent})

    @property
    def total_volume(self) -> int:
        """Total bytes sent in the window."""
        recent = self.get_recent()
        return sum(r.content_length for r in recent)

    @property
    def total_requests(self) -> int:
        """Total requests since first seen."""
        return self._total_requests

    @property
    def total_blocked(self) -> int:
        """Total blocked requests since first seen."""
        return self._total_blocked


class AnomalyDetector:
    """Detects anomalous behavior by comparing against thresholds.

    Uses simple statistical thresholds. In production, these would be
    learned from the user's historical baseline.

    Args:
        max_requests_per_minute: Threshold for request rate.
        max_block_rate: Threshold for block ratio.
        max_volume_per_hour: Threshold for total bytes per hour.
        max_content_length: Threshold for single request size.
    """

    def __init__(
        self,
        max_requests_per_minute: float = 30.0,
        max_block_rate: float = 0.5,
        max_volume_per_hour: int = 10_000_000,  # 10 MB
        max_content_length: float = 100_000,  # 100 KB average
    ) -> None:
        self._max_rpm = max_requests_per_minute
        self._max_block_rate = max_block_rate
        self._max_volume = max_volume_per_hour
        self._max_content = max_content_length

    def check(self, profile: UserProfile) -> list[Anomaly]:
        """Check a user profile for anomalous behavior.

        Args:
            profile: The user profile to analyze.

        Returns:
            List of detected anomalies (empty if normal).
        """
        anomalies: list[Anomaly] = []

        # Check request rate
        rpm = profile.request_rate
        if rpm > self._max_rpm:
            anomalies.append(
                Anomaly(
                    signal="high_request_rate",
                    description=f"Request rate ({rpm:.0f}/min) exceeds threshold ({self._max_rpm:.0f}/min)",  # noqa: E501
                    severity=min(1.0, rpm / (self._max_rpm * 2)),
                    current_value=rpm,
                    baseline_value=self._max_rpm,
                )
            )

        # Check block rate
        block_rate = profile.block_rate
        if block_rate > self._max_block_rate:
            anomalies.append(
                Anomaly(
                    signal="high_block_rate",
                    description=f"Block rate ({block_rate:.1%}) exceeds threshold ({self._max_block_rate:.1%})",  # noqa: E501
                    severity=min(1.0, block_rate / self._max_block_rate),
                    current_value=block_rate,
                    baseline_value=self._max_block_rate,
                )
            )

        # Check total volume
        volume = profile.total_volume
        if volume > self._max_volume:
            anomalies.append(
                Anomaly(
                    signal="high_volume",
                    description=f"Data volume ({volume:,} bytes) exceeds threshold ({self._max_volume:,})",  # noqa: E501
                    severity=min(1.0, volume / (self._max_volume * 2)),
                    current_value=volume,
                    baseline_value=self._max_volume,
                )
            )

        # Check average content size
        avg = profile.avg_content_length
        if avg > self._max_content:
            anomalies.append(
                Anomaly(
                    signal="large_payloads",
                    description=f"Average payload ({avg:.0f} bytes) exceeds threshold ({self._max_content:.0f})",  # noqa: E501
                    severity=min(1.0, avg / (self._max_content * 2)),
                    current_value=avg,
                    baseline_value=self._max_content,
                )
            )

        return anomalies


class RiskScorer:
    """Aggregates multiple signals into a composite risk score.

    Weights:
        - block_rate: 0.4 (most indicative of intentional data exfil)
        - request_rate: 0.2 (burst activity)
        - volume: 0.2 (data exfiltration volume)
        - anomaly_count: 0.2 (number of simultaneous anomalies)
    """

    WEIGHTS = {
        "block_rate": 0.4,
        "request_rate": 0.2,
        "volume": 0.2,
        "anomaly_count": 0.2,
    }

    def __init__(self, detector: AnomalyDetector | None = None) -> None:
        self._detector = detector or AnomalyDetector()

    def score(self, profile: UserProfile) -> RiskScore:
        """Calculate composite risk score for a user.

        Args:
            profile: The user profile to score.

        Returns:
            RiskScore with level and contributing signals.
        """
        anomalies = self._detector.check(profile)
        signals: list[str] = []

        # Block rate signal
        block_score = min(1.0, profile.block_rate / 0.5) * self.WEIGHTS["block_rate"]
        if profile.block_rate > 0.1:
            signals.append(f"block_rate:{profile.block_rate:.1%}")

        # Request rate signal
        rpm = profile.request_rate
        rate_score = min(1.0, rpm / 30.0) * self.WEIGHTS["request_rate"]
        if rpm > 10:
            signals.append(f"request_rate:{rpm:.0f}/min")

        # Volume signal
        volume = profile.total_volume
        vol_score = min(1.0, volume / 10_000_000) * self.WEIGHTS["volume"]
        if volume > 1_000_000:
            signals.append(f"volume:{volume:,}B")

        # Anomaly count signal
        anomaly_score = min(1.0, len(anomalies) / 3) * self.WEIGHTS["anomaly_count"]
        if anomalies:
            signals.append(f"anomalies:{len(anomalies)}")

        total = block_score + rate_score + vol_score + anomaly_score
        total = min(1.0, total)

        # Classify level
        if total >= 0.75:
            level = RiskLevel.CRITICAL
        elif total >= 0.5:
            level = RiskLevel.HIGH
        elif total >= 0.25:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return RiskScore(
            score=total,
            level=level,
            signals=signals,
            anomalies=anomalies,
        )
