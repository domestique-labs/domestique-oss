"""Tests for behavioral analytics."""

import time

import pytest

from domestique_app.services.analytics import (
    AnomalyDetector,
    RiskLevel,
    RiskScorer,
    UserProfile,
)


@pytest.fixture
def profile():
    return UserProfile("user@corp.com", window_seconds=60.0)


@pytest.fixture
def detector():
    return AnomalyDetector(
        max_requests_per_minute=10.0,
        max_block_rate=0.3,
        max_volume_per_hour=1_000_000,
        max_content_length=50_000,
    )


class TestUserProfile:
    """Tests for UserProfile tracking."""

    def test_record_request(self, profile):
        profile.record_request("api.openai.com", 500)
        assert profile.total_requests == 1
        assert len(profile.get_recent()) == 1

    def test_multiple_requests(self, profile):
        for i in range(5):
            profile.record_request("api.openai.com", 100 * (i + 1))
        assert profile.total_requests == 5

    def test_block_tracking(self, profile):
        profile.record_request("api.openai.com", 500, was_blocked=True)
        profile.record_request("api.openai.com", 500, was_blocked=False)
        assert profile.total_blocked == 1
        assert profile.block_rate == 0.5

    def test_request_rate(self, profile):
        for _ in range(5):
            profile.record_request("api.openai.com", 100)
        assert profile.request_rate == 5

    def test_avg_content_length(self, profile):
        profile.record_request("api.openai.com", 100)
        profile.record_request("api.openai.com", 300)
        assert profile.avg_content_length == 200.0

    def test_unique_destinations(self, profile):
        profile.record_request("api.openai.com", 100)
        profile.record_request("api.anthropic.com", 200)
        profile.record_request("api.openai.com", 100)
        assert profile.unique_destinations == 2

    def test_total_volume(self, profile):
        profile.record_request("api.openai.com", 100)
        profile.record_request("api.openai.com", 200)
        assert profile.total_volume == 300

    def test_empty_profile(self, profile):
        assert profile.request_rate == 0
        assert profile.block_rate == 0.0
        assert profile.avg_content_length == 0.0
        assert profile.total_volume == 0

    def test_window_expiry(self):
        profile = UserProfile("user", window_seconds=0.01)
        profile.record_request("api.openai.com", 100)
        time.sleep(0.02)
        assert len(profile.get_recent()) == 0

    def test_max_history(self):
        profile = UserProfile("user", max_history=5)
        for _i in range(10):
            profile.record_request("api.openai.com", 100)
        assert profile.total_requests == 10
        # Only 5 in deque
        assert len(profile.get_recent(9999)) == 5


class TestAnomalyDetector:
    """Tests for anomaly detection."""

    def test_normal_behavior(self, detector, profile):
        profile.record_request("api.openai.com", 500)
        anomalies = detector.check(profile)
        assert anomalies == []

    def test_high_request_rate(self, detector):
        profile = UserProfile("user", window_seconds=60.0)
        for _ in range(15):
            profile.record_request("api.openai.com", 100)
        anomalies = detector.check(profile)
        assert any(a.signal == "high_request_rate" for a in anomalies)

    def test_high_block_rate(self, detector):
        profile = UserProfile("user", window_seconds=60.0)
        for _ in range(10):
            profile.record_request("api.openai.com", 100, was_blocked=True)
        for _ in range(2):
            profile.record_request("api.openai.com", 100, was_blocked=False)
        anomalies = detector.check(profile)
        assert any(a.signal == "high_block_rate" for a in anomalies)

    def test_high_volume(self, detector):
        profile = UserProfile("user", window_seconds=3600.0)
        for _ in range(20):
            profile.record_request("api.openai.com", 100_000)
        anomalies = detector.check(profile)
        assert any(a.signal == "high_volume" for a in anomalies)

    def test_large_payloads(self, detector):
        profile = UserProfile("user", window_seconds=60.0)
        for _ in range(5):
            profile.record_request("api.openai.com", 100_000)
        anomalies = detector.check(profile)
        assert any(a.signal == "large_payloads" for a in anomalies)

    def test_anomaly_severity_bounded(self, detector):
        profile = UserProfile("user", window_seconds=60.0)
        for _ in range(100):
            profile.record_request("api.openai.com", 100)
        anomalies = detector.check(profile)
        for a in anomalies:
            assert 0.0 <= a.severity <= 1.0


class TestRiskScorer:
    """Tests for risk scoring."""

    def test_low_risk_normal_user(self):
        scorer = RiskScorer()
        profile = UserProfile("user", window_seconds=60.0)
        profile.record_request("api.openai.com", 500)
        risk = scorer.score(profile)
        assert risk.level == RiskLevel.LOW
        assert risk.score < 0.25

    def test_high_risk_many_blocks(self):
        scorer = RiskScorer()
        profile = UserProfile("user", window_seconds=60.0)
        for _ in range(20):
            profile.record_request("api.openai.com", 50_000, was_blocked=True)
        risk = scorer.score(profile)
        assert risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert risk.score >= 0.5

    def test_score_bounded(self):
        scorer = RiskScorer()
        profile = UserProfile("user", window_seconds=60.0)
        for _ in range(1000):
            profile.record_request("api.openai.com", 999_999, was_blocked=True)
        risk = scorer.score(profile)
        assert 0.0 <= risk.score <= 1.0

    def test_signals_populated(self):
        scorer = RiskScorer()
        profile = UserProfile("user", window_seconds=60.0)
        for _ in range(50):
            profile.record_request("api.openai.com", 100_000, was_blocked=True)
        risk = scorer.score(profile)
        assert len(risk.signals) > 0

    def test_risk_levels(self):
        """Verify all risk levels are achievable."""
        scorer = RiskScorer()

        # LOW
        p1 = UserProfile("u1", window_seconds=60.0)
        p1.record_request("api.openai.com", 100)
        assert scorer.score(p1).level == RiskLevel.LOW
