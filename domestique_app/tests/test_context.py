"""Tests for multi-turn context awareness."""

import time

import pytest

from domestique_app.services.context import ContextAnalyzer, Message, SessionTracker


@pytest.fixture
def tracker():
    return SessionTracker(window_size=10, ttl_seconds=60.0)


@pytest.fixture
def analyzer():
    return ContextAnalyzer()


class TestSessionTracker:
    """Tests for message tracking."""

    def test_add_and_retrieve(self, tracker):
        tracker.add_message("s1", "Hello")
        window = tracker.get_window("s1")
        assert len(window) == 1
        assert window[0].text == "Hello"

    def test_window_size_limit(self):
        tracker = SessionTracker(window_size=3)
        for i in range(5):
            tracker.add_message("s1", f"msg{i}")
        window = tracker.get_window("s1")
        assert len(window) == 3
        assert window[0].text == "msg2"

    def test_separate_sessions(self, tracker):
        tracker.add_message("s1", "Hello")
        tracker.add_message("s2", "World")
        assert len(tracker.get_window("s1")) == 1
        assert len(tracker.get_window("s2")) == 1

    def test_empty_session(self, tracker):
        assert tracker.get_window("nonexistent") == []

    def test_clear_session(self, tracker):
        tracker.add_message("s1", "Hello")
        tracker.clear_session("s1")
        assert tracker.get_window("s1") == []

    def test_active_sessions_count(self, tracker):
        tracker.add_message("s1", "a")
        tracker.add_message("s2", "b")
        assert tracker.active_sessions == 2

    def test_ttl_expiry(self):
        tracker = SessionTracker(window_size=10, ttl_seconds=0.01)
        tracker.add_message("s1", "old message")
        time.sleep(0.02)
        assert tracker.get_window("s1") == []


class TestContextAnalyzer:
    """Tests for split-message detection."""

    def test_no_messages(self, analyzer):
        result = analyzer.analyze([])
        assert result.is_suspicious is False

    def test_single_message(self, analyzer):
        result = analyzer.analyze([Message(text="Hello")])
        assert result.is_suspicious is False

    def test_safe_conversation(self, analyzer):
        messages = [
            Message(text="What is machine learning?"),
            Message(text="Can you explain neural networks?"),
            Message(text="What about transformers?"),
        ]
        result = analyzer.analyze(messages)
        assert result.is_suspicious is False

    def test_preamble_then_digits(self, analyzer):
        messages = [
            Message(text="My social security number is"),
            Message(text="123 45 6789"),
        ]
        result = analyzer.analyze(messages)
        assert result.is_suspicious is True
        assert result.confidence >= 0.8

    def test_ssn_preamble_digits_later(self, analyzer):
        messages = [
            Message(text="The SSN for the record is"),
            Message(text="some other text"),
            Message(text="456 78 9012"),
        ]
        result = analyzer.analyze(messages)
        assert result.is_suspicious is True

    def test_credit_card_preamble(self, analyzer):
        messages = [
            Message(text="My credit card number is"),
            Message(text="4111 1111 1111 1111"),
        ]
        result = analyzer.analyze(messages)
        assert result.is_suspicious is True

    def test_number_words_with_context(self, analyzer):
        messages = [
            Message(text="My social security number is"),
            Message(text="one two three"),
            Message(text="forty five six seven eight nine"),
        ]
        result = analyzer.analyze(messages)
        assert result.is_suspicious is True

    def test_combined_ssn_across_messages(self, analyzer):
        messages = [
            Message(text="Here is 123"),
            Message(text="45-6789 for the record"),
        ]
        result = analyzer.analyze(messages)
        assert result.is_suspicious is True
        assert "SSN" in result.reason

    def test_combined_cc_across_messages(self, analyzer):
        messages = [
            Message(text="Card: 4111-1111"),
            Message(text="1111-1111"),
        ]
        result = analyzer.analyze(messages)
        assert result.is_suspicious is True
        assert "Credit card" in result.reason

    def test_no_false_positive_normal_numbers(self, analyzer):
        """Normal numeric discussion shouldn't trigger."""
        messages = [
            Message(text="The population is about 300 million"),
            Message(text="The GDP is 21 trillion"),
        ]
        result = analyzer.analyze(messages)
        assert result.is_suspicious is False


class TestIntegration:
    """Integration tests combining tracker and analyzer."""

    def test_full_flow(self):
        tracker = SessionTracker()
        analyzer = ContextAnalyzer()

        tracker.add_message("attacker", "My SSN is")
        tracker.add_message("attacker", "one two three forty five")
        tracker.add_message("attacker", "six seven eight nine")

        window = tracker.get_window("attacker")
        result = analyzer.analyze(window)
        assert result.is_suspicious is True
