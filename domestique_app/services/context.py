"""Multi-turn context awareness for split-message PII detection.

Tracks conversation context across multiple requests to detect when users
split sensitive data across messages to evade per-request detection.

Architecture:
    - SessionTracker: per-user/session sliding window buffer
    - ContextAnalyzer: detects split-message patterns
    - Configurable window size (default: 10 messages)

Detection strategies:
    1. Accumulation: concatenate recent messages, re-run PII detection
    2. Numeric sequences: detect numbers split across messages
    3. Suspicious patterns: "my SSN is" in one message, digits in next

Usage:
    from domestique_app.services.context import SessionTracker, ContextAnalyzer

    tracker = SessionTracker()
    tracker.add_message("session-123", "My social security number is")
    tracker.add_message("session-123", "one two three forty five six seven eight nine")

    analyzer = ContextAnalyzer()
    result = analyzer.analyze(tracker.get_window("session-123"))
    if result.is_suspicious:
        print(f"Split-message evasion detected: {result.reason}")
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class Message:
    """A single message in the conversation context."""

    text: str
    timestamp: float = field(default_factory=time.time)
    session_id: str = ""


@dataclass
class ContextResult:
    """Result of multi-turn context analysis."""

    is_suspicious: bool
    reason: str = ""
    combined_text: str = ""
    confidence: float = 0.0
    messages_analyzed: int = 0


class SessionTracker:
    """Tracks conversation messages per session with a sliding window.

    Thread-safe. Messages older than TTL are automatically evicted.

    Args:
        window_size: Maximum messages to retain per session.
        ttl_seconds: Time-to-live for messages (default: 1 hour).
    """

    def __init__(
        self,
        window_size: int = 10,
        ttl_seconds: float = 3600.0,
    ) -> None:
        self._window_size = window_size
        self._ttl = ttl_seconds
        self._sessions: dict[str, list[Message]] = defaultdict(list)
        self._lock = threading.Lock()

    def add_message(self, session_id: str, text: str) -> None:
        """Add a message to the session's context window.

        Args:
            session_id: Unique session/user identifier.
            text: The message content.
        """
        msg = Message(text=text, session_id=session_id)
        with self._lock:
            window = self._sessions[session_id]
            window.append(msg)
            # Trim to window size
            if len(window) > self._window_size:
                self._sessions[session_id] = window[-self._window_size :]

    def get_window(self, session_id: str) -> list[Message]:
        """Get the current message window for a session.

        Automatically evicts expired messages.

        Args:
            session_id: The session to retrieve.

        Returns:
            List of recent messages (newest last).
        """
        now = time.time()
        with self._lock:
            window = self._sessions.get(session_id, [])
            # Evict expired messages
            valid = [m for m in window if (now - m.timestamp) < self._ttl]
            self._sessions[session_id] = valid
            return list(valid)

    def clear_session(self, session_id: str) -> None:
        """Remove all messages for a session."""
        with self._lock:
            self._sessions.pop(session_id, None)

    @property
    def active_sessions(self) -> int:
        """Number of sessions with messages."""
        with self._lock:
            return len(self._sessions)


# Patterns that suggest PII is being split across messages
_SPLIT_PREAMBLES = [
    re.compile(r"(?:my|the)\s+(?:social security|ssn|ss number)", re.IGNORECASE),
    re.compile(r"(?:my|the)\s+(?:credit card|card number|cc number)", re.IGNORECASE),
    re.compile(r"(?:my|the)\s+(?:account|routing)\s+number", re.IGNORECASE),
    re.compile(r"(?:my|the)\s+(?:password|pin|passcode)\s+is", re.IGNORECASE),
    re.compile(r"(?:my|the)\s+(?:api|access|secret)\s+key", re.IGNORECASE),
]

# Patterns for numbers expressed as words
_NUMBER_WORDS = re.compile(
    r"\b(?:zero|one|two|three|four|five|six|seven|eight|nine|"
    r"ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|"
    r"eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|"
    r"hundred|thousand)\b",
    re.IGNORECASE,
)

# SSN-like digit patterns (when combined across messages)
_SSN_COMBINED = re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b")
_CC_COMBINED = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")


class ContextAnalyzer:
    """Analyzes multi-turn context for split-message PII evasion.

    Stateless analyzer - pass it a message window from SessionTracker.

    Strategies:
        1. Preamble + digits: "My SSN is" followed by numbers
        2. Combined text scan: concatenate all messages, run PII regex
        3. Number word detection: "one two three" pattern
    """

    def __init__(self, min_messages: int = 2) -> None:
        """Initialize analyzer.

        Args:
            min_messages: Minimum messages needed for analysis.
        """
        self._min_messages = min_messages

    def analyze(self, messages: list[Message]) -> ContextResult:
        """Analyze a message window for split-message evasion.

        Args:
            messages: Recent messages (from SessionTracker.get_window).

        Returns:
            ContextResult indicating if evasion was detected.
        """
        if len(messages) < self._min_messages:
            return ContextResult(
                is_suspicious=False,
                messages_analyzed=len(messages),
            )

        # Strategy 1: Preamble in earlier message + digits in later
        preamble_result = self._check_preamble_then_digits(messages)
        if preamble_result.is_suspicious:
            return preamble_result

        # Strategy 2: Number words spanning messages
        number_words_result = self._check_number_words(messages)
        if number_words_result.is_suspicious:
            return number_words_result

        # Strategy 3: Concatenate and scan for PII patterns
        combined_result = self._check_combined_text(messages)
        if combined_result.is_suspicious:
            return combined_result

        return ContextResult(
            is_suspicious=False,
            messages_analyzed=len(messages),
        )

    def _check_preamble_then_digits(self, messages: list[Message]) -> ContextResult:
        """Check if a PII preamble in one message is followed by digits."""
        for i, msg in enumerate(messages[:-1]):
            for pattern in _SPLIT_PREAMBLES:
                if pattern.search(msg.text):
                    # Look for digits in subsequent messages
                    for j in range(i + 1, len(messages)):
                        later_text = messages[j].text
                        digit_count = sum(c.isdigit() for c in later_text)
                        if digit_count >= 4:
                            combined = " ".join(m.text for m in messages[i : j + 1])
                            return ContextResult(
                                is_suspicious=True,
                                reason="PII preamble followed by digits across messages",
                                combined_text=combined,
                                confidence=0.9,
                                messages_analyzed=len(messages),
                            )
        return ContextResult(is_suspicious=False, messages_analyzed=len(messages))

    def _check_number_words(self, messages: list[Message]) -> ContextResult:
        """Check for numbers expressed as words across messages."""
        # Look at last 3 messages
        recent = messages[-3:]
        combined = " ".join(m.text for m in recent)

        word_matches = _NUMBER_WORDS.findall(combined)
        if len(word_matches) >= 5:
            # Check if there's also a preamble suggesting PII context
            all_text = " ".join(m.text for m in messages)
            for pattern in _SPLIT_PREAMBLES:
                if pattern.search(all_text):
                    return ContextResult(
                        is_suspicious=True,
                        reason="Number words with PII preamble context",
                        combined_text=combined,
                        confidence=0.85,
                        messages_analyzed=len(messages),
                    )

        return ContextResult(is_suspicious=False, messages_analyzed=len(messages))

    def _check_combined_text(self, messages: list[Message]) -> ContextResult:
        """Concatenate messages and scan for PII patterns."""
        combined = " ".join(m.text for m in messages)

        # Check for SSN pattern in combined text
        if _SSN_COMBINED.search(combined):  # noqa: SIM102
            # Verify it spans multiple messages (not in a single one)
            if not any(_SSN_COMBINED.search(m.text) for m in messages):
                return ContextResult(
                    is_suspicious=True,
                    reason="SSN pattern detected across combined messages",
                    combined_text=combined,
                    confidence=0.8,
                    messages_analyzed=len(messages),
                )

        # Check for credit card pattern in combined text
        if _CC_COMBINED.search(combined):  # noqa: SIM102
            if not any(_CC_COMBINED.search(m.text) for m in messages):
                return ContextResult(
                    is_suspicious=True,
                    reason="Credit card pattern detected across combined messages",
                    combined_text=combined,
                    confidence=0.8,
                    messages_analyzed=len(messages),
                )

        return ContextResult(is_suspicious=False, messages_analyzed=len(messages))
