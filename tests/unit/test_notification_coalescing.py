"""Tests for coalesced desktop "blocked" notifications.

A single browser prompt can fan out into several proxied requests (the
message itself plus background autocomplete/title-generation calls), each
of which may get blocked independently. NotificationCoalescer exists so
that burst of blocks collapses into a single toast per host per window
instead of spamming the user with one notification per blocked request.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from domestique_app.services.notifications import NotificationCoalescer


class _FakeTimer:
    """Stand-in for threading.Timer that runs synchronously on demand.

    Captures the callback instead of scheduling it on a background thread,
    so tests can deterministically simulate "the window elapsed" by calling
    fire() rather than sleeping in real time.
    """

    instances: list["_FakeTimer"] = []

    def __init__(self, interval, function, args=None, kwargs=None):
        self.interval = interval
        self.function = function
        self.args = args or ()
        self.kwargs = kwargs or {}
        self.daemon = False
        self.started = False
        _FakeTimer.instances.append(self)

    def start(self):
        self.started = True

    def fire(self):
        self.function(*self.args, **self.kwargs)


def _make_coalescer(notify_fn):
    _FakeTimer.instances.clear()
    return NotificationCoalescer(
        window_seconds=5.0,
        notify_fn=notify_fn,
        timer_factory=_FakeTimer,
    )


class TestNotificationCoalescing:
    def test_single_block_emits_one_notification(self):
        notify_fn = MagicMock()
        coalescer = _make_coalescer(notify_fn)

        coalescer.record_block("chatgpt.com")
        assert notify_fn.call_count == 0  # deferred until window elapses

        _FakeTimer.instances[0].fire()

        notify_fn.assert_called_once_with("Domestique", "Blocked a leak to chatgpt.com")

    def test_many_blocks_within_window_emit_one_notification(self):
        """N block events within the coalescing window -> exactly 1 notify() call."""
        notify_fn = MagicMock()
        coalescer = _make_coalescer(notify_fn)

        for _ in range(6):
            coalescer.record_block("chatgpt.com")

        # Only the first record_block() in a window should schedule a timer.
        assert len(_FakeTimer.instances) == 1

        _FakeTimer.instances[0].fire()

        notify_fn.assert_called_once_with("Domestique", "Blocked 6 requests to chatgpt.com")

    def test_different_hosts_get_independent_windows(self):
        notify_fn = MagicMock()
        coalescer = _make_coalescer(notify_fn)

        coalescer.record_block("chatgpt.com")
        coalescer.record_block("chatgpt.com")
        coalescer.record_block("claude.ai")

        assert len(_FakeTimer.instances) == 2
        for timer in _FakeTimer.instances:
            timer.fire()

        assert notify_fn.call_count == 2
        notify_fn.assert_any_call("Domestique", "Blocked 2 requests to chatgpt.com")
        notify_fn.assert_any_call("Domestique", "Blocked a leak to claude.ai")

    def test_new_window_opens_after_previous_flush(self):
        """After a window flushes, a fresh block should start a new window/notification."""
        notify_fn = MagicMock()
        coalescer = _make_coalescer(notify_fn)

        coalescer.record_block("chatgpt.com")
        _FakeTimer.instances[0].fire()
        notify_fn.assert_called_once_with("Domestique", "Blocked a leak to chatgpt.com")

        coalescer.record_block("chatgpt.com")
        assert len(_FakeTimer.instances) == 2
        _FakeTimer.instances[1].fire()

        assert notify_fn.call_count == 2
        notify_fn.assert_called_with("Domestique", "Blocked a leak to chatgpt.com")

    def test_notify_failure_does_not_raise(self):
        """A notify() failure must never propagate - block path safety."""
        notify_fn = MagicMock(side_effect=RuntimeError("boom"))
        coalescer = _make_coalescer(notify_fn)

        coalescer.record_block("chatgpt.com")
        _FakeTimer.instances[0].fire()  # must not raise

        notify_fn.assert_called_once()

    def test_notify_block_helper_never_raises(self):
        """notify_block() (the entry point mitm_addon.py calls) must never
        raise, even if scheduling/coalescing itself blows up."""
        from domestique_app.services import notifications as notifications_module

        original_get_default = notifications_module.get_default_coalescer

        class _ExplodingCoalescer:
            def record_block(self, host):
                raise RuntimeError("boom")

        notifications_module.get_default_coalescer = lambda: _ExplodingCoalescer()
        try:
            notifications_module.notify_block("chatgpt.com")  # must not raise
        finally:
            notifications_module.get_default_coalescer = original_get_default
