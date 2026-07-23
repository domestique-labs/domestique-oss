"""Approach C: opt-in enriched block toast (category + score). Default off.

The coalescer defers notify() until its window timer elapses (see
tests/unit/test_notification_coalescing.py), so these tests inject a fake,
synchronous timer via a dedicated NotificationCoalescer instance - the same
technique the existing coalescing tests use - rather than sleeping in real
time on the process-wide default coalescer.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from domestique_app.services import notifications as notif
from domestique_app.services.notifications import NotificationCoalescer


class _FakeTimer:
    """Stand-in for threading.Timer that fires synchronously on demand."""

    instances: list[_FakeTimer] = []

    def __init__(self, interval, function, args=None, kwargs=None):
        self.interval = interval
        self.function = function
        self.args = args or ()
        self.kwargs = kwargs or {}
        self.daemon = False

    def start(self):
        _FakeTimer.instances.append(self)

    def fire(self):
        self.function(*self.args, **self.kwargs)


def _make_coalescer(notify_fn):
    _FakeTimer.instances.clear()
    return NotificationCoalescer(window_seconds=5.0, notify_fn=notify_fn, timer_factory=_FakeTimer)


class TestEnrichedToast:
    def test_detail_omitted_by_default(self):
        """With the setting off (default), the toast body must NOT include the
        category - only host + count, as before."""
        notify_fn = MagicMock()
        coalescer = _make_coalescer(notify_fn)

        with (
            patch.object(notif, "get_default_coalescer", return_value=coalescer),
            patch.object(notif, "_toast_detail_enabled", return_value=False),
        ):
            notif.notify_block("chatgpt.com", detail="US SSN (92%)")
            # _toast_detail_enabled must still be patched when the window
            # elapses - _flush() is what actually consults it.
            _FakeTimer.instances[0].fire()

        notify_fn.assert_called_once_with("Domestique", "Blocked a leak to chatgpt.com")
        for call in notify_fn.call_args_list:
            assert "SSN" not in " ".join(str(a) for a in call.args)

    def test_detail_included_when_enabled(self):
        notify_fn = MagicMock()
        coalescer = _make_coalescer(notify_fn)

        with (
            patch.object(notif, "get_default_coalescer", return_value=coalescer),
            patch.object(notif, "_toast_detail_enabled", return_value=True),
        ):
            notif.notify_block("chatgpt.com", detail="US SSN (92%)")
            _FakeTimer.instances[0].fire()

        joined = " ".join(" ".join(str(a) for a in c.args) for c in notify_fn.call_args_list)
        assert "SSN" in joined

    def test_detail_enabled_but_not_supplied_stays_plain(self):
        """Enabling the setting doesn't fabricate a category out of nothing -
        no detail passed in means the plain host+count message."""
        notify_fn = MagicMock()
        coalescer = _make_coalescer(notify_fn)

        with (
            patch.object(notif, "get_default_coalescer", return_value=coalescer),
            patch.object(notif, "_toast_detail_enabled", return_value=True),
        ):
            notif.notify_block("chatgpt.com")
            _FakeTimer.instances[0].fire()

        notify_fn.assert_called_once_with("Domestique", "Blocked a leak to chatgpt.com")

    def test_notify_block_still_never_raises_with_detail_kwarg(self):
        """detail is purely additive - the block-path safety guarantee holds."""
        notify_fn = MagicMock(side_effect=RuntimeError("boom"))
        coalescer = _make_coalescer(notify_fn)

        with (
            patch.object(notif, "get_default_coalescer", return_value=coalescer),
            patch.object(notif, "_toast_detail_enabled", return_value=True),
        ):
            notif.notify_block("chatgpt.com", detail="US SSN (92%)")
            _FakeTimer.instances[0].fire()  # must not raise


class TestToastDetailEnabled:
    def test_default_is_false_when_config_missing_key(self):
        with patch(
            "domestique_app.services.pipeline_config.load_config_dict",
            return_value={},
        ):
            assert notif._toast_detail_enabled() is False

    def test_true_when_config_opts_in(self):
        with patch(
            "domestique_app.services.pipeline_config.load_config_dict",
            return_value={"toast_detail_enabled": True},
        ):
            assert notif._toast_detail_enabled() is True

    def test_false_on_config_read_failure(self):
        with patch(
            "domestique_app.services.pipeline_config.load_config_dict",
            side_effect=RuntimeError("boom"),
        ):
            assert notif._toast_detail_enabled() is False
