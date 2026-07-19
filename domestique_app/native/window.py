"""Main application window with embedded WKWebView.

Displays the dashboard HTML inside a native macOS window,
providing a seamless configuration experience.
"""

from __future__ import annotations

from pathlib import Path

from AppKit import (
    NSApp,
    NSBackingStoreBuffered,
    NSMakeRect,
    NSWindow,
    NSWindowStyleMaskClosable,
    NSWindowStyleMaskMiniaturizable,
    NSWindowStyleMaskResizable,
    NSWindowStyleMaskTitled,
)
from Foundation import NSURL
from WebKit import WKWebView, WKWebViewConfiguration

# Autoresizing mask: flexible width (0x02) + flexible height (0x10)
_AUTORESIZE_FLEX = 0x02 | 0x10

DASHBOARD_PATH = Path(__file__).parent.parent / "assets" / "dashboard.html"


class MainWindow:
    """Native macOS window embedding the dashboard web view.

    The window can be shown/hidden without being destroyed, preserving
    the web view state across open/close cycles.
    """

    TITLE = "Domestique"
    DEFAULT_SIZE = (960, 720)

    def __init__(self) -> None:
        self._window = self._create_window()
        self._webview = self._create_webview()
        self._window.contentView().addSubview_(self._webview)
        self._load_dashboard()

    def show(self) -> None:
        """Show and activate the window."""
        self._window.makeKeyAndOrderFront_(None)
        NSApp.activateIgnoringOtherApps_(True)

    def hide(self) -> None:
        """Hide the window without destroying it."""
        self._window.orderOut_(None)

    @property
    def is_visible(self) -> bool:
        """Whether the window is currently on screen."""
        return self._window.isVisible()

    def _create_window(self) -> NSWindow:
        """Create the NSWindow with standard chrome."""
        w, h = self.DEFAULT_SIZE
        style = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskMiniaturizable
            | NSWindowStyleMaskResizable
        )
        window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, w, h),
            style,
            NSBackingStoreBuffered,
            False,
        )
        window.setTitle_(self.TITLE)
        window.center()
        window.setReleasedWhenClosed_(False)
        return window

    def _create_webview(self) -> WKWebView:
        """Create a WKWebView filling the content area."""
        config = WKWebViewConfiguration.new()
        webview = WKWebView.alloc().initWithFrame_configuration_(
            self._window.contentView().bounds(),
            config,
        )
        webview.setAutoresizingMask_(_AUTORESIZE_FLEX)
        return webview

    def _load_dashboard(self) -> None:
        """Load the dashboard HTML into the web view (cache-busted)."""
        if DASHBOARD_PATH.exists():
            import time

            int(time.time())
            url = NSURL.fileURLWithPath_(str(DASHBOARD_PATH))
            # Force reload by using loadFileURL which doesn't cache as aggressively
            self._webview.loadFileURL_allowingReadAccessToURL_(
                url,
                NSURL.fileURLWithPath_(str(DASHBOARD_PATH.parent)),
            )
