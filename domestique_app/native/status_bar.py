"""Menu bar (status bar) icon and dropdown menu.

Displays the Domestique shield icon in the macOS menu bar - solid when
active, faded when disabled - like Notion and other native macOS apps.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from AppKit import (
    NSImage,
    NSMenu,
    NSMenuItem,
    NSSquareStatusItemLength,
    NSStatusBar,
)
from Foundation import NSSize

_ASSETS = Path(__file__).parent.parent / "assets" / "images"
_ICON_ACTIVE = _ASSETS / "menubar-icon@2x.png"
_ICON_DISABLED = _ASSETS / "menubar-icon-disabled@2x.png"


class StatusBar:
    """Manages the macOS menu bar status item.

    Shows a shield icon - solid when protection is active, faded/X when
    disabled. Uses template images so macOS handles light/dark mode.

    Args:
        delegate: The AppDelegate instance that handles menu actions.
    """

    # Class-level retain prevents garbage collection
    _instance = None

    def __init__(self, delegate: Any) -> None:
        self._delegate = delegate

        # Fixed square width (same as Notion, Dropbox, etc.)
        self._status_item = NSStatusBar.systemStatusBar().statusItemWithLength_(
            NSSquareStatusItemLength
        )
        # Strong retain at class level
        StatusBar._instance = self
        self._status_item.setVisible_(True)

        # Load icons
        self._icon_active = self._load_icon(_ICON_ACTIVE)
        self._icon_disabled = self._load_icon(_ICON_DISABLED)

        # Set initial icon
        button = self._status_item.button()
        if self._icon_active:
            button.setImage_(self._icon_active)
        else:
            # Text fallback if image fails
            button.setTitle_("🛡️")

        self._build_menu()

    def _load_icon(self, path: Path) -> NSImage | None:
        """Load a template image for the menu bar.

        Template images let macOS handle rendering (solid/faded, light/dark).
        """
        if not path.exists():
            return None
        icon = NSImage.alloc().initWithContentsOfFile_(str(path.resolve()))
        if icon:
            icon.setSize_(NSSize(18, 18))
            icon.setTemplate_(True)
        return icon

    def set_active(self, active: bool) -> None:
        """Update the status bar icon - solid when active, faded when disabled.

        Args:
            active: Whether the firewall protection is currently running.
        """
        button = self._status_item.button()
        if active:
            self._status_label.setTitle_("Protection: Active ✓")
            self._toggle_item.setTitle_("Disable Protection")
            if self._icon_active:
                button.setImage_(self._icon_active)
                button.setAppearsDisabled_(False)
            else:
                button.setTitle_("🛡️")
        else:
            self._status_label.setTitle_("Protection: Disabled ✗")
            self._toggle_item.setTitle_("Enable Protection")
            if self._icon_disabled:
                button.setImage_(self._icon_disabled)
                button.setAppearsDisabled_(True)
            else:
                button.setTitle_("⚠️")

    def _build_menu(self) -> None:
        """Construct the dropdown menu."""
        menu = NSMenu.new()

        # App name header (non-interactive)
        self._add_item(menu, "Domestique", action=None, enabled=False)

        # Status label
        self._status_label = self._add_item(
            menu, "Protection: Starting...", action=None, enabled=False
        )

        menu.addItem_(NSMenuItem.separatorItem())

        # Protection toggle
        # TODO(onboarding-wizard): mirror the pystray tray (app/services/tray.py),
        # which now has two independent items — "API Proxy: on/off" and
        # "Browser Protection: on/off". This menu still uses the single
        # all-or-nothing `toggleFirewall:` selector because the actual toggle
        # logic lives in app/native/app_delegate.py; splitting it requires a
        # new delegate action + state plumbing there and is scoped out of the
        # tray-decoupling change.
        self._toggle_item = self._add_item(menu, "Disable Protection", action="toggleFirewall:")

        menu.addItem_(NSMenuItem.separatorItem())

        # Window and tools
        self._add_item(menu, "Open Dashboard", action="showWindow:")
        self._add_item(menu, "Run Benchmark", action="runBenchmark:")
        self._add_item(menu, "View Last Report", action="viewReport:")

        menu.addItem_(NSMenuItem.separatorItem())

        # Quit
        quit_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Quit Domestique", "terminate:", "q"
        )
        menu.addItem_(quit_item)

        self._status_item.setMenu_(menu)

    def _add_item(
        self,
        menu: NSMenu,
        title: str,
        action: str | None,
        enabled: bool = True,
    ) -> NSMenuItem:
        """Add a menu item targeting the delegate.

        Args:
            menu: Parent menu to add to.
            title: Display text.
            action: Selector name (e.g., 'toggleFirewall:') or None.
            enabled: Whether the item is interactive.

        Returns:
            The created NSMenuItem.
        """
        item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(title, action, "")
        if action:
            item.setTarget_(self._delegate)
        item.setEnabled_(enabled)
        menu.addItem_(item)
        return item
