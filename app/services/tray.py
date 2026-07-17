"""Windows system tray icon for Domestique.

Mirrors the macOS StatusBar: shows a shield icon in the notification area
with a right-click menu for toggling protection, opening the dashboard,
and quitting. Icon changes to reflect active/inactive state.
"""

from __future__ import annotations

import threading
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    import pystray
    from PIL.Image import Image

_ASSETS = Path(__file__).parent.parent / "assets" / "images"
_ICON_PATH = _ASSETS / "logo-64.png"
_FALLBACK_ICON = Path(__file__).parent.parent / "assets" / "icon.png"


def _load_icon() -> Image:
    """Load the tray icon image via Pillow."""
    from PIL import Image

    for path in (_ICON_PATH, _FALLBACK_ICON):
        if path.exists():
            return Image.open(path)
    # Generate a simple fallback icon
    img = Image.new("RGBA", (64, 64), (16, 185, 129, 255))
    return img


class SystemTray:
    """Windows notification-area (system tray) icon with context menu.

    Provides the same functionality as the macOS StatusBar:
    - Shield icon indicating protection status
    - Right-click menu: toggle protection, open dashboard, quit

    Usage:
        tray = SystemTray(
            on_toggle=my_toggle_fn,
            on_quit=my_quit_fn,
            dashboard_url="http://127.0.0.1:9876",
        )
        tray.start()  # runs in background thread
        tray.set_active(True)
    """

    def __init__(
        self,
        *,
        on_toggle: Callable[[], None],
        on_quit: Callable[[], None],
        dashboard_url: str = "http://127.0.0.1:9876",
    ) -> None:
        self._on_toggle = on_toggle
        self._on_quit = on_quit
        self._dashboard_url = dashboard_url
        self._active = False
        self._icon = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the tray icon in a background thread."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        import pystray

        image = _load_icon()

        menu = pystray.Menu(
            pystray.MenuItem(
                lambda _: "✅ Protection Active" if self._active else "❌ Protection Inactive",
                self._handle_toggle,
                default=True,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open Dashboard", self._handle_dashboard),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit Domestique", self._handle_quit),
        )

        self._icon = pystray.Icon(
            name="Domestique",
            icon=image,
            title="Domestique — Protection Inactive",
            menu=menu,
        )
        self._icon.run()

    def set_active(self, active: bool) -> None:
        """Update the tray icon tooltip to reflect protection state."""
        self._active = active
        if self._icon:
            status = "Active" if active else "Inactive"
            self._icon.title = f"Domestique — Protection {status}"

    def stop(self) -> None:
        """Remove the tray icon."""
        if self._icon:
            self._icon.stop()

    def _handle_toggle(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:
        self._on_toggle()

    def _handle_dashboard(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:
        webbrowser.open(self._dashboard_url)

    def _handle_quit(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:
        self._on_quit()
