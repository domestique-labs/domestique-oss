"""Windows system tray icon for Domestique.

Mirrors the macOS StatusBar: shows a shield icon in the notification area
with a right-click menu for toggling protection, opening the dashboard,
and quitting. Icon changes to reflect active/inactive state.

The API proxy and browser protection are separate services with separate
config flags (proxy_enabled vs browser_interception), so the menu exposes
one independent toggle per service instead of a single all-or-nothing
switch.
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
    - Right-click menu: independent API-proxy / browser-protection
      toggles, open dashboard, quit

    Usage:
        tray = SystemTray(
            on_toggle_api=toggle_api_proxy_fn,
            on_toggle_browser=toggle_browser_fn,
            on_quit=my_quit_fn,
            dashboard_url="http://127.0.0.1:9876",
        )
        tray.start()  # runs in background thread
        tray.set_states(api_active=True, browser_active=False)
    """

    def __init__(
        self,
        *,
        on_toggle_api: Callable[[], None],
        on_toggle_browser: Callable[[], None],
        on_quit: Callable[[], None],
        dashboard_url: str = "http://127.0.0.1:9876",
    ) -> None:
        self._on_toggle_api = on_toggle_api
        self._on_toggle_browser = on_toggle_browser
        self._on_quit = on_quit
        self._dashboard_url = dashboard_url
        self._api_active = False
        self._browser_active = False
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
                lambda _: f"API Proxy: {'on' if self._api_active else 'off'}",
                self._handle_toggle_api,
                default=True,
            ),
            pystray.MenuItem(
                lambda _: f"Browser Protection: {'on' if self._browser_active else 'off'}",
                self._handle_toggle_browser,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open Dashboard", self._handle_dashboard),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit Domestique", self._handle_quit),
        )

        self._icon = pystray.Icon(
            name="Domestique",
            icon=image,
            title=self._tooltip(),
            menu=menu,
        )
        self._icon.run()

    def _tooltip(self) -> str:
        api = "on" if self._api_active else "off"
        browser = "on" if self._browser_active else "off"
        return f"Domestique — API Proxy: {api}, Browser: {browser}"

    def set_states(self, *, api_active: bool, browser_active: bool) -> None:
        """Update tooltip/menu state for both services independently."""
        self._api_active = api_active
        self._browser_active = browser_active
        if self._icon:
            self._icon.title = self._tooltip()
            # Menu labels are lazy callables; nudge pystray to re-render them.
            update = getattr(self._icon, "update_menu", None)
            if callable(update):
                update()

    def set_active(self, active: bool) -> None:
        """Back-compat single-switch state setter (treats both as one).

        Prefer :meth:`set_states`, which reflects each service on its own.
        """
        self.set_states(api_active=active, browser_active=active)

    def stop(self) -> None:
        """Remove the tray icon."""
        if self._icon:
            self._icon.stop()

    def _handle_toggle_api(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:
        self._on_toggle_api()

    def _handle_toggle_browser(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:
        self._on_toggle_browser()

    def _handle_dashboard(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:
        webbrowser.open(self._dashboard_url)

    def _handle_quit(self, icon: pystray.Icon, item: pystray.MenuItem) -> None:
        self._on_quit()
