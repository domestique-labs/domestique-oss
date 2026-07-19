"""Domestique desktop application.

Provides data loss prevention controls for LLM API traffic.
On macOS it can use the native AppKit shell; on Windows and Linux it runs the
same local API with the dashboard in the default browser.

- Real-time firewall status and controls
- Visual configuration of the detection stack
- One-click benchmark execution with interactive reports
- Proxy lifecycle management

Architecture:
    app/
    |---- __init__.py          ← Package root, version
    |---- __main__.py          ← Entry point (python -m domestique_app)
    |---- config/              ← Configuration management
    |     |---- schema.py        ← Typed config schema and defaults
    |     `---- store.py         ← Load/save/validate operations
    |---- services/            ← Backend services (no UI coupling)
    |     |---- proxy.py         ← Firewall proxy lifecycle
    |     `---- benchmark.py     ← Benchmark runner with progress
    |---- server/              ← HTTP API for dashboard ↔ backend
    |     `---- api.py           ← REST endpoints on localhost:9876
    |---- native/              ← macOS-specific UI (PyObjC)
    |     |---- app_delegate.py  ← NSApplication delegate
    |     |---- status_bar.py    ← Menu bar icon and menu
    |     `---- window.py        ← Main window with WKWebView
    |---- assets/              ← Static files (HTML, icons)
    |     |---- dashboard.html   ← Configuration UI
    |     |---- icon.png         ← App icon (1024x1024)
    |     `---- icon.icns        ← macOS icon bundle
    `---- tests/               ← Unit and integration tests
        |---- test_config.py
        |---- test_services.py
        `---- test_server.py
"""

__version__ = "1.0.0"
__app_name__ = "LLM Firewall"
