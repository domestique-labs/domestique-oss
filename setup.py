"""py2app build configuration for Domestique.app.

This file is ONLY the macOS app-bundle build. Normal installs (pip / pipx /
``python -m build``) are driven entirely by ``pyproject.toml`` — so unless the
``py2app`` command is explicitly invoked, we fall through to a bare ``setup()``
that lets setuptools read pyproject (packages, entry points, package-data).
This keeps ``pipx install domestique`` clean while preserving
``python setup.py py2app`` for the native build.
"""

import sys

from setuptools import setup

if "py2app" not in sys.argv:
    # pyproject-driven build (pip / pipx / build). Do not pull in py2app.
    setup()
else:
    sys.setrecursionlimit(5000)

    APP = ["app_entry.py"]
    DATA_FILES = [
        ("", ["domestique_app/assets/dashboard.html"]),
        ("assets", ["domestique_app/assets/icon.icns", "domestique_app/assets/icon.png"]),
        (
            "assets/images",
            [
                "domestique_app/assets/images/logo-512.png",
                "domestique_app/assets/images/menubar-icon.png",
                "domestique_app/assets/images/menubar-icon@2x.png",
                "domestique_app/assets/images/menubar-icon-disabled.png",
                "domestique_app/assets/images/menubar-icon-disabled@2x.png",
            ],
        ),
    ]

    OPTIONS = {
        "argv_emulation": False,
        "iconfile": "domestique_app/assets/icon.icns",
        "plist": {
            "CFBundleName": "Domestique",
            "CFBundleDisplayName": "Domestique",
            "CFBundleIdentifier": "com.domestique.app",
            "CFBundleVersion": "1.0.0",
            "CFBundleShortVersionString": "1.0",
            "LSUIElement": False,  # Show in Dock with our icon
            "NSHighResolutionCapable": True,
        },
        "packages": ["rumps", "domestique_app", "domestique"],
        "excludes": [
            "mitmproxy",
            "pytest",
            "torch",
            "transformers",
            "tensorflow",
            "torchaudio",
            "torchvision",
        ],
        "includes": [
            "json",
            "subprocess",
            "threading",
            "pathlib",
            "objc",
            "AppKit",
            "WebKit",
            "Foundation",
        ],
    }

    setup(
        name="Domestique",
        app=APP,
        data_files=DATA_FILES,
        options={"py2app": OPTIONS},
        setup_requires=["py2app"],
    )
