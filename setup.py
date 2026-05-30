"""py2app build configuration for LLMGuard.app."""

import sys
sys.setrecursionlimit(5000)

from setuptools import setup

APP = ["app_entry.py"]
DATA_FILES = [
    ("", ["app/assets/dashboard.html"]),
    ("assets", ["app/assets/icon.icns", "app/assets/icon.png"]),
    ("assets/images", [
        "app/assets/images/logo-512.png",
        "app/assets/images/menubar-icon.png",
        "app/assets/images/menubar-icon@2x.png",
        "app/assets/images/menubar-icon-disabled.png",
        "app/assets/images/menubar-icon-disabled@2x.png",
    ]),
]

OPTIONS = {
    "argv_emulation": False,
    "iconfile": "app/assets/icon.icns",
    "plist": {
        "CFBundleName": "LLMGuard",
        "CFBundleDisplayName": "LLMGuard",
        "CFBundleIdentifier": "com.enterprise.llmguard",
        "CFBundleVersion": "1.0.0",
        "CFBundleShortVersionString": "1.0",
        "LSUIElement": False,  # Show in Dock with our icon
        "NSHighResolutionCapable": True,
    },
    "packages": ["rumps", "app", "llmguard"],
    "excludes": ["mitmproxy", "pytest", "torch", "transformers", "tensorflow", "torchaudio", "torchvision"],
    "includes": ["json", "subprocess", "threading", "pathlib", "objc",
                 "AppKit", "WebKit", "Foundation"],
}

setup(
    name="LLMGuard",
    app=APP,
    data_files=DATA_FILES,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
