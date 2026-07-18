#!/usr/bin/env python3
"""Domestique app bundle entry point (py2app)."""
import sys
import os

sys.setrecursionlimit(10000)

# Ensure project root is importable
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

os.environ.setdefault("HF_HUB_OFFLINE", "1")

from domestique_app.main import launch
launch()
