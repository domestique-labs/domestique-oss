"""Apple Silicon unified memory is not all available to a model.

`detect_gpu` reported installed unified memory as VRAM, so an 8 GB Mac cleared
the `quality` threshold (6 GB) and the wizard said gemma4:e4b — a 3.3 GB
download — "fits without swapping". macOS plus Metal's working-set cap leave
nowhere near that free, so the user paid for the download and then swapped.
"""

from __future__ import annotations

import pytest

from domestique.setup_wizard import (
    LLM_PRESETS,
    apple_usable_vram_gb,
    recommend_preset,
)


@pytest.mark.parametrize("installed", [4, 8, 16, 32, 64, 128])
def test_usable_is_always_below_installed(installed: int) -> None:
    assert apple_usable_vram_gb(installed) < installed


def test_eight_gb_mac_no_longer_gets_the_largest_model() -> None:
    """The regression this fixes, stated as a case."""
    installed = 8.0
    assert recommend_preset(installed, None, installed) == "quality"  # the old claim
    usable = apple_usable_vram_gb(installed)
    assert usable < LLM_PRESETS["quality"]["vram_gb"]
    assert recommend_preset(usable, None, installed) == "balanced"


@pytest.mark.parametrize("installed", [16.0, 24.0, 32.0, 64.0, 128.0])
def test_machines_with_real_headroom_are_unaffected(installed: float) -> None:
    """The fix must not punish machines that genuinely fit the big model."""
    assert recommend_preset(apple_usable_vram_gb(installed), None, installed) == "quality"


def test_reported_vram_matches_what_drives_the_recommendation(monkeypatch) -> None:
    """The displayed number and the decision must come from the same value.

    Printing installed memory while deciding on usable memory would leave the
    wizard explaining its choice with a figure that did not produce it.
    """
    import platform

    from domestique import setup_wizard as sw

    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(platform, "machine", lambda: "arm64")
    monkeypatch.setattr(sw, "detect_total_ram_gb", lambda: 8.0)
    monkeypatch.setattr(sw.shutil, "which", lambda _n: None)  # no nvidia-smi

    label, vram = sw.detect_gpu()
    assert vram == apple_usable_vram_gb(8.0)
    assert "8.0 GB" in label and f"{vram} GB usable" in label
