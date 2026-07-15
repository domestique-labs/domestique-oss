from __future__ import annotations

import pytest

from domestique.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "domestique" in out.lower()


def test_demo_redacts_and_prints(capsys):
    rc = main(["demo"])
    out = capsys.readouterr().out
    assert rc == 0
    after_block = out.split("AFTER")[-1]
    assert "AKIAIOSFODNN7EXAMPLE" not in after_block
    assert "REDACTED" in out


def test_start_is_wired(monkeypatch, capsys):
    calls = {}

    def fake_run(app, host, port, **kw):
        calls["host"] = host
        calls["port"] = port

    monkeypatch.setattr("uvicorn.run", fake_run)
    rc = main(["start", "--port", "8111"])
    assert rc == 0
    assert calls["host"] == "127.0.0.1"
    assert calls["port"] == 8111

    # the start banner is printed before the server launches
    out = capsys.readouterr().out
    assert "DomestiqueCore active on http://127.0.0.1:8111" in out
    assert "[OSS PROXY]" in out
    assert "export OPENAI_BASE_URL=http://127.0.0.1:8111/v1" in out


def test_banner_has_ascii_fallback(monkeypatch):
    from domestique import cli

    # when the console can't encode the fancy glyphs, fall back to plain ASCII
    monkeypatch.setattr(cli, "_supports_unicode", lambda: False)
    banner = cli._banner("127.0.0.1", 8000)
    assert banner.encode("ascii")  # must be pure ASCII, no exception
    assert "[>]" in banner and "[+]" in banner
