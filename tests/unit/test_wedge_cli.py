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


def test_start_is_wired(monkeypatch):
    calls = {}

    def fake_run(app, host, port, **kw):
        calls["host"] = host
        calls["port"] = port

    monkeypatch.setattr("uvicorn.run", fake_run)
    rc = main(["start", "--port", "8111"])
    assert rc == 0
    assert calls["host"] == "127.0.0.1"
    assert calls["port"] == 8111
