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
        calls["kw"] = kw

    monkeypatch.setattr("uvicorn.run", fake_run)
    rc = main(["start", "--port", "8111"])
    assert rc == 0
    assert calls["host"] == "127.0.0.1"
    assert calls["port"] == 8111
    # one voice by default: uvicorn's own access log is silenced so it doesn't
    # speak over the ticker (the ticker is the single per-request signal).
    assert calls["kw"].get("access_log") is False
    assert calls["kw"].get("log_level") == "warning"

    # the start banner is printed before the server launches
    out = capsys.readouterr().out
    assert "Domestique Proxy active on http://127.0.0.1:8111" in out
    assert "DomestiqueCore" not in out  # renamed
    assert "[OSS PROXY]" in out
    assert "export OPENAI_BASE_URL=http://127.0.0.1:8111/v1" in out
    # the policy location is shown cleanly in the banner (replaces the raw
    # `policy_loaded` structlog line the user asked to have surfaced here).
    assert "Policy" in out
    assert "cli-rules.yaml" in out


def test_start_access_log_flag_restores_uvicorn_logs(monkeypatch):
    calls = {}

    def fake_run(app, host, port, **kw):
        calls["kw"] = kw

    monkeypatch.setattr("uvicorn.run", fake_run)
    rc = main(["start", "--port", "8112", "--access-log"])
    assert rc == 0
    assert calls["kw"].get("access_log") is True
    assert calls["kw"].get("log_level") == "info"


def test_banner_has_ascii_fallback(monkeypatch):
    from domestique import cli

    # when the console can't encode the fancy glyphs, fall back to plain ASCII
    monkeypatch.setattr(cli, "_supports_unicode", lambda: False)
    banner = cli._banner(
        "127.0.0.1", 8000, policy="policy/cli-rules.yaml (14 rules, redact-first)"
    )
    assert banner.encode("ascii")  # must be pure ASCII, no exception
    assert "[>]" in banner and "[+]" in banner
    assert "Domestique Proxy active on" in banner
    assert "Policy" in banner and "cli-rules.yaml" in banner
