"""Domestique OSS CLI - the developer wedge entry point.

Commands:
    domestique start [--host H] [--port P] [--no-setup]   launch the :8000 redacting proxy
    domestique demo                          show a before/after redaction, no key needed
    domestique setup [--yes]                 first-run onboarding wizard
    domestique browser on|off|status         toggle browser interception (dashboard API)
    domestique --version
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys

from domestique import __version__
from domestique.branding import LOGO, supports_unicode

_DASHBOARD_URL = "http://127.0.0.1:9876"

_DEMO_PROMPT = (
    "Here is my AWS key AKIAIOSFODNN7EXAMPLE and email jane.doe@corp.com, "
    "SSN 123-45-6789. Please help me debug this."
)

# Backwards-compatible aliases: the logo and unicode probe moved to
# domestique.branding (shared with the app launcher), but tests and callers
# still reference / monkeypatch these module-level names.
_LOGO = LOGO
_supports_unicode = supports_unicode


def _banner(host: str, port: int) -> str:
    url = f"http://{host}:{port}"
    if _supports_unicode():
        rule, active, check, arrow = "─" * 60, "►", "✔", "→"
    else:
        rule, active, check, arrow = "-" * 60, ">", "+", "->"
    return (
        _LOGO
        + "  [OSS PROXY]\n"
        + rule
        + "\n"
        + f"  [{active}] DomestiqueCore active on {url}\n"
        + f"  [{check}] Intercepting outbound prompts {arrow} redacting secrets & PII\n"
        + rule
        + "\n"
        + "  Point your agent at it (keep your own API key):\n"
        + f"    export OPENAI_BASE_URL={url}/v1\n"
        + f"    export ANTHROPIC_BASE_URL={url}\n"
        + "  Redact by default.  Press Ctrl-C to stop.\n"
    )


_SETUP_LATER_HINT = (
    "Continuing with regex-only detection (run 'domestique setup' in another terminal anytime)."
)


def _maybe_offer_first_run_setup(no_setup: bool) -> None:
    """Offer the setup wizard on the very first ``domestique start``.

    Only fires when ALL of these hold: --no-setup was not passed, no
    ~/.domestique/config.json exists yet, and stdin is an interactive TTY
    (never prompt in pipes/CI). Declining continues with regex-only
    detection; accepting runs the full wizard (which ends with the
    in-process demo) before the server starts.
    """
    if no_setup:
        return
    from domestique import setup_wizard

    if (setup_wizard.DOMESTIQUE_HOME / "config.json").exists():
        return
    # stdin can be None (pythonw, GUI launchers) or already closed (some
    # service managers) — both must mean "not interactive", never a crash.
    try:
        interactive = sys.stdin is not None and sys.stdin.isatty()
    except ValueError:
        interactive = False
    if not interactive:
        return
    # eof_default=False: a stream that passes isatty() but immediately EOFs
    # (canonical: `docker run -t` without -i) must DECLINE — auto-accepting
    # would install extras and pull multi-GB models unattended mid-`start`.
    if setup_wizard.prompt_yes_no(
        "First run - configure detection tiers now?", default=True, eof_default=False
    ):
        try:
            setup_wizard.run_wizard()
        except SystemExit as exc:
            # A failed install step must not kill `domestique start`;
            # regex-only protection still works with zero downloads.
            print(f"Setup did not complete (exit: {exc.code}).")
            print(_SETUP_LATER_HINT)
    else:
        print(_SETUP_LATER_HINT)


def _cmd_start(host: str, port: int, *, no_setup: bool = False) -> int:
    import uvicorn

    from domestique.gateway import create_gateway

    # Best effort: make the console UTF-8 so the banner glyphs render on Windows.
    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

    _maybe_offer_first_run_setup(no_setup)

    print(_banner(host, port))
    uvicorn.run(create_gateway(), host=host, port=port)
    return 0


def _cmd_setup(yes: bool) -> int:
    from domestique.setup_wizard import run_wizard

    try:
        return run_wizard(yes=yes)
    except KeyboardInterrupt:
        print("\n  cancelled — nothing was installed or changed.")
        return 130


def _browser_unreachable_hint() -> None:
    """Explain how to get the dashboard app, without ever importing it."""
    import importlib.util

    if importlib.util.find_spec("app") is None:
        print("Browser protection needs the dashboard app, which is not installed.")
        print('Install it with:  pipx inject domestique "domestique[browser-proxy]"')
        print('  (or in a plain venv: pip install "domestique[browser-proxy]")')
    else:
        # `--mode portable` works on a core install everywhere; bare
        # `python -m app` needs the [macos-native] extra on macOS.
        print("dashboard app isn't running (or didn't respond) - start it with:")
        print("  python -m app --mode portable")


def _cmd_browser(action: str, url: str) -> int:
    """Toggle/inspect browser interception via the local dashboard HTTP API.

    Talks HTTP only (architecture rule: domestique/ never imports app/).
    Uses the browser-proxy endpoints exclusively, so the API-proxy state
    (proxy_enabled) is never touched.
    """
    import urllib.error
    import urllib.request

    endpoints = {
        "on": ("POST", "/api/browser-proxy/start"),
        "off": ("POST", "/api/browser-proxy/stop"),
        "status": ("GET", "/api/browser-proxy"),
    }
    method, path = endpoints[action]
    req = urllib.request.Request(  # noqa: S310  # local dashboard URL, http only
        url.rstrip("/") + path,
        method=method,
        data=b"" if method == "POST" else None,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("error", "")
        except (json.JSONDecodeError, OSError):
            detail = ""
        print(f"error: dashboard API returned {exc.code}" + (f" - {detail}" if detail else ""))
        return 1
    except (urllib.error.URLError, TimeoutError, OSError):
        _browser_unreachable_hint()
        return 1

    if action == "status":
        running = bool(payload.get("running", False))
        print(f"browser protection: {'on' if running else 'off'}")
        print(f"  setup complete: {payload.get('setup_complete', False)}")
        domains = payload.get("intercepted_domains")
        if isinstance(domains, list) and domains:
            print(f"  intercepted domains: {len(domains)}")
        return 0

    if payload.get("ok"):
        already = " (was already on)" if payload.get("already_running") else ""
        print(f"browser protection turned {action}{already}")
        return 0
    print(f"error: {payload.get('error', 'unexpected dashboard response')}")
    return 1


def run_demo(*, interactive: bool | None = None) -> int:
    """Canned before/after redaction, then (on a TTY) an interactive loop.

    ``interactive=None`` auto-detects: the try-your-own loop only runs when
    stdin is a real TTY, so pipes/CI/subprocess smoke tests see exactly the
    canned output and exit.
    """
    from domestique.gateway import build_wedge_pipeline

    pipeline = build_wedge_pipeline()
    result = asyncio.run(pipeline.inspect(_DEMO_PROMPT))
    after = result.redacted_text or _DEMO_PROMPT
    print("Domestique demo - watch it redact secrets before they reach the LLM.\n")
    print("BEFORE:\n" + _DEMO_PROMPT + "\n")
    print("AFTER (sent to the model):\n" + after + "\n")
    if result.findings:
        print("Findings: " + ", ".join(f.description for f in result.findings))

    if interactive is None:
        try:
            interactive = sys.stdin is not None and sys.stdin.isatty()
        except ValueError:
            interactive = False
    if interactive:
        print("\nNow try your own - paste a prompt with (fake!) secrets, Enter to finish.")
        while True:
            try:
                text = input("\nprompt> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not text:
                break
            res = asyncio.run(pipeline.inspect(text))
            print("AFTER:    " + (res.redacted_text or text))
            if res.findings:
                print("Findings: " + ", ".join(f.description for f in res.findings))
            else:
                print("Findings: none - nothing sensitive detected")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="domestique", description="Domestique OSS CLI wedge")
    parser.add_argument("--version", action="version", version=f"domestique {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    start = sub.add_parser("start", help="launch the :8000 redacting proxy")
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--port", type=int, default=8000)
    start.add_argument(
        "--no-setup",
        action="store_true",
        help="skip the first-run setup offer",
    )

    sub.add_parser("demo", help="show a before/after redaction (no API key needed)")

    setup = sub.add_parser("setup", help="first-run onboarding wizard (hardware-aware)")
    setup.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="accept all recommended defaults (non-interactive)",
    )

    browser = sub.add_parser("browser", help="toggle browser interception via the dashboard")
    browser.add_argument("action", choices=["on", "off", "status"])
    browser.add_argument(
        "--url",
        default=_DASHBOARD_URL,
        help=f"dashboard API base URL (default: {_DASHBOARD_URL})",
    )

    args = parser.parse_args(argv)
    if args.cmd == "start":
        return _cmd_start(args.host, args.port, no_setup=args.no_setup)
    if args.cmd == "demo":
        return run_demo()
    if args.cmd == "setup":
        return _cmd_setup(args.yes)
    if args.cmd == "browser":
        return _cmd_browser(args.action, args.url)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
