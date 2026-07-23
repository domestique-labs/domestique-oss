"""Domestique OSS CLI - the developer wedge entry point.

Commands:
    domestique start [--host H] [--port P] [--no-setup] [--quiet] [--strict] [--access-log]
                                             launch the :8000 redacting proxy
    domestique demo                          show a before/after redaction, no key needed
    domestique report [--json] [--days N]    summarize redactions & blocks by type
    domestique setup [--yes]                 first-run onboarding wizard
    domestique browser [on|off|status]       bare = set up & launch; on/off/status control
    domestique --version
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import webbrowser
from typing import TYPE_CHECKING, Any, cast

from domestique import __version__, console
from domestique.branding import LOGO, supports_unicode
from domestique.detectors.status import detector_status, unavailable_configured
from domestique.labels import label as _label
from domestique.models import Action

if TYPE_CHECKING:
    from collections.abc import Callable

    from domestique.config import Settings
    from domestique.detectors.registry import Finding
    from domestique.detectors.status import TierStatus
    from domestique.policy import PolicyEngine

_DASHBOARD_URL = "http://127.0.0.1:9876"

_APP_MODULE = "domestique_app"

_DEMO_PROMPT = (
    "Here is my AWS key AKIAIOSFODNN7EXAMPLE and email jane.doe@corp.com, "
    "SSN 123-45-6789. Please help me debug this."
)

# Backwards-compatible aliases: the logo and unicode probe moved to
# domestique.branding (shared with the app launcher), but tests and callers
# still reference / monkeypatch these module-level names.
_LOGO = LOGO
_supports_unicode = supports_unicode


def _banner(host: str, port: int, *, policy: str | None = None) -> str:
    url = f"http://{host}:{port}"
    if _supports_unicode():
        rule, active, check, arrow = "─" * 60, "►", "✔", "→"
    else:
        rule, active, check, arrow = "-" * 60, ">", "+", "->"
    # Surface the loaded policy location cleanly here rather than leaking the
    # raw `policy_loaded` structlog line into the banner.
    policy_line = f"  [{check}] Policy {arrow} {policy}\n" if policy else ""
    return (
        _LOGO
        + "  [OSS PROXY]\n"
        + rule
        + "\n"
        + f"  [{active}] Domestique Proxy active on {url}\n"
        + f"  [{check}] Intercepting outbound prompts {arrow} redacting secrets & PII\n"
        + policy_line
        + rule
        + "\n"
        + "  Point your agent at it (keep your own API key):\n"
        + f"    export OPENAI_BASE_URL={url}/v1\n"
        + f"    export ANTHROPIC_BASE_URL={url}\n"
        + "  Redact by default.  Press Ctrl-C to stop.\n"
        + f"  {arrow} Protect your web browser too:  domestique browser\n"
    )


def _policy_summary(policy: PolicyEngine) -> str:
    """One-line policy description for the banner: ``location (N rules, mode)``."""
    from domestique.gateway import _CLI_POLICY
    from domestique.policy import _display_path

    actions = policy.actions
    if Action.REDACT in actions:
        mode = "redact-first"
    elif Action.BLOCK in actions:
        mode = "block-only"
    else:
        mode = "allow-all"
    return f"{_display_path(_CLI_POLICY)} ({policy.rule_count} rules, {mode})"


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


def _live_feedback_enabled(*, quiet: bool, isatty: bool) -> bool:
    """Show the live redaction ticker only on an interactive TTY and not --quiet."""
    return (not quiet) and isatty


def _make_ticker(
    *, color: bool, emit: Callable[[str], None] | None = None
) -> Callable[[Action, list[str], str], None]:
    """Build the per-request live-feedback callback for the wedge."""
    write = emit or (lambda line: print(line, flush=True))
    paint = console.Palette(enabled=color)
    g = console.glyphs()

    def on_decision(action: Action, categories: list[str], host: str) -> None:
        names = ", ".join(_label(c) for c in categories) or "sensitive data"
        if action is Action.BLOCK:
            write(f"  {paint(g['cross'], 'red')} blocked ({names}) {g['arrow']} {host}")
        else:
            write(
                f"  {paint(g['check'], 'green')} redacted {len(categories)} "
                f"({names}) {g['arrow']} {host}"
            )

    return on_decision


def _render_detector_warnings(missing: list[TierStatus], *, color: bool) -> str:
    """One warning line per configured-but-unavailable detection tier."""
    paint = console.Palette(enabled=color)
    g = console.glyphs()
    lines = []
    for tier in missing:
        lines.append(
            f"  {paint('⚠', 'red') if _supports_unicode() else '  [!]'} "
            f"{paint(tier.label + ' configured but unavailable', 'bold')} "
            f"{g['arrow']} install:  {tier.install_hint}"
        )
    return "\n".join(lines)


def _cmd_start(
    host: str,
    port: int,
    *,
    no_setup: bool = False,
    quiet: bool = False,
    strict: bool = False,
    access_log: bool = False,
) -> int:
    import uvicorn

    from domestique.config_loader import settings_from_config
    from domestique.gateway import build_cli_pipeline, create_gateway

    # Best effort: make the console UTF-8 so the banner glyphs render on Windows.
    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

    _quiet_process_logs()  # keep the banner + ticker clean (info logs → stderr, WARNING+)
    _maybe_offer_first_run_setup(no_setup)

    settings = settings_from_config()
    color = console.supports_color()

    # UX-2: surface configured-but-unavailable detection tiers. --strict verifies
    # deeply (model load) and refuses to start rather than run half-protected.
    statuses = detector_status(settings, deep=strict)
    missing = unavailable_configured(statuses)
    if missing:
        if strict:
            print("⛔ strict mode: some configured detection is unavailable.\n")
            print(_render_detector_warnings(missing, color=color))
            print("\n  Install the missing tier(s) above, or drop --strict to run anyway.")
            return 2
        print(_render_detector_warnings(missing, color=color))
        print("  " + _SETUP_LATER_HINT + "\n")

    try:
        interactive = sys.stdout.isatty()
    except (AttributeError, ValueError):
        interactive = False
    on_decision = (
        _make_ticker(color=color)
        if _live_feedback_enabled(quiet=quiet, isatty=interactive)
        else None
    )

    # Build the pipeline here (same work create_gateway would do internally, just
    # moved up) so the banner can show the actual loaded policy location.
    pipeline = build_cli_pipeline(settings)
    print(_banner(host, port, policy=_policy_summary(pipeline.policy)))
    gateway = create_gateway(settings, pipeline=pipeline, on_decision=on_decision)
    # One voice: silence uvicorn's per-request access log + INFO startup chatter
    # so it never speaks over the ticker. The ticker (redact/block only) is the
    # single per-request signal; a clean request stays silent. --access-log
    # restores uvicorn's raw HTTP logs for debugging.
    uvicorn.run(
        gateway,
        host=host,
        port=port,
        access_log=access_log,
        log_level="info" if access_log else "warning",
    )
    return 0


def _cmd_report(*, as_json: bool = False, days: int | None = None) -> int:
    from domestique.report import (
        aggregate,
        default_audit_path,
        load_events,
        render_text,
        to_json,
    )

    data = aggregate(load_events(default_audit_path(), since_days=days))
    if as_json:
        print(to_json(data))
    else:
        print(render_text(data, color=console.supports_color(), since_days=days))
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

    if importlib.util.find_spec("domestique_app") is None:
        print("Browser protection needs the dashboard app, which is not installed.")
        print('Install it with:  pipx inject domestique "domestique[browser-proxy]"')
        print('  (or in a plain venv: pip install "domestique[browser-proxy]")')
    else:
        # `--mode portable` works on a core install everywhere; bare
        # `python -m domestique_app` needs the [macos-native] extra on macOS.
        print("dashboard app isn't running (or didn't respond) - start it with:")
        print("  python -m domestique_app --mode portable")


def _cmd_browser(action: str, url: str) -> int:
    """Toggle/inspect browser interception via the local dashboard HTTP API.

    Talks HTTP only (architecture rule: domestique/ never imports domestique_app/).
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


def _print_mitmproxy_hint() -> None:
    """Tell the user how to add browser support by hand.

    Uses the same detection _ensure_browser_dependency would use to install
    it automatically, so a plain pip/venv install is never told to run
    `pipx inject` (which may not even have pipx on PATH), or vice versa.
    """
    _, cmd = _detect_install_context()
    print("Browser support (mitmproxy) isn't installed. Add it with:")
    print(f"  {' '.join(cmd)}")
    print("  then re-run:  domestique browser")


def _detect_install_context() -> tuple[str, list[str]]:
    """Pick the right install command for how domestique was installed.

    pipx installs live in their own venv and need `pipx inject`; a plain
    venv/pip install takes `pip install`. Returns (kind, argv).

    Detection is OS-agnostic: ``sys.prefix`` is normalised to forward slashes
    (Windows pipx venvs use backslashes, so the raw substring never matched),
    and pipx's own ``pipx_metadata.json`` marker at the venv root is treated as
    definitive — it also catches custom PIPX_HOME layouts whose path isn't
    literally ".../pipx/venvs/...".
    """
    import os
    from pathlib import Path

    prefix_posix = sys.prefix.replace("\\", "/")
    under_pipx = (
        bool(os.environ.get("PIPX_HOME"))
        or "/pipx/venvs/" in prefix_posix
        or (Path(sys.prefix) / "pipx_metadata.json").is_file()
    )
    if under_pipx and shutil.which("pipx"):
        return "pipx", ["pipx", "inject", "domestique", "domestique[browser-proxy]"]
    return "pip", [sys.executable, "-m", "pip", "install", "domestique[browser-proxy]"]


def _ensure_browser_dependency(*, assume_yes: bool, no_install: bool) -> bool:
    """Ensure mitmproxy is available, installing it on demand.

    Returns True if the dependency is present (or was just installed), False
    if it's missing and could not / should not be installed. Never imports
    mitmproxy in-process (the spawned app subprocess uses a fresh interpreter),
    so success is judged by the installer's exit code, not a re-check.
    """
    if importlib.util.find_spec("mitmproxy") is not None:
        return True
    if no_install:
        _print_mitmproxy_hint()
        return False
    if not assume_yes and sys.stdin is not None and sys.stdin.isatty():
        reply = input("Add browser support (~a few MB, mitmproxy)? [Y/n] ").strip().lower()
        if reply in {"n", "no"}:
            _print_mitmproxy_hint()
            return False
    kind, cmd = _detect_install_context()
    print(f"→ installing browser support via {kind}…")
    try:
        result = subprocess.run(cmd, check=False)  # noqa: S603
    except OSError as exc:
        print(f"error: install command failed to run: {exc}")
        _print_mitmproxy_hint()
        return False
    if result.returncode != 0:
        print("error: installing browser support failed.")
        _print_mitmproxy_hint()
        return False
    return True


def _dashboard_call(
    url: str, path: str, *, method: str = "GET", timeout: float = 5.0
) -> dict[str, Any] | None:
    """Call a dashboard JSON endpoint. Returns the parsed body (including a
    4xx/5xx JSON error body), or None if unreachable / non-JSON."""
    import urllib.error
    import urllib.request

    try:
        req = urllib.request.Request(  # noqa: S310  # local dashboard, http only
            url.rstrip("/") + path,
            method=method,
            data=b"" if method == "POST" else None,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return cast("dict[str, Any]", json.loads(resp.read().decode("utf-8")))
    except urllib.error.HTTPError as exc:
        try:
            return cast("dict[str, Any]", json.loads(exc.read().decode("utf-8")))
        except (json.JSONDecodeError, OSError):
            return None
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError):
        return None


def _dashboard_reachable(url: str) -> bool:
    """True if the dashboard HTTP server answers. Uses the cheap browser-proxy
    status endpoint (no interception-chain verification)."""
    return _dashboard_call(url, "/api/browser-proxy", timeout=3.0) is not None


def _wait_for_dashboard(url: str, *, timeout: float = 30.0, interval: float = 0.5) -> bool:
    """Poll until the dashboard is reachable or the timeout elapses."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _dashboard_reachable(url):
            return True
        time.sleep(interval)
    return False


def _spawn_dashboard_app() -> None:
    """Launch the dashboard app detached, in portable mode, without opening a
    browser tab (the launcher opens the dashboard itself once it's up).

    ``start_new_session=True`` is POSIX-only -- CPython's Windows
    ``_execute_child`` takes the parameter but literally names it
    ``unused_start_new_session`` and never acts on it. Without
    ``CREATE_NEW_PROCESS_GROUP`` on Windows the spawned process stays in
    this console's process group, so Ctrl+C while ``_wait_for_dashboard``
    is still polling would kill the freshly-spawned dashboard along with
    the CLI -- the opposite of "detached". Mirrors
    ``domestique_app.services.runtime.subprocess_group_kwargs`` (same
    logic, reimplemented here rather than imported: ``domestique/`` must
    never import ``domestique_app/``).
    """
    import os

    kwargs: dict[str, object] = (
        {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        if os.name == "nt"
        else {"start_new_session": True}
    )
    subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", _APP_MODULE, "--mode", "portable", "--no-browser"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **kwargs,
    )


def _ensure_app_running(url: str, *, timeout: float = 30.0) -> bool:
    """Make sure the dashboard app is up: reachable already, or spawn + wait."""
    if _dashboard_reachable(url):
        return True
    _spawn_dashboard_app()
    return _wait_for_dashboard(url, timeout=timeout)


def _post_browser_start(url: str) -> dict[str, Any] | None:
    """Turn on browser interception via the dashboard (also enables the system
    proxy server-side). Returns the dashboard's JSON response, or None.

    Uses a generous timeout: on first run the dashboard's handler does
    synchronous setup (generate CA, install to keychain, generate PAC,
    launch mitmdump, enable system proxy) that can far exceed the default
    timeout.
    """
    return _dashboard_call(url, "/api/browser-proxy/start", method="POST", timeout=60.0)


def _warn_if_cert_untrusted(url: str) -> None:
    """On platforms where the CA wasn't auto-trusted, point the user at the
    dashboard to finish trusting it. Silent when trusted or status is unknown."""
    status = _dashboard_call(url, "/api/cert-status")
    if status is None:
        return
    if status.get("generated") and not status.get("trusted", True):
        print("note: the Domestique certificate isn't trusted yet on this system.")
        print(f"  finish trusting it in the dashboard: {url}")


def _cmd_browser_launch(
    url: str, *, assume_yes: bool, no_install: bool, open_dashboard: bool
) -> int:
    """Bare `domestique browser`: one idempotent step to full browser protection.

    Ensure mitmproxy -> ensure the dashboard app is up -> turn interception on
    (which generates/trusts the CA and enables the system proxy server-side)
    -> warn if the CA still isn't trusted -> open the dashboard. Re-running
    when already protected just re-opens the dashboard.
    """
    if not _ensure_browser_dependency(assume_yes=assume_yes, no_install=no_install):
        return 1

    if not _ensure_app_running(url):
        print("error: the dashboard app didn't come up in time.")
        print("  check logs under ~/.domestique/, then retry, or run it directly:")
        print("    python -m domestique_app --mode portable")
        return 1

    payload = _post_browser_start(url)
    if payload is None or payload.get("error"):
        detail = payload.get("error") if payload else "no response from the dashboard"
        print(f"error: could not turn on browser protection - {detail}")
        return 1

    _warn_if_cert_untrusted(url)

    if open_dashboard:
        webbrowser.open(url)

    if payload.get("already_running"):
        print("Browser protection is already on. Dashboard:")
    else:
        print("Your browser is now protected. Try a chatbot and watch the dashboard:")
    print(f"  {url}")
    print("  To stop:  domestique browser off")
    return 0


def _render_config_header(settings: Settings, policy: PolicyEngine, *, color: bool) -> str:
    g = console.glyphs()
    paint = console.Palette(enabled=color)
    actions = policy.actions
    redact = "on" if Action.REDACT in actions else "off"
    block = "on (crown-jewels)" if Action.BLOCK in actions else "off"

    presets = ["minimal", "balanced", "quality", "legacy-cpu"]
    active = settings.local_llm_preset
    preset_cells = [
        paint(f"[{p}]", "cyan") if p == active else paint(f" {p} ", "dim") for p in presets
    ]

    tiers = [
        ("Regex", settings.enable_secret_detection),
        ("Presidio", settings.enable_pii_detection),
        ("GLiNER", settings.enable_gliner),
        ("Semantic", settings.enable_semantic_detection),
        (f"LLM:{settings.local_llm_model}", settings.enable_local_llm),
    ]
    stack_cells = [
        (paint(f"{g['check']} {name}", "green") if on else paint(f"{g['dot']} {name}", "dim"))
        for name, on in tiers
    ]

    rule = "  " + g["rule"] * 58
    return "\n".join(
        [
            "  " + paint("Active configuration", "bold"),
            rule,
            f"    Policy           redact {redact}   {g['dot']}   block {block}",
            "    Hardware preset  " + "  ".join(preset_cells),
            "    Detection stack  " + "   ".join(stack_cells),
        ]
    )


def _highlight_secrets(before: str, findings: list[Finding], paint: console.Palette) -> str:
    """Paint each finding's leaked span red, non-overlapping, left to right."""
    spans = sorted({(f.span.start, f.span.end) for f in findings if f.span is not None})
    out: list[str] = []
    cursor = 0
    for start, end in spans:
        if start < cursor:  # skip overlaps
            continue
        out.append(before[cursor:start])
        out.append(paint(before[start:end], "red"))
        cursor = end
    out.append(before[cursor:])
    return "".join(out)


def _highlight_tokens(after: str, paint: console.Palette) -> str:
    return re.sub(
        r"\[[A-Z0-9_]+_REDACTED\]",
        lambda m: paint(m.group(0), "green"),
        after,
    )


def _render_canned(before: str, after: str, findings: list[Finding], *, color: bool) -> str:
    g = console.glyphs()
    paint = console.Palette(enabled=color)
    rule = "  " + g["rule"] * 60
    lines = [
        "",
        "  " + paint("Domestique demo — watch it redact secrets", "bold"),
        rule,
        "  BEFORE",
        "    " + _highlight_secrets(before, findings, paint),
        "",
        f"  AFTER {g['arrow']} sent to the model",
        "    " + _highlight_tokens(after, paint),
        rule,
        "  Findings",
    ]
    for f in findings:
        lines.append(
            f"    {paint(g['check'], 'green')} {_label(f.category):<16} {f.confidence:.0%}"
        )
    return "\n".join(lines)


def _truncate(value: str, width: int = 22) -> str:
    value = value.strip()
    if len(value) <= width:
        return value
    keep = width - 1
    return value[: keep // 2] + "…" + value[-(keep - keep // 2) :]


def _render_ledger(before: str, findings: list[Finding], *, color: bool) -> str:
    g = console.glyphs()
    paint = console.Palette(enabled=color)

    # dedupe by span, keep highest confidence per span
    best: dict[tuple[int, int], Finding] = {}
    for f in findings:
        if f.span is None:
            continue
        key = (f.span.start, f.span.end)
        if key not in best or f.confidence > best[key].confidence:
            best[key] = f
    ordered = sorted(best.values(), key=lambda f: f.span.start if f.span else 0)

    if not ordered:
        return f"  {g['dot']} nothing sensitive detected"

    rows = []
    for f in ordered:
        assert f.span is not None
        leaked = _truncate(before[f.span.start : f.span.end])
        token = f"[{f.category.upper()}_REDACTED]"
        rows.append((_label(f.category), leaked, token, f"{f.confidence:.0%}"))

    lw = max(len(r[0]) for r in rows)
    vw = max(len(r[1]) for r in rows)
    out = [f"  {paint(g['check'], 'green')} redacted {len(rows)} secret(s)"]
    for label, leaked, token, conf in rows:
        out.append(
            f"    {paint(g['check'], 'green')} {label:<{lw}}  "
            f"{paint(leaked, 'red'):<{vw}}  {g['arrow']}  "
            f"{paint(token, 'green')}  {paint(conf, 'dim')}"
        )
    return "\n".join(out)


def _quiet_process_logs() -> None:
    """Silence info-level process logs (to stderr) so CLI output stays clean.

    Domestique never calls ``structlog.configure()`` elsewhere, so structlog's
    unconfigured default — a ``ConsoleRenderer`` that always emits ANSI color
    to stdout, tty or not — is what fires when the policy/pipeline loaders
    log (e.g. ``policy_loaded``). Left alone, that padded dev-format line
    ("[info     ] policy_loaded            path=...") interleaves into the
    rendered demo and the ``start`` banner/ticker on every run. Raising the
    threshold to WARNING and routing to stderr keeps the config header / ticker
    (stdout) clean while real warnings (e.g. ``gliner_not_cached``) still surface.

    The factory below resolves ``sys.stderr`` at each call instead of once
    here (``structlog.PrintLoggerFactory(file=sys.stderr)`` would capture it
    once): structlog only re-resolves the *current* stdout dynamically, any
    other stream is bound at configure time, which would go stale across a
    stream swap (e.g. pytest's per-test capsys/capfd redirection).
    """
    import logging

    import structlog

    def _stderr_logger_factory(*_args: object) -> structlog.PrintLogger:
        return structlog.PrintLogger(file=sys.stderr)

    structlog.configure(
        processors=[
            *structlog.get_config()["processors"][:-1],
            structlog.dev.ConsoleRenderer(colors=console.supports_color(sys.stderr)),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
        logger_factory=_stderr_logger_factory,
    )


def run_demo(*, interactive: bool | None = None) -> int:
    """Canned before/after redaction, then (on a TTY) an interactive loop.

    Builds the pipeline from the user's loaded config so the header and the
    redaction reflect the same detectors ("run the real stack"). Fresh
    machine -> Settings() defaults, shown honestly.
    """
    from domestique.config_loader import settings_from_config
    from domestique.gateway import build_cli_pipeline

    _quiet_process_logs()
    color = console.supports_color()
    settings = settings_from_config()
    pipeline = build_cli_pipeline(settings)
    # Reuse the pipeline's own policy for the header — loading it a second
    # time via from_yaml_default() re-parsed the YAML and double-logged.
    print(_render_config_header(settings, pipeline.policy, color=color))

    result = asyncio.run(pipeline.inspect(_DEMO_PROMPT))
    after = result.redacted_text or _DEMO_PROMPT
    print(_render_canned(_DEMO_PROMPT, after, result.findings, color=color))

    if interactive is None:
        try:
            interactive = sys.stdin is not None and sys.stdin.isatty()
        except ValueError:
            interactive = False
    if interactive:
        g = console.glyphs()
        print(
            f"\n  Now try your own {g['arrow']} paste anything with secrets — real or "
            "fake, it never leaves your machine ;)  Enter on a blank line to finish."
        )
        while True:
            try:
                text = input("\n  prompt> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not text:
                break
            res = asyncio.run(pipeline.inspect(text))
            print(_render_ledger(text, res.findings, color=color))
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
    start.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the live redaction ticker (also auto-suppressed when not a TTY)",
    )
    start.add_argument(
        "--strict",
        action="store_true",
        help="refuse to start if a configured detection tier is unavailable (fail-closed)",
    )
    start.add_argument(
        "--access-log",
        action="store_true",
        help="restore uvicorn's raw HTTP access log (off by default; the ticker is the voice)",
    )

    sub.add_parser("demo", help="show a before/after redaction (no API key needed)")

    report = sub.add_parser("report", help="summarize redactions & blocks by type")
    report.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    report.add_argument(
        "--days", type=int, default=None, help="only count events from the last N days"
    )

    setup = sub.add_parser("setup", help="first-run onboarding wizard (hardware-aware)")
    setup.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="accept all recommended defaults (non-interactive)",
    )

    browser = sub.add_parser(
        "browser",
        help="browser protection: bare = set up & launch; on/off/status to control",
    )
    browser.add_argument(
        "action",
        nargs="?",
        choices=["on", "off", "status"],
        default=None,
        help="on/off/status to control a running dashboard; omit to set up & launch",
    )
    browser.add_argument(
        "--url",
        default=_DASHBOARD_URL,
        help=f"dashboard API base URL (default: {_DASHBOARD_URL})",
    )
    browser.add_argument(
        "--no-open", action="store_true", help="don't open the dashboard in a browser"
    )
    browser.add_argument(
        "--yes", "-y", action="store_true", help="skip the browser-support install confirmation"
    )
    browser.add_argument(
        "--no-install",
        action="store_true",
        help="never auto-install browser support; print the manual command instead",
    )

    args = parser.parse_args(argv)
    if args.cmd == "start":
        return _cmd_start(
            args.host,
            args.port,
            no_setup=args.no_setup,
            quiet=args.quiet,
            strict=args.strict,
            access_log=args.access_log,
        )
    if args.cmd == "demo":
        return run_demo()
    if args.cmd == "report":
        return _cmd_report(as_json=args.json, days=args.days)
    if args.cmd == "setup":
        return _cmd_setup(args.yes)
    if args.cmd == "browser":
        if args.action is None:
            return _cmd_browser_launch(
                args.url,
                assume_yes=args.yes,
                no_install=args.no_install,
                open_dashboard=not args.no_open,
            )
        return _cmd_browser(args.action, args.url)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
