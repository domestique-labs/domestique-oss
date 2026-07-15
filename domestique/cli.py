"""Domestique OSS CLI - the developer wedge entry point.

Commands:
    domestique start [--host H] [--port P]   launch the :8000 redacting proxy
    domestique demo                          show a before/after redaction, no key needed
    domestique --version
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import sys

from domestique import __version__

_DEMO_PROMPT = (
    "Here is my AWS key AKIAIOSFODNN7EXAMPLE and email jane.doe@corp.com, "
    "SSN 123-45-6789. Please help me debug this."
)

# figlet "standard" rendering of "domestique"
_LOGO = r"""
     _                           _   _
  __| | ___  _ __ ___   ___  ___| |_(_) __ _ _   _  ___
 / _` |/ _ \| '_ ` _ \ / _ \/ __| __| |/ _` | | | |/ _ \
| (_| | (_) | | | | | |  __/\__ \ |_| | (_| | |_| |  __/
 \__,_|\___/|_| |_| |_|\___||___/\__|_|\__, |\__,_|\___|
                                       |_|
"""


def _supports_unicode() -> bool:
    """Whether stdout can encode the fancy banner glyphs (False on a cp1252 console)."""
    enc = getattr(sys.stdout, "encoding", None) or ""
    try:
        "►✔→─".encode(enc)
    except (LookupError, UnicodeError):
        return False
    return True


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


def _cmd_start(host: str, port: int) -> int:
    import uvicorn

    from domestique.gateway import create_gateway

    # Best effort: make the console UTF-8 so the banner glyphs render on Windows.
    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

    print(_banner(host, port))
    uvicorn.run(create_gateway(), host=host, port=port)
    return 0


def run_demo() -> int:
    from domestique.gateway import build_wedge_pipeline

    pipeline = build_wedge_pipeline()
    result = asyncio.run(pipeline.inspect(_DEMO_PROMPT))
    after = result.redacted_text or _DEMO_PROMPT
    print("Domestique demo - watch it redact secrets before they reach the LLM.\n")
    print("BEFORE:\n" + _DEMO_PROMPT + "\n")
    print("AFTER (sent to the model):\n" + after + "\n")
    if result.findings:
        print("Findings: " + ", ".join(f.description for f in result.findings))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="domestique", description="Domestique OSS CLI wedge")
    parser.add_argument("--version", action="version", version=f"domestique {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    start = sub.add_parser("start", help="launch the :8000 redacting proxy")
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--port", type=int, default=8000)

    sub.add_parser("demo", help="show a before/after redaction (no API key needed)")

    args = parser.parse_args(argv)
    if args.cmd == "start":
        return _cmd_start(args.host, args.port)
    if args.cmd == "demo":
        return run_demo()
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
