"""`domestique report` — aggregate the wedge's metadata-only audit log.

The wedge appends one compact JSONL event per redact/block decision to
``~/.domestique/audit.jsonl`` (see ``domestique.audit.AuditLogger``). Those
events carry **no raw prompt text** — only the action, the detection
categories, a count, and a timestamp — so a report can be produced and shared
without exposing anything sensitive.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from domestique import console
from domestique.config_loader import DOMESTIQUE_HOME
from domestique.labels import label

if TYPE_CHECKING:
    from collections.abc import Iterable

_AUDIT_ENV = "DOMESTIQUE_AUDIT_LOG"


def default_audit_path() -> Path:
    """Resolve the wedge audit-log path (env override, else ~/.domestique)."""
    override = os.environ.get(_AUDIT_ENV, "").strip()
    return Path(override) if override else DOMESTIQUE_HOME / "audit.jsonl"


@dataclass
class ReportData:
    """Aggregated view of audit events."""

    total_events: int = 0
    by_category: dict[str, dict[str, int]] = field(default_factory=dict)
    action_totals: dict[str, int] = field(default_factory=dict)


def load_events(path: Path | str, *, since_days: int | None = None) -> list[dict[str, Any]]:
    """Read audit events from a JSONL file, skipping malformed lines.

    When *since_days* is given, only events whose ``ts`` is within that many
    days of now are returned; events without a parseable ``ts`` are kept.
    """
    p = Path(path)
    if not p.exists():
        return []

    cutoff = None
    if since_days is not None:
        cutoff = datetime.now(UTC) - timedelta(days=since_days)

    events: list[dict[str, Any]] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(event, dict):
            continue
        if cutoff is not None and not _within(event.get("ts"), cutoff):
            continue
        events.append(event)
    return events


def _within(ts: object, cutoff: datetime) -> bool:
    """True if *ts* (ISO string) is at or after *cutoff*; True if unparseable."""
    if not isinstance(ts, str):
        return True
    try:
        parsed = datetime.fromisoformat(ts)
    except ValueError:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed >= cutoff


def aggregate(events: Iterable[dict[str, Any]]) -> ReportData:
    """Roll events up into per-category, per-action counts."""
    by_category: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    action_totals: dict[str, int] = defaultdict(int)
    total = 0
    for event in events:
        total += 1
        action = str(event.get("action", "unknown"))
        action_totals[action] += 1
        for category in event.get("categories", []) or []:
            by_category[str(category)][action] += 1
    return ReportData(
        total_events=total,
        by_category={k: dict(v) for k, v in by_category.items()},
        action_totals=dict(action_totals),
    )


def to_json(data: ReportData) -> str:
    """Machine-readable report."""
    return json.dumps(
        {
            "total_events": data.total_events,
            "action_totals": data.action_totals,
            "by_category": data.by_category,
        },
        indent=2,
    )


def render_text(data: ReportData, *, color: bool = False, since_days: int | None = None) -> str:
    """Human-readable report table."""
    g = console.glyphs()
    paint = console.Palette(enabled=color)

    if data.total_events == 0:
        return (
            "  No events recorded yet — run `domestique start` and send some traffic,\n"
            "  then check back. (Only redactions and blocks are logged; nothing sensitive.)"
        )

    window = f"last {since_days}d" if since_days is not None else "all time"
    rows = sorted(
        data.by_category.items(),
        key=lambda kv: sum(kv[1].values()),
        reverse=True,
    )
    name_w = max((len(label(cat)) for cat, _ in rows), default=4)
    name_w = max(name_w, len("Type"))

    lines = [
        "",
        "  " + paint(f"Domestique report — {data.total_events} events ({window})", "bold"),
        "  " + g["rule"] * (name_w + 26),
        f"    {'Type':<{name_w}}  {'Redacted':>8}  {'Blocked':>8}",
    ]
    for cat, counts in rows:
        redacted = counts.get("redact", 0)
        blocked = counts.get("block", 0)
        lines.append(f"    {label(cat):<{name_w}}  {redacted:>8}  {blocked:>8}")

    lines.append("  " + g["rule"] * (name_w + 26))
    total_redacted = data.action_totals.get("redact", 0)
    total_blocked = data.action_totals.get("block", 0)
    lines.append(
        f"    {paint(str(total_redacted) + ' redacted', 'green')} "
        f"{g['dot']} {paint(str(total_blocked) + ' blocked', 'red')}"
    )
    return "\n".join(lines)
