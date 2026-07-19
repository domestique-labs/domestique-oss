from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

_VALID_ACTIONS = {"allow", "redact", "block"}


@dataclass(frozen=True)
class CorpusRow:
    """One labeled evaluation example.

    ``expected_action`` is the *desired* firewall verdict (ground truth),
    independent of what any single detector currently does.
    """

    id: str
    text: str
    expected_action: str
    categories: tuple[str, ...] = field(default_factory=tuple)


def load_corpus(path: Path) -> list[CorpusRow]:
    """Load a JSONL corpus. Raises ValueError on a malformed row."""
    rows: list[CorpusRow] = []
    seen: set[str] = set()
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        action = obj.get("expected_action")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"{path}:{lineno}: bad expected_action {action!r}")
        rid = str(obj["id"])
        if rid in seen:
            raise ValueError(f"{path}:{lineno}: duplicate id {rid!r}")
        seen.add(rid)
        rows.append(
            CorpusRow(
                id=rid,
                text=str(obj["text"]),
                expected_action=action,
                categories=tuple(obj.get("categories", ())),
            )
        )
    return rows


def corpus_checksum(rows: list[CorpusRow]) -> str:
    """Order-independent sha256 of the corpus content."""
    canonical = sorted(
        json.dumps(
            {"id": r.id, "text": r.text, "expected_action": r.expected_action,
             "categories": list(r.categories)},
            sort_keys=True, ensure_ascii=True,
        )
        for r in rows
    )
    digest = hashlib.sha256()
    for item in canonical:
        digest.update(item.encode("utf-8"))
    return digest.hexdigest()
