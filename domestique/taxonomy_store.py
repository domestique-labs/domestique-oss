"""Persisted registry of LLM-coined taxonomy terms.

Canonical terms live in code (``taxonomy.CANONICAL``); this stores only the
open-vocabulary terms the LLM invents, so they survive restarts and keep a
stable token prefix. Fail-safe: any path/IO error degrades to in-memory only.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
from pathlib import Path
from uuid import uuid4

import structlog

from domestique.taxonomy import (
    CANONICAL,
    GENERIC_PREFIX,
    MAX_PREFIX_LEN,
    _derive_prefix,
    is_label_shaped,
    is_value_like,
    normalize_category,
)

logger = structlog.get_logger()

_CANONICAL_PREFIXES = set(CANONICAL.values())

#: A coined term longer than this is treated as junk and never persisted. The
#: LLM ``c`` field is untrusted, so an over-long value is likely a hallucination
#: echoing prompt text — persisting it would grow ``~/.domestique/taxonomy.json``
#: unbounded and leak user data into a file the design treats as non-sensitive.
#: It still yields a bounded derived prefix, so redaction/reversal is unaffected.
_MAX_COINED_TERM_LEN = 64
#: Hard ceiling on distinct persisted coined terms, bounding the file size no
#: matter how many novel categories a model emits.
_MAX_COINED_TERMS = 512


def _tmp_path_for(path: Path) -> Path:
    """A write-scratch path no other writer can be using.

    PID + uuid, because the three shipped processes share one file and a fixed
    ``taxonomy.json.tmp`` lets two of them write the same scratch file at once.
    """
    return path.with_name(f"{path.name}.{os.getpid()}.{uuid4().hex}.tmp")


def _default_path() -> Path | None:
    try:
        return Path.home() / ".domestique" / "taxonomy.json"
    except Exception:
        return None


class TaxonomyStore:
    """Thread-safe store of coined term -> token prefix, persisted to JSON."""

    def __init__(self, path: Path | None) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._terms: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        self._terms = self._read_disk()

    def _read_disk(self) -> dict[str, str]:
        """Current on-disk mapping, or ``{}`` if absent/unreadable.

        Never raises: an unreadable file must not block a later write, or one
        corrupt byte would freeze the registry for good.
        """
        if self._path is None or not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            logger.warning("taxonomy_store_load_failed", path=str(self._path))
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items()}

    def _persist_locked(self) -> None:
        """Merge this store's terms into the file and replace it atomically.

        Three processes ship (wedge, browser proxy, demo), each with its own
        store over the same file, and ``self._terms`` was seeded once at
        construction — so writing it wholesale makes the last writer silently
        discard every term the others coined. Re-reading and merging on each
        write recovers most of them. On-disk entries win for keys already
        present, so a prefix another process already handed out is never
        reassigned; the merged view is written back into ``self._terms`` so this
        process agrees with the file it just wrote.

        This reduces lost updates but does not eliminate them: the read-modify
        -write is not atomic across processes and takes no file lock, so writes
        interleaving between the read and the replace are still lost. Measured
        under 8 concurrent processes coining 320 terms, 88 survived. ``os.replace``
        is atomic, so the file is never observed corrupt or partial — the failure
        mode is a missing label, which costs a coined prefix and nothing more.
        A real fix needs an flock/O_EXCL critical section; tracked separately.

        Persistence must never raise into the request path: any failure degrades
        to in-memory only.
        """
        if self._path is None:
            return
        tmp: Path | None = None
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            merged = {**self._terms, **self._read_disk()}
            self._terms = merged
            # Unique per write: a fixed temp name is a second race — two
            # processes would write the same file and one would replace a
            # half-written copy of the other's.
            tmp = _tmp_path_for(self._path)
            tmp.write_text(json.dumps(merged, indent=2, sort_keys=True), encoding="utf-8")
            # 0600 before the rename, so the file is never briefly world-readable.
            # Coined terms are derived from prompts; the default 0644 let any
            # other local user read them. No-op semantics on Windows.
            with contextlib.suppress(OSError):
                os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
        except Exception:
            logger.warning("taxonomy_store_persist_failed", path=str(self._path))
            if tmp is not None:
                with contextlib.suppress(OSError):
                    tmp.unlink(missing_ok=True)  # no orphan scratch files

    def prefix_of(self, term: str) -> str | None:
        with self._lock:
            return self._terms.get(term)

    def terms(self) -> dict[str, str]:
        with self._lock:
            return dict(self._terms)

    def _tmp_path(self) -> Path | None:
        """The temp file this store would write next (unique per call)."""
        return None if self._path is None else _tmp_path_for(self._path)

    def register(self, raw: str, *, scanned_text: str | None = None) -> str:
        """Return the prefix for ``raw``; coin + persist it if new, non-canonical,
        and within the length/count bounds.

        ``raw`` is untrusted model output. A model that echoes a secret into its
        category field would otherwise mint a token *containing that secret* — a
        token that is sent upstream — and persist it as a key in
        ``~/.domestique/taxonomy.json``. Two guards, in order:

        1. **Shape** (:func:`is_label_shaped`), an allowlist: the term must look
           like an identifier. This is the load-bearing one. Containment alone
           let ``c = "password_" + t`` through, egressing the whole secret as
           ``[PASSWORD_TR0UB4DOR_3X_1]``, because a label and a value are not
           adjacent in the prompt.
        2. **Containment** (:func:`is_value_like`), for the residue shape cannot
           see: a label-shaped secret such as ``hunter2`` that appears verbatim
           in ``scanned_text``. Pass ``scanned_text`` whenever the caller has it.

        Either rejection returns ``GENERIC_PREFIX`` and stores nothing.

        An over-long term (untrusted, likely-hallucinated LLM output) or one that
        would exceed ``_MAX_COINED_TERMS`` still gets a bounded derived prefix so
        redaction works, but is NOT persisted — the on-disk file can neither grow
        unbounded nor absorb prompt data echoed into the ``c`` field.
        """
        term = normalize_category(raw)
        if term in CANONICAL:
            return CANONICAL[term]
        # Both guards must precede the length bound below: that path returns
        # _derive_prefix(term), which would put the first MAX_PREFIX_LEN
        # characters of the leaked value straight into the token.
        # Deliberately no term/text in any payload — logging either would just
        # move the leak into the log file.
        if not is_label_shaped(term):
            logger.warning("taxonomy_category_not_label_shaped")
            return GENERIC_PREFIX
        if scanned_text is not None and is_value_like(term, scanned_text):
            logger.warning("taxonomy_value_like_category_rejected")
            return GENERIC_PREFIX
        if len(term) > _MAX_COINED_TERM_LEN:
            return _derive_prefix(term)
        with self._lock:
            existing = self._terms.get(term)
            if existing is not None:
                return existing
            if len(self._terms) >= _MAX_COINED_TERMS:
                logger.warning("taxonomy_store_full", limit=_MAX_COINED_TERMS)
                return _derive_prefix(term)
            prefix = self._unique_prefix_locked(_derive_prefix(term))
            self._terms[term] = prefix
            self._persist_locked()  # may adopt another process's prefix for `term`
            return self._terms.get(term, prefix)

    def _unique_prefix_locked(self, base: str) -> str:
        taken = _CANONICAL_PREFIXES | set(self._terms.values())
        if base not in taken:
            return base
        for n in range(2, 1000):
            suffix = f"_{n}"
            candidate = base[: MAX_PREFIX_LEN - len(suffix)].rstrip("_") + suffix
            if candidate not in taken:
                return candidate
        return base  # pathological; accept collision over infinite loop


_DEFAULT: TaxonomyStore | None = None
_DEFAULT_LOCK = threading.Lock()


def default_store() -> TaxonomyStore:
    """Process-global store, initialized from ``~/.domestique/taxonomy.json`` once."""
    global _DEFAULT
    if _DEFAULT is None:
        with _DEFAULT_LOCK:
            if _DEFAULT is None:
                _DEFAULT = TaxonomyStore(path=_default_path())
    return _DEFAULT
