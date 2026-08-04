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
import time
from collections.abc import Iterator
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

# Cross-platform advisory file lock, resolved once at import.
#
# OS advisory locks are used rather than an O_EXCL lockfile specifically for the
# crash story: both backends are held on an open descriptor, so the OS releases
# the lock when the process dies. There is no stale-lock recovery path to get
# wrong, and no mtime heuristic. Measured: a lock held by a SIGKILLed process is
# reacquirable in under a millisecond.
try:  # POSIX
    import fcntl

    def _acquire(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    _LOCKING = "fcntl"
except ImportError:  # pragma: no cover - exercised on Windows only
    try:
        import msvcrt

        def _acquire(fd: int) -> None:
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)

        _LOCKING = "msvcrt"
    except ImportError:  # pragma: no cover - neither backend (not CPython)
        def _acquire(fd: int) -> None:
            return None

        _LOCKING = "none"

#: Give up waiting and write unlocked rather than block a request path.
_LOCK_TIMEOUT_S = 2.0


@contextlib.contextmanager
def _file_lock(path: Path) -> Iterator[bool]:
    """Hold an exclusive advisory lock for the whole read-modify-write.

    The lock lives on a ``.lock`` sidecar, never on the data file itself:
    ``os.replace`` swaps the inode, so a lock held on ``taxonomy.json`` is
    silently dropped the moment another writer renames over it.

    It must span read → merge → replace. Locking only the write leaves the
    original bug intact, because the *stale read* is what loses the update.

    Yields True when the lock was actually held. On timeout or any lock error
    it yields False and the caller proceeds unlocked — degrading to today's
    lossy-but-safe behaviour beats blocking a request.
    """
    lock_path = path.with_name(path.name + ".lock")
    fd = None
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + _LOCK_TIMEOUT_S
        while True:
            try:
                _acquire(fd)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    logger.warning("taxonomy_lock_timeout", backend=_LOCKING)
                    yield False
                    return
                time.sleep(0.002)
        try:
            yield _LOCKING != "none"
        finally:
            with contextlib.suppress(OSError):
                os.close(fd)
                fd = None
    except OSError:
        yield False
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)

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

        Merging alone was not enough. The read-modify-write is not atomic across
        processes, so any write landing between the read and the ``os.replace``
        was still lost: measured over 10 trials of 8 processes coining 320 terms,
        a mean of 146 survived, and 16 processes coining 480 lost up to 94%.
        ``os.replace`` is atomic, so the file was never corrupt — the failure
        mode was a missing label.

        So the whole critical section now runs under :func:`_file_lock`. Same
        benchmark: 320/320 and 480/480 survive, every trial. Uncontended cost is
        within noise (~0.22 ms/write); contended p99 rises to roughly 40 ms at 8
        writers because the lock serializes what used to run in parallel and
        lose. Coining only happens for a novel category, so that tail is rare.

        Persistence must never raise into the request path: any failure degrades
        to in-memory only.
        """
        if self._path is None:
            return
        tmp: Path | None = None
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with _file_lock(self._path):
                self._persist_critical_section()
            return
        except OSError:
            logger.warning("taxonomy_store_persist_failed", path=str(self._path))
            if tmp is not None:
                with contextlib.suppress(OSError):
                    tmp.unlink(missing_ok=True)

    def _persist_critical_section(self) -> None:
        """Read → merge → replace. Must run under :func:`_file_lock`."""
        if self._path is None:
            return
        tmp: Path | None = None
        try:
            merged = self._merge_preserving_uniqueness(self._read_disk())
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

    def _merge_preserving_uniqueness(self, on_disk: dict[str, str]) -> dict[str, str]:
        """Fold *on_disk* over local terms without creating a duplicate prefix.

        ``_unique_prefix_locked`` picks a free prefix against the terms this
        process knows about, but the disk map is read *after* that choice. A
        plain ``{**local, **disk}`` merge can therefore reintroduce exactly the
        collision the uniqueness rule exists to prevent: two categories whose
        derived prefixes truncate to the same MAX_PREFIX_LEN string end up
        sharing one prefix on disk.

        That is not cosmetic. ``taxonomy.py`` states prefixes must be unique
        because a collision merges two categories' token counters — so the
        reversible vault can substitute the wrong original value back when it
        rewrites a response.

        Disk wins for keys already present (a prefix another process handed out
        is never reassigned); any *local* term left colliding is re-keyed.
        """
        merged = dict(on_disk)
        seen = set(merged.values())
        for term, prefix in self._terms.items():
            if term in merged:
                continue  # disk already assigned this term a prefix
            if prefix in seen:
                prefix = self._free_prefix(prefix, seen)
            merged[term] = prefix
            seen.add(prefix)
        return merged

    @staticmethod
    def _free_prefix(base: str, taken: set[str]) -> str:
        for n in range(2, 1000):
            suffix = f"_{n}"
            candidate = base[: MAX_PREFIX_LEN - len(suffix)].rstrip("_") + suffix
            if candidate not in taken:
                return candidate
        return base  # pathological; accept collision over an infinite loop

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
