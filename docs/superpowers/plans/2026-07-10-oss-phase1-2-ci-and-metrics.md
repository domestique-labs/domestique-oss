# OSS Phase 1 (CI Hardening) + Phase 2 (Deterministic Metrics Harness) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the OSS repo's CI a trustworthy gate (blocking lint/format/types on the core package + a local pre-commit layer), then add a deterministic, black-box metrics harness that scores every PR on circumvention (bypass rate), false positives, F1, and latency — and comments the diff vs `main`.

**Architecture:** Part A hardens the *existing* `.github/workflows/ci.yml` (which today runs tests + an informational lint job) so `ruff`/`ruff format`/`mypy` are **blocking on `llmguard/`** while `app/` stays informational (it carries ~1099 lint errors). Part B adds a `bench/eval/` package that drives the **real FastAPI firewall over its HTTP boundary** (ASGI) against a **local mock upstream** that echoes the body it received — so the harness observes decisions black-box (403=block, 200+unchanged=allow, 200+changed=redact) and stays valid against a future Rust reimplementation.

**Tech Stack:** Python ≥3.11, FastAPI, httpx (ASGITransport), uvicorn, litellm (upstream client), pytest + pytest-asyncio, ruff, mypy, GitHub Actions.

## Global Constraints

- Python floor: `requires-python = ">=3.11"`; CI matrix `["3.11", "3.12"]`.
- Ruff config already in `pyproject.toml`: `line-length = 99`, `target-version = "py311"`, lint select `["E","F","I","N","UP","ANN","S","B","A","SIM","TCH"]`, ignore `["ANN401","S101"]` (drop the removed `ANN101`/`ANN102`).
- Mypy: `strict = true`, `python_version = "3.11"`.
- Blocking quality gates apply to **`llmguard/` only**; `app/` remains informational (`continue-on-error: true`) this plan.
- Determinism (Part B gate): all requests use `model = "gpt-4o-mini"`; env `PYTHONHASHSEED=0`; every detector flag left at its default `False` (gate = always-on `SecretDetector` regex only); `fail_mode="closed"`.
- Config env prefix is `LLMGUARD_`; litellm upstream base is the non-prefixed `OPENAI_API_BASE`.
- New eval code MUST be black-box: it talks to the firewall only via HTTP/ASGI request+response and to the mock only via HTTP. It must NOT import `llmguard.detectors.*` or `llmguard.policy.*`.
- Frequent commits: one commit per task, message prefix `ci:` (Part A) or `feat(eval):` (Part B).

---

# PART A — Phase 1: CI Hardening + Local Gate

Current state (verified): `.github/workflows/ci.yml` has a blocking `test` job (pytest, py3.11/3.12) and an **informational** `lint` job. `ruff check llmguard` = 46 errors (18 auto-fixable). `ruff format --check` = 48 files would reformat. `app/` = 1099 errors (out of scope; stays informational).

## Task A1: Make ruff lint + format blocking on `llmguard/`

**Files:**
- Modify: `llmguard/` (auto- and hand-fix the 46 lint findings; apply `ruff format`)
- Modify: `.github/workflows/ci.yml`
- Modify: `pyproject.toml:[tool.ruff.lint] ignore`

- [ ] **Step 1: Drop the removed ruff codes from config**

In `pyproject.toml`, change the ignore list (removes dead `ANN101`/`ANN102` that ruff now warns about):

```toml
[tool.ruff.lint]
select = ["E", "F", "I", "N", "UP", "ANN", "S", "B", "A", "SIM", "TCH"]
ignore = ["ANN401", "S101"]
```

- [ ] **Step 2: Auto-fix and format the core package**

Run:
```bash
.venv/Scripts/python -m ruff check llmguard --fix
.venv/Scripts/python -m ruff format llmguard
```
Expected: ~18 lint fixes applied; `llmguard` files reformatted.

- [ ] **Step 3: Hand-fix the remaining lint errors**

Run `.venv/Scripts/python -m ruff check llmguard` and resolve each remaining finding. Expected categories and fixes (do NOT blanket-ignore — fix at the source):
- `E501 line-too-long` (11): wrap the line, or extract a variable. Never `# noqa` unless a URL string.
- `TC001 typing-only-first-party-import` (5): move the import into an `if TYPE_CHECKING:` block.
- `UP045 non-pep604-annotation-optional` (5): `Optional[X]` → `X | None`.
- `UP035 deprecated-import` (3): `from typing import List` → use `list`, etc.
- `ANN204 / ANN202` (3): add return type annotations (`-> None`, real type).
- `S110 try-except-pass` (2): add a `logger.debug(...)` in the except, or narrow the exception.
- `S104 hardcoded-bind-all-interfaces` (1): add a targeted `# noqa: S104  # bind-all is intentional for the proxy listener` with a one-line justification comment.
- `S310 suspicious-url-open-usage` (1): if it's a `urllib.request.urlopen` on a trusted constant, add `# noqa: S310` with justification; otherwise switch to `httpx`.
- `B007`, `SIM103`, `SIM105`, `UP017`, `UP037`, `UP042`: apply the mechanical fix ruff describes.

- [ ] **Step 3b: Run tests to prove no behavior change**

Run: `.venv/Scripts/python -m pytest -q`
Expected: same pass count as before the task (no new failures introduced by the refactors).

- [ ] **Step 4: Verify the core package is clean**

Run:
```bash
.venv/Scripts/python -m ruff check llmguard
.venv/Scripts/python -m ruff format --check llmguard
```
Expected: `All checks passed!` and no files to reformat.

- [ ] **Step 5: Split the CI lint job into blocking-core + informational-app**

Replace the `lint` job in `.github/workflows/ci.yml` with two jobs:

```yaml
  lint-core:
    name: Lint & format (core, blocking)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - name: Install (core + dev)
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"
      - name: Ruff (lint, core)
        run: ruff check llmguard
      - name: Ruff (format check, core)
        run: ruff format --check llmguard

  lint-app:
    name: Lint (app, informational)
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - name: Install (core + dev)
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"
      - name: Ruff (lint, app)
        run: ruff check app
```

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml llmguard .github/workflows/ci.yml
git commit -m "ci: make ruff lint+format blocking on core package"
```

## Task A2: Add pre-commit local gate

**Files:**
- Create: `.pre-commit-config.yaml`
- Modify: `pyproject.toml` (add `pre-commit` to `[project.optional-dependencies].dev`)

**Interfaces:**
- Produces: a `pre-commit` hook set developers run before push; mirrors the CI `lint-core` gate plus a fast unit subset.

- [ ] **Step 1: Add pre-commit to dev extras**

In `pyproject.toml`, `dev` list, add:
```toml
    "pre-commit>=4,<5",
```

- [ ] **Step 2: Create `.pre-commit-config.yaml`**

```yaml
# Local dev gate — mirrors CI lint-core. Install with: pre-commit install
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.8.6
    hooks:
      - id: ruff
        name: ruff (lint, core)
        args: [--fix]
        files: ^llmguard/
      - id: ruff-format
        name: ruff (format, core)
        files: ^llmguard/
  - repo: local
    hooks:
      - id: pytest-fast
        name: pytest (unit, fast)
        entry: python -m pytest tests/unit -q
        language: system
        pass_filenames: false
        stages: [pre-push]
```

- [ ] **Step 3: Install and run against all files**

Run:
```bash
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/pre-commit install --install-hooks
.venv/Scripts/pre-commit run --all-files
```
Expected: `ruff` and `ruff-format` hooks pass on `llmguard/` (they only match `^llmguard/`). Fix any residual finding they surface.

- [ ] **Step 4: Commit**

```bash
git add .pre-commit-config.yaml pyproject.toml
git commit -m "ci: add pre-commit local gate mirroring lint-core"
```

## Task A3: Baseline + ratchet mypy on `llmguard/`, make it blocking

**Files:**
- Modify: `pyproject.toml` (`[tool.mypy]` overrides = the baseline ignore list)
- Modify: `.github/workflows/ci.yml` (add a blocking `types` job)

**Interfaces:**
- Produces: a green `mypy llmguard` gate achieved by explicitly ignoring today's failing modules (the "baseline"), so *new* code is fully type-checked and the ignore list can only shrink.

- [ ] **Step 1: Capture the current failing modules**

Run:
```bash
.venv/Scripts/python -m mypy llmguard --no-error-summary 2>&1 | grep -oE '^llmguard/[^:]+' | sort -u
```
Expected: a list of `.py` files with type errors. If the list is empty, skip Steps 2–3 and make the job blocking directly.

- [ ] **Step 2: Write the baseline overrides**

For each failing file from Step 1, add a per-module override in `pyproject.toml`. Convert the path to a module (`llmguard/detectors/pii.py` → `llmguard.detectors.pii`). Example (replace the module list with the ACTUAL failing modules from Step 1):

```toml
[[tool.mypy.overrides]]
# BASELINE: pre-existing type debt. Ratchet DOWN — never add modules here.
# Remove a line once its module type-checks clean.
module = [
    "llmguard.detectors.pii",
    "llmguard.detectors.registry",
    "llmguard.transport",
]
ignore_errors = true
```

- [ ] **Step 3: Verify the gate is green with the baseline**

Run: `.venv/Scripts/python -m mypy llmguard`
Expected: `Success: no issues found in N source files`. If errors remain, add the offending module to the override list and re-run until green.

- [ ] **Step 4: Add a blocking `types` job to CI**

Add to `.github/workflows/ci.yml`:

```yaml
  types:
    name: Types (core, blocking)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: pip
      - name: Install (core + dev)
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"
      - name: Mypy (core, baseline-ratcheted)
        run: mypy llmguard
```

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml .github/workflows/ci.yml
git commit -m "ci: baseline-ratchet mypy and make it blocking on core"
```

---

# PART B — Phase 2: Deterministic Metrics Harness (`bench/eval/`)

> **Scope — what's real vs. substituted (read before implementing):**
> The harness drives the **real** production code path — `create_app`, the real detector
> pipeline, the real policy engine, the real `LLMProxy`/litellm transport, over a **real**
> uvicorn socket. The **only** thing substituted is the **upstream LLM provider**, and that is
> done by env-redirect (`OPENAI_API_BASE`), *not* by monkeypatching any internal function.
> Two deliberate scope limits: **(1)** heavy detector tiers are *configured off* via real config
> flags (regex-only gate) — real code, reduced profile, not a mock; **(2)** this exercises the
> **API-proxy entry point only** (`llmguard/app.py`). The browser-MITM path, system-proxy
> registration, CA trust, real traffic interception, and the desktop app are **out of scope here**
> — they are covered by Phase 3's two-ring VM E2E, not this plan.


**File structure (all new):**
- `bench/eval/__init__.py` — package marker + public exports
- `bench/eval/corpus.py` — `CorpusRow`, `load_corpus`, `corpus_checksum`
- `bench/eval/data/corpus.jsonl` — seed labeled corpus
- `bench/eval/mock_upstream.py` — echo mock server + `running_mock` context manager
- `bench/eval/runner.py` — black-box driver: `classify_action`, `observe_corpus`, `Observation`
- `bench/eval/metrics.py` — `Metrics`, `compute_metrics`
- `bench/eval/scorecard.py` — `to_json`, `to_markdown`
- `bench/eval/__main__.py` — CLI (`python -m bench.eval run ...`)
- `tests/eval/test_corpus.py`, `test_metrics.py`, `test_scorecard.py`, `test_runner_e2e.py`
- `.github/workflows/eval.yml` — PR-vs-main diff + gate + comment

Add to `pyproject.toml` `[project.optional-dependencies].dev`: `"uvicorn[standard]"` is already a core dep; no new deps needed (fastapi, httpx, uvicorn, litellm all present).

## Task B1: Corpus schema, loader, checksum + seed data

**Files:**
- Create: `bench/eval/__init__.py`, `bench/eval/corpus.py`, `bench/eval/data/corpus.jsonl`
- Test: `tests/eval/test_corpus.py`

**Interfaces:**
- Produces:
  - `CorpusRow(id: str, text: str, expected_action: str, categories: tuple[str, ...])` — frozen dataclass; `expected_action ∈ {"allow","redact","block"}`.
  - `load_corpus(path: Path) -> list[CorpusRow]`
  - `corpus_checksum(rows: list[CorpusRow]) -> str` — sha256 hex of canonical JSON (stable ordering).

- [ ] **Step 1: Write the failing test**

`tests/eval/test_corpus.py`:
```python
from pathlib import Path

from bench.eval.corpus import CorpusRow, corpus_checksum, load_corpus

DATA = Path(__file__).parent.parent.parent / "bench" / "eval" / "data" / "corpus.jsonl"


def test_load_corpus_parses_rows():
    rows = load_corpus(DATA)
    assert len(rows) >= 12
    assert all(isinstance(r, CorpusRow) for r in rows)
    assert all(r.expected_action in {"allow", "redact", "block"} for r in rows)
    assert len({r.id for r in rows}) == len(rows)  # ids unique


def test_checksum_is_stable_and_order_independent():
    rows = load_corpus(DATA)
    assert corpus_checksum(rows) == corpus_checksum(list(reversed(rows)))
    assert len(corpus_checksum(rows)) == 64  # sha256 hex


def test_load_rejects_bad_action(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"id": "x", "text": "hi", "expected_action": "nope"}\n', encoding="utf-8")
    try:
        load_corpus(bad)
        assert False, "expected ValueError"
    except ValueError:
        pass
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/eval/test_corpus.py -q`
Expected: FAIL — `ModuleNotFoundError: bench.eval.corpus`.

- [ ] **Step 3: Write the implementation**

`bench/eval/__init__.py`:
```python
"""Deterministic, black-box detection-quality metrics harness."""
```

`bench/eval/corpus.py`:
```python
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
```

`bench/eval/data/corpus.jsonl` (seed set calibrated to the always-on `SecretDetector` regex; the `block`/`redact` rows the regex misses are the deliberate *circumvention* probes):
```jsonl
{"id": "sec-aws", "text": "Here is my AWS key AKIAIOSFODNN7EXAMPLE for the deploy.", "expected_action": "block", "categories": ["aws_key"]}
{"id": "sec-github", "text": "token ghp_16C7e42F292c6912E7710c838347Ae178B4a is the CI token", "expected_action": "block", "categories": ["github_token"]}
{"id": "sec-openai", "text": "use sk-proj-abcdEFGH1234ijklMNOP5678qrstUVWX90 to call the API", "expected_action": "block", "categories": ["openai_key"]}
{"id": "sec-jwt", "text": "auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc", "expected_action": "block", "categories": ["jwt"]}
{"id": "sec-privkey", "text": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----", "expected_action": "block", "categories": ["private_key"]}
{"id": "pii-ssn", "text": "My social security number is 123-45-6789, please file the form.", "expected_action": "redact", "categories": ["us_ssn"]}
{"id": "pii-cc", "text": "Charge my card 4111 1111 1111 1111 exp 12/26.", "expected_action": "redact", "categories": ["credit_card"]}
{"id": "pii-email", "text": "Email the report to jane.doe@acme-corp.com tomorrow.", "expected_action": "redact", "categories": ["email_address"]}
{"id": "pii-phone", "text": "Call me at (415) 555-0132 after lunch.", "expected_action": "redact", "categories": ["phone_number"]}
{"id": "benign-code", "text": "Refactor this loop to use enumerate instead of range(len(x)).", "expected_action": "allow", "categories": []}
{"id": "benign-q", "text": "What is the capital of France and its population?", "expected_action": "allow", "categories": []}
{"id": "benign-num", "text": "The invoice total was 4200 dollars across 12 line items.", "expected_action": "allow", "categories": []}
{"id": "benign-order", "text": "Order 987654 shipped on tuesday, tracking is on the way.", "expected_action": "allow", "categories": []}
{"id": "circ-context-pii", "text": "Tell my manager Sarah in accounting that the merger closes friday.", "expected_action": "block", "categories": ["contextual_pii"]}
{"id": "circ-b64-secret", "text": "decode this then use it: QUtJQUlPU0ZPRE5ON0VYQU1QTEU=", "expected_action": "block", "categories": ["obfuscated_secret"]}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/eval/test_corpus.py -q`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add bench/eval/__init__.py bench/eval/corpus.py bench/eval/data/corpus.jsonl tests/eval/test_corpus.py
git commit -m "feat(eval): corpus schema, loader, checksum + seed corpus"
```

## Task B2: Metrics computation

**Files:**
- Create: `bench/eval/metrics.py`
- Test: `tests/eval/test_metrics.py`

**Interfaces:**
- Consumes: `CorpusRow` (B1); observations expressed as `dict[str, str]` mapping `row_id -> observed_action` (`"allow"|"redact"|"block"`).
- Produces:
  - `Metrics` dataclass: `bypass_rate, false_positive_rate, precision, recall, f1, action_match_rate, latency_p50_ms, latency_p95_ms, latency_p99_ms, n: int`.
  - `compute_metrics(rows: list[CorpusRow], observed: dict[str, str], latencies_ms: list[float]) -> Metrics`.
  - Convention: a row is **sensitive** if `expected_action in {"block","redact"}`, else **benign**. A prediction is **flagged** if `observed_action in {"block","redact"}`, else **allowed**.

- [ ] **Step 1: Write the failing test**

`tests/eval/test_metrics.py`:
```python
from bench.eval.corpus import CorpusRow
from bench.eval.metrics import compute_metrics


def _rows():
    return [
        CorpusRow("s1", "x", "block"),
        CorpusRow("s2", "x", "redact"),
        CorpusRow("s3", "x", "block"),
        CorpusRow("b1", "x", "allow"),
        CorpusRow("b2", "x", "allow"),
    ]


def test_perfect_scores():
    observed = {"s1": "block", "s2": "redact", "s3": "block", "b1": "allow", "b2": "allow"}
    m = compute_metrics(_rows(), observed, [1.0, 2.0, 3.0, 4.0, 5.0])
    assert m.bypass_rate == 0.0
    assert m.false_positive_rate == 0.0
    assert m.recall == 1.0
    assert m.precision == 1.0
    assert m.f1 == 1.0
    assert m.action_match_rate == 1.0
    assert m.n == 5


def test_one_bypass_one_false_positive():
    # s3 slips through (bypass); b1 wrongly flagged (false positive)
    observed = {"s1": "block", "s2": "redact", "s3": "allow", "b1": "block", "b2": "allow"}
    m = compute_metrics(_rows(), observed, [10.0] * 5)
    assert round(m.bypass_rate, 3) == round(1 / 3, 3)      # 1 of 3 sensitive allowed
    assert m.false_positive_rate == 0.5                     # 1 of 2 benign flagged
    assert round(m.recall, 3) == round(2 / 3, 3)           # TP=2, FN=1
    assert round(m.precision, 3) == round(2 / 3, 3)        # TP=2, FP=1


def test_latency_percentiles():
    observed = {r.id: "allow" for r in _rows()}
    m = compute_metrics(_rows(), observed, [1, 2, 3, 4, 100])
    assert m.latency_p50_ms == 3
    assert m.latency_p99_ms == 100
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/eval/test_metrics.py -q`
Expected: FAIL — `ModuleNotFoundError: bench.eval.metrics`.

- [ ] **Step 3: Write the implementation**

`bench/eval/metrics.py`:
```python
from __future__ import annotations

from dataclasses import dataclass

_FLAGGED = {"block", "redact"}


@dataclass(frozen=True)
class Metrics:
    bypass_rate: float
    false_positive_rate: float
    precision: float
    recall: float
    f1: float
    action_match_rate: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    n: int


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    # nearest-rank
    k = max(0, min(len(ordered) - 1, round(pct / 100.0 * (len(ordered) - 1))))
    return float(ordered[k])


def compute_metrics(rows, observed, latencies_ms) -> Metrics:
    tp = fp = fn = tn = 0
    bypass = fp_count = 0
    sensitive = benign = 0
    action_match = 0

    for row in rows:
        obs = observed[row.id]
        is_sensitive = row.expected_action in _FLAGGED
        is_flagged = obs in _FLAGGED
        if obs == row.expected_action:
            action_match += 1
        if is_sensitive:
            sensitive += 1
            if is_flagged:
                tp += 1
            else:
                fn += 1
                bypass += 1
        else:
            benign += 1
            if is_flagged:
                fp += 1
                fp_count += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    n = len(rows)
    return Metrics(
        bypass_rate=bypass / sensitive if sensitive else 0.0,
        false_positive_rate=fp_count / benign if benign else 0.0,
        precision=precision,
        recall=recall,
        f1=f1,
        action_match_rate=action_match / n if n else 0.0,
        latency_p50_ms=_percentile(latencies_ms, 50),
        latency_p95_ms=_percentile(latencies_ms, 95),
        latency_p99_ms=_percentile(latencies_ms, 99),
        n=n,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/eval/test_metrics.py -q`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add bench/eval/metrics.py tests/eval/test_metrics.py
git commit -m "feat(eval): metrics (bypass, FP, P/R/F1, latency percentiles)"
```

## Task B3: Scorecard rendering (JSON + Markdown diff)

**Files:**
- Create: `bench/eval/scorecard.py`
- Test: `tests/eval/test_scorecard.py`

**Interfaces:**
- Consumes: `Metrics` (B2).
- Produces:
  - `to_json(metrics: Metrics, *, commit: str, corpus_sha: str, profile: str) -> str` — deterministic JSON (sorted keys).
  - `to_markdown(current: Metrics, baseline: Metrics | None) -> str` — table; when `baseline` given, adds a delta column and arrows.

- [ ] **Step 1: Write the failing test**

`tests/eval/test_scorecard.py`:
```python
import json

from bench.eval.metrics import Metrics
from bench.eval.scorecard import to_json, to_markdown


def _m(**kw):
    base = dict(bypass_rate=0.1, false_positive_rate=0.0, precision=1.0, recall=0.9,
               f1=0.95, action_match_rate=0.9, latency_p50_ms=1.0, latency_p95_ms=2.0,
               latency_p99_ms=3.0, n=15)
    base.update(kw)
    return Metrics(**base)


def test_to_json_roundtrips_and_includes_meta():
    payload = to_json(_m(), commit="abc123", corpus_sha="deadbeef", profile="core")
    data = json.loads(payload)
    assert data["commit"] == "abc123"
    assert data["corpus_sha"] == "deadbeef"
    assert data["profile"] == "core"
    assert data["metrics"]["bypass_rate"] == 0.1


def test_markdown_shows_delta_direction():
    current = _m(bypass_rate=0.05)      # improved (lower)
    baseline = _m(bypass_rate=0.10)
    md = to_markdown(current, baseline)
    assert "bypass_rate" in md
    assert "better" in md               # lower bypass is better


def test_markdown_without_baseline():
    md = to_markdown(_m(), None)
    assert "bypass_rate" in md
    assert "n = 15" in md
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/eval/test_scorecard.py -q`
Expected: FAIL — `ModuleNotFoundError: bench.eval.scorecard`.

- [ ] **Step 3: Write the implementation**

`bench/eval/scorecard.py`:
```python
from __future__ import annotations

import json
from dataclasses import asdict

from bench.eval.metrics import Metrics

# For each metric: True if a LOWER value is better.
_LOWER_BETTER = {
    "bypass_rate": True, "false_positive_rate": True,
    "precision": False, "recall": False, "f1": False, "action_match_rate": False,
    "latency_p50_ms": True, "latency_p95_ms": True, "latency_p99_ms": True,
}


def to_json(metrics: Metrics, *, commit: str, corpus_sha: str, profile: str) -> str:
    return json.dumps(
        {"commit": commit, "corpus_sha": corpus_sha, "profile": profile,
         "metrics": asdict(metrics)},
        sort_keys=True, indent=2,
    )


def _fmt(value: float) -> str:
    return f"{value:.4f}" if isinstance(value, float) else str(value)


def to_markdown(current: Metrics, baseline: Metrics | None) -> str:
    cur = asdict(current)
    base = asdict(baseline) if baseline else None
    lines = ["### LLMGuard eval scorecard", "", f"n = {current.n}", ""]
    if base is None:
        lines += ["| metric | value |", "| --- | --- |"]
        for key, val in cur.items():
            if key == "n":
                continue
            lines.append(f"| {key} | {_fmt(val)} |")
    else:
        lines += ["| metric | main | PR | Δ | verdict |", "| --- | --- | --- | --- | --- |"]
        for key, val in cur.items():
            if key == "n":
                continue
            b = base[key]
            delta = val - b
            if abs(delta) < 1e-9:
                verdict = "="
            else:
                improved = (delta < 0) == _LOWER_BETTER[key]
                verdict = "✅ better" if improved else "⚠️ worse"
            lines.append(f"| {key} | {_fmt(b)} | {_fmt(val)} | {delta:+.4f} | {verdict} |")
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/eval/test_scorecard.py -q`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add bench/eval/scorecard.py tests/eval/test_scorecard.py
git commit -m "feat(eval): JSON + markdown scorecard with baseline diff"
```

## Task B4: Mock upstream (echo server)

**Files:**
- Create: `bench/eval/mock_upstream.py`
- Test: `tests/eval/test_mock_upstream.py`

**Interfaces:**
- Produces:
  - `MockUpstream` — holds `received: list[dict]`; `build_app() -> FastAPI` exposes `POST /v1/chat/completions` (records body, returns a canned OpenAI ChatCompletion) and `GET /health`.
  - `serve(app) -> ContextManager[str]` — generic helper that runs any ASGI app in a uvicorn thread on an ephemeral localhost port and yields its **root** base URL (e.g. `http://127.0.0.1:54321`). Reused by the runner (Task B5) to boot the firewall over a real socket — this keeps the harness black-box (real HTTP, swappable for a Rust server).
  - `running_mock() -> ContextManager[MockUpstreamHandle]` where `MockUpstreamHandle` has `.base_url: str` (root + `/v1`) and `.mock: MockUpstream`.

- [ ] **Step 1: Write the failing test**

`tests/eval/test_mock_upstream.py`:
```python
import httpx

from bench.eval.mock_upstream import running_mock


def test_mock_records_body_and_returns_openai_shape():
    with running_mock() as handle:
        r = httpx.post(
            f"{handle.base_url}/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi there"}]},
            timeout=5,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["choices"][0]["message"]["role"] == "assistant"
        assert handle.mock.received[-1]["messages"][-1]["content"] == "hi there"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/eval/test_mock_upstream.py -q`
Expected: FAIL — `ModuleNotFoundError: bench.eval.mock_upstream`.

- [ ] **Step 3: Write the implementation**

`bench/eval/mock_upstream.py`:
```python
from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import uvicorn
from fastapi import FastAPI, Request

_CANNED_RESPONSE: dict[str, Any] = {
    "id": "chatcmpl-mock",
    "object": "chat.completion",
    "created": 0,
    "model": "gpt-4o-mini",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
    ],
    "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
}


class MockUpstream:
    """OpenAI-compatible echo server: records each request body verbatim."""

    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []

    def build_app(self) -> FastAPI:
        app = FastAPI()

        @app.get("/health")
        async def health() -> dict[str, str]:
            return {"status": "ok"}

        @app.post("/v1/chat/completions")
        async def chat(request: Request) -> dict[str, Any]:
            self.received.append(await request.json())
            return _CANNED_RESPONSE

        return app


@dataclass
class MockUpstreamHandle:
    base_url: str
    mock: MockUpstream


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


@contextmanager
def serve(app: Any) -> Iterator[str]:
    """Run any ASGI app in a background uvicorn thread; yield its root base URL."""
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(250):
        if server.started:
            break
        time.sleep(0.02)
    else:
        raise RuntimeError("ASGI app did not start in time")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@contextmanager
def running_mock() -> Iterator[MockUpstreamHandle]:
    mock = MockUpstream()
    with serve(mock.build_app()) as root:
        yield MockUpstreamHandle(base_url=f"{root}/v1", mock=mock)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/eval/test_mock_upstream.py -q`
Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add bench/eval/mock_upstream.py tests/eval/test_mock_upstream.py
git commit -m "feat(eval): OpenAI-compatible echo mock upstream"
```

## Task B5: Black-box runner (observe + classify)

**Files:**
- Create: `bench/eval/runner.py`
- Test: `tests/eval/test_runner_e2e.py`

**Interfaces:**
- Consumes: `CorpusRow` (B1), `running_mock`/`MockUpstreamHandle` (B4), the real firewall app via `llmguard.app.create_app` + `llmguard.config.Settings`.
- Produces:
  - `classify_action(status_code: int, sent_text: str, upstream_text: str | None) -> str` → `"block"|"redact"|"allow"`.
  - `Observation(row_id: str, observed_action: str, status_code: int, latency_ms: float)`.
  - `observe_corpus(rows: list[CorpusRow]) -> tuple[list[Observation], dict[str, str]]` — boots mock + firewall (in-process ASGI), drives every row sequentially, returns observations and the `row_id -> observed_action` map.
- Determinism: sets env `OPENAI_API_BASE=<mock>/`, `OPENAI_API_KEY=sk-test`, `LLMGUARD_OPENAI_API_KEY=sk-test`, `LLMGUARD_FAIL_MODE=closed`, `PYTHONHASHSEED=0`; all detector flags default `False` (regex-only gate profile).

- [ ] **Step 1: Write the failing test**

`tests/eval/test_runner_e2e.py`:
```python
from bench.eval.corpus import CorpusRow
from bench.eval.runner import classify_action, observe_corpus


def test_classify_action_rules():
    assert classify_action(403, "secret", None) == "block"
    assert classify_action(200, "hello world", "hello world") == "allow"
    assert classify_action(200, "my ssn 123-45-6789", "my ssn [US_SSN_REDACTED]") == "redact"


def test_observe_corpus_end_to_end():
    rows = [
        CorpusRow("blk", "AWS key AKIAIOSFODNN7EXAMPLE here", "block", ("aws_key",)),
        CorpusRow("red", "my ssn is 123-45-6789", "redact", ("us_ssn",)),
        CorpusRow("ok", "what is the capital of France?", "allow", ()),
    ]
    observations, observed = observe_corpus(rows)
    assert observed["blk"] == "block"
    assert observed["red"] == "redact"
    assert observed["ok"] == "allow"
    assert all(o.latency_ms >= 0 for o in observations)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/eval/test_runner_e2e.py -q`
Expected: FAIL — `ModuleNotFoundError: bench.eval.runner`.

- [ ] **Step 3: Write the implementation**

`bench/eval/runner.py`:
```python
from __future__ import annotations

import os
import time
from dataclasses import dataclass

import httpx

from bench.eval.corpus import CorpusRow
from bench.eval.mock_upstream import MockUpstreamHandle, running_mock, serve


@dataclass(frozen=True)
class Observation:
    row_id: str
    observed_action: str
    status_code: int
    latency_ms: float


def classify_action(status_code: int, sent_text: str, upstream_text: str | None) -> str:
    """Map the HTTP-boundary evidence to a verdict (language-agnostic)."""
    if status_code == 403:
        return "block"
    if status_code == 200:
        if upstream_text is None:
            return "block"  # nothing reached upstream despite 200 → treat as blocked
        return "allow" if upstream_text == sent_text else "redact"
    raise RuntimeError(f"unexpected firewall status {status_code}")


def _configure_determinism(handle: MockUpstreamHandle) -> None:
    # litellm/openai read either of these for the upstream base URL.
    os.environ["OPENAI_API_BASE"] = handle.base_url
    os.environ["OPENAI_BASE_URL"] = handle.base_url
    os.environ["OPENAI_API_KEY"] = "sk-test"
    os.environ["LLMGUARD_OPENAI_API_KEY"] = "sk-test"
    os.environ["LLMGUARD_FAIL_MODE"] = "closed"
    os.environ["PYTHONHASHSEED"] = "0"


def observe_corpus(rows: list[CorpusRow]) -> tuple[list[Observation], dict[str, str]]:
    observations: list[Observation] = []
    observed: dict[str, str] = {}

    with running_mock() as handle:
        # Env must be set BEFORE create_app/Settings/LLMProxy read it.
        _configure_determinism(handle)
        # Import after env is set so litellm/Settings pick up the mock upstream.
        from llmguard.app import create_app
        from llmguard.config import Settings

        firewall_app = create_app(Settings())  # detector flags default False → regex-only gate
        with serve(firewall_app) as fw_url:
            with httpx.Client(base_url=fw_url, timeout=30) as client:
                for row in rows:
                    before = len(handle.mock.received)
                    payload = {"model": "gpt-4o-mini",
                               "messages": [{"role": "user", "content": row.text}]}
                    t0 = time.perf_counter()
                    resp = client.post("/v1/chat/completions", json=payload)
                    latency_ms = (time.perf_counter() - t0) * 1000
                    upstream_text: str | None = None
                    if len(handle.mock.received) > before:
                        body = handle.mock.received[-1]
                        upstream_text = body["messages"][-1]["content"]
                    action = classify_action(resp.status_code, row.text, upstream_text)
                    observations.append(
                        Observation(row.id, action, resp.status_code, round(latency_ms, 3))
                    )
                    observed[row.id] = action

    return observations, observed
```

> **Note on latency:** this now measures real localhost-socket round-trip (~1–3 ms overhead) rather than in-process. That overhead is constant across runs, so regression *deltas* stay meaningful; the absolute p99 is "end-to-end incl. loopback", which is the honest black-box number.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/eval/test_runner_e2e.py -q`
Expected: 2 passed. (If `red` classifies as `block` instead of `redact`, the shipped default policy blocks SSN rather than redacting it — update the `red` row's `expected_action` to match the *intended* policy, and note the discrepancy for the policy owner. The metric still counts both as "flagged".)

- [ ] **Step 5: Commit**

```bash
git add bench/eval/runner.py tests/eval/test_runner_e2e.py
git commit -m "feat(eval): black-box runner boots firewall+mock, observes verdicts"
```

## Task B6: CLI entrypoint

**Files:**
- Create: `bench/eval/__main__.py`
- Test: `tests/eval/test_cli.py`

**Interfaces:**
- Consumes: everything above.
- Produces: `python -m bench.eval run --corpus <path> --out <results.json> [--baseline <base.json>] [--commit <sha>] [--fail-on-regression]`.
  - Writes the JSON scorecard to `--out`, prints the markdown scorecard to stdout.
  - With `--fail-on-regression` + `--baseline`: exit 1 if `bypass_rate` or `false_positive_rate` rose by more than 0.001 vs baseline.
- `run_eval(corpus_path, out_path, *, baseline_path, commit, fail_on_regression) -> int` is the importable core (returns intended exit code).

- [ ] **Step 1: Write the failing test**

`tests/eval/test_cli.py`:
```python
import json
from pathlib import Path

from bench.eval.__main__ import run_eval

DATA = Path("bench/eval/data/corpus.jsonl")


def test_run_eval_writes_results(tmp_path):
    out = tmp_path / "results.json"
    code = run_eval(DATA, out, baseline_path=None, commit="testsha", fail_on_regression=False)
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["commit"] == "testsha"
    assert "bypass_rate" in data["metrics"]
    assert data["metrics"]["n"] >= 12


def test_fail_on_regression_trips(tmp_path):
    good = tmp_path / "base.json"
    run_eval(DATA, good, baseline_path=None, commit="base", fail_on_regression=False)
    # Corrupt the baseline to a perfect score so current looks like a regression.
    payload = json.loads(good.read_text(encoding="utf-8"))
    payload["metrics"]["bypass_rate"] = 0.0
    payload["metrics"]["false_positive_rate"] = 0.0
    good.write_text(json.dumps(payload), encoding="utf-8")
    out = tmp_path / "cur.json"
    code = run_eval(DATA, out, baseline_path=good, commit="cur", fail_on_regression=True)
    # If the current corpus has any bypass at all, this must trip.
    cur = json.loads(out.read_text(encoding="utf-8"))
    expected = 1 if cur["metrics"]["bypass_rate"] > 0.001 else 0
    assert code == expected
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/eval/test_cli.py -q`
Expected: FAIL — `ModuleNotFoundError` / `run_eval` undefined.

- [ ] **Step 3: Write the implementation**

`bench/eval/__main__.py`:
```python
from __future__ import annotations

import argparse
import json
from pathlib import Path

from bench.eval.corpus import corpus_checksum, load_corpus
from bench.eval.metrics import Metrics, compute_metrics
from bench.eval.runner import observe_corpus
from bench.eval.scorecard import to_json, to_markdown

_REGRESSION_EPS = 0.001


def _metrics_from_json(path: Path) -> Metrics:
    data = json.loads(path.read_text(encoding="utf-8"))["metrics"]
    return Metrics(**data)


def run_eval(
    corpus_path: Path,
    out_path: Path,
    *,
    baseline_path: Path | None,
    commit: str,
    fail_on_regression: bool,
) -> int:
    rows = load_corpus(corpus_path)
    observations, observed = observe_corpus(rows)
    latencies = [o.latency_ms for o in observations]
    metrics = compute_metrics(rows, observed, latencies)

    out_path.write_text(
        to_json(metrics, commit=commit, corpus_sha=corpus_checksum(rows), profile="core"),
        encoding="utf-8",
    )

    baseline = _metrics_from_json(baseline_path) if baseline_path else None
    print(to_markdown(metrics, baseline))

    if fail_on_regression and baseline is not None:
        if (metrics.bypass_rate > baseline.bypass_rate + _REGRESSION_EPS
                or metrics.false_positive_rate > baseline.false_positive_rate + _REGRESSION_EPS):
            print("REGRESSION: bypass_rate or false_positive_rate increased vs baseline")
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="bench.eval")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run the deterministic eval")
    run.add_argument("--corpus", type=Path, default=Path("bench/eval/data/corpus.jsonl"))
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--baseline", type=Path, default=None)
    run.add_argument("--commit", type=str, default="local")
    run.add_argument("--fail-on-regression", action="store_true")
    args = parser.parse_args()
    return run_eval(
        args.corpus, args.out,
        baseline_path=args.baseline, commit=args.commit,
        fail_on_regression=args.fail_on_regression,
    )


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/eval/test_cli.py -q`
Then a real smoke run:
```bash
.venv/Scripts/python -m bench.eval run --out /tmp/results.json --commit smoke
```
Expected: tests pass; smoke run prints a markdown table and writes `results.json`.

- [ ] **Step 5: Commit**

```bash
git add bench/eval/__main__.py tests/eval/test_cli.py
git commit -m "feat(eval): CLI with results.json output and regression gate"
```

## Task B7: Committed baseline + Eval CI workflow (diff, gate, comment)

**Files:**
- Create: `bench/eval/data/baseline.json` (the accepted metrics snapshot on `main`)
- Create: `.github/workflows/eval.yml`

**Interfaces:**
- Consumes: `python -m bench.eval run` (B6).
- Produces: on every PR — a `pr-results.json` artifact, a scorecard **PR comment** diffing the PR against the committed `baseline.json`, and a **failing check** if `bypass_rate` or `false_positive_rate` regressed.

**Design note — why a committed baseline, not a live `main` re-run:** the harness (`bench/eval`) and the system-under-test (`llmguard`) live in the same repo and share package names, so re-running the harness against a second `main` checkout has an unresolvable tool-vs-subject import ambiguity. Instead we **snapshot the accepted metrics into `baseline.json` and commit it.** A PR that *intentionally* moves metrics regenerates that file in the same PR (its diff makes the change reviewable) — the standard snapshot-testing pattern, fully deterministic and single-checkout.

- [ ] **Step 1: Generate and commit the baseline snapshot**

Run the deterministic eval on the current branch and save it as the committed baseline:
```bash
.venv/Scripts/python -m bench.eval run --out bench/eval/data/baseline.json --commit baseline
```
Expected: `bench/eval/data/baseline.json` written with a `metrics` block. Commit it:
```bash
git add bench/eval/data/baseline.json
git commit -m "feat(eval): commit baseline metrics snapshot"
```

- [ ] **Step 2: Create the workflow**

`.github/workflows/eval.yml`:
```yaml
name: Eval

on:
  pull_request:
    branches: [main]

concurrency:
  group: eval-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read
  pull-requests: write

jobs:
  eval:
    name: Deterministic metrics
    runs-on: ubuntu-latest
    env:
      PYTHONHASHSEED: "0"
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip

      - name: Install (core + dev)
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"

      - name: Run eval + regression gate (vs committed baseline)
        run: |
          python -m bench.eval run \
            --out pr-results.json \
            --baseline bench/eval/data/baseline.json \
            --commit "${{ github.event.pull_request.head.sha }}" \
            --fail-on-regression | tee scorecard.md

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: eval-results
          path: pr-results.json

      - name: Comment scorecard on PR
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            let body = "### LLMGuard eval scorecard\n_(scorecard unavailable)_";
            try { body = fs.readFileSync('scorecard.md', 'utf8'); } catch (e) {}
            const marker = "<!-- llmguard-eval-scorecard -->";
            body = marker + "\n" + body;
            const { data: comments } = await github.rest.issues.listComments({
              owner: context.repo.owner, repo: context.repo.repo,
              issue_number: context.issue.number,
            });
            const existing = comments.find(c => c.body && c.body.includes(marker));
            if (existing) {
              await github.rest.issues.updateComment({
                owner: context.repo.owner, repo: context.repo.repo,
                comment_id: existing.id, body,
              });
            } else {
              await github.rest.issues.createComment({
                owner: context.repo.owner, repo: context.repo.repo,
                issue_number: context.issue.number, body,
              });
            }
```

- [ ] **Step 3: Validate the workflow YAML locally**

Run: `.venv/Scripts/python -c "import yaml; yaml.safe_load(open('.github/workflows/eval.yml')); print('yaml ok')"`
Expected: `yaml ok`.

- [ ] **Step 4: Commit and push a test PR**

```bash
git add .github/workflows/eval.yml
git commit -m "feat(eval): PR eval workflow with scorecard comment + regression gate"
```
Open a draft PR and confirm: the `Eval` check runs, a scorecard comment appears diffing against the committed baseline, and `pr-results.json` uploads. To prove the gate bites, temporarily weaken a `SecretDetector` pattern on a throwaway branch and confirm the check fails with a `bypass_rate` regression.

**Maintenance rule (document in the PR description template later):** when a change *intentionally* alters detection metrics, regenerate `bench/eval/data/baseline.json` in the same PR so the new numbers are reviewed alongside the code.

---

## Self-Review Notes (author)

- **Spec coverage:** Phase 1 (baseline CI + local pre-commit) = Part A; Phase 2 (mock upstream, pinned/regex-only deterministic profile, labeled corpus, bypass/FP/F1/latency metrics, PR-comment diff vs a committed baseline snapshot, shareable JSON scorecard) = Part B. Black-box real-socket HTTP boundary satisfies the "language-agnostic conformance suite" requirement (swap `serve(create_app(...))` for a Rust base URL and the suite is unchanged). **Deferred to explicit follow-ups (not in this plan):** Presidio/GLiNER/semantic advisory lanes, the shared `LLMGuard-CI` repo extraction, trend store/dashboard (Phase 4), and cross-platform build/E2E (Phase 3).
- **Baseline model:** committed `bench/eval/data/baseline.json` snapshot (not a live `main` re-run) — avoids the harness-vs-SUT import ambiguity; intentional metric changes regenerate it in-PR.
- **Regex-only gate rationale:** keeps CI install light (`.[dev]` only), byte-deterministic, and <10s — the Presidio lane is the immediate next increment (add `--profile pii`, install `.[pii]` + pinned spaCy model, run non-blocking).
- **Known calibration coupling:** corpus `expected_action` for `redact` vs `block` rows is coupled to `llmguard/policy/rules.yaml`; Task B5 Step 4 documents reconciling the seed row if the shipped policy differs. Metrics headline numbers (bypass/FP) are robust to that block-vs-redact choice.
