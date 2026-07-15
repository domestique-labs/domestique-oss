# Repository layout & module boundaries

This repo hosts two Python packages plus benchmark and evaluation suites. This note
explains what belongs where and the dependency direction between them.

## The two packages

### `domestique/` — the core firewall (standalone library + CLI)
The redacting proxy engine and its CLI. Detectors, policy, transport, audit logging,
prompt extraction/redaction, and the `domestique start` / `domestique demo` entry
points live here. It depends **only** on third-party libraries — never on `app/`.
You can `pip install` and use it with no desktop/browser components present.

### `app/` — the desktop + browser application
The macOS menu-bar app, the browser-interception MITM addon, the dashboard/server
API, cert management, and system-proxy/PAC integration. `app/` **depends on**
`domestique/` (it reuses the core detection/redaction), never the reverse.

```
app/  ──depends on──▶  domestique/        (one direction only)
```

> **Layering rule:** `domestique/` must not import from `app/`. Shared logic (e.g.
> `domestique/redaction.py`, moved here from `app/services/`) lives in core so the
> library stays installable and testable on its own.

## Benchmarks vs. evaluation

Two top-level suites with distinct purposes — kept separate on purpose:

| Dir | Purpose | Entry points |
|---|---|---|
| `bench/` | **Deterministic detection-quality eval harness** — labeled corpus, bypass/FP/F1/latency metrics, PR scorecard, plus browser-perf micro-benchmarks. | `python -m bench.eval` · `bench/eval/`, `bench/browser_perf/` |
| `benchmarks/` | **File-scanning benchmark** — measures detection over a dataset of documents/images (PDF/CSV/PNG/OCR). | `benchmarks/file_scanning/run_benchmark.py` |

Rule of thumb: **`bench/` scores the firewall's decisions** (the CI quality gate);
**`benchmarks/` scores file/attachment scanning** on a sample corpus.

## Tests
- `tests/` — core (`domestique/`) unit, integration, and eval tests.
- `app/tests/` — desktop/browser app tests (interceptor, MITM addon, server API).
