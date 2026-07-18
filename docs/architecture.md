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

## Benchmarks & evaluation

All benchmark and evaluation suites live under a single top-level `benchmarks/`,
split into subpackages by what they measure:

| Subpackage | Purpose | Entry point |
|---|---|---|
| `benchmarks/eval/` | **Deterministic detection-quality gate** — labeled corpus, bypass/FP/F1/latency metrics, baseline comparison + PR scorecard. This is the CI quality gate. | `python -m benchmarks.eval` |
| `benchmarks/datasets/` | **Detection-accuracy sweeps** over custom + public corpora (hand-crafted cases + public HuggingFace datasets). | `python -m benchmarks.datasets.evaluate` |
| `benchmarks/browser_perf/` | **Browser-mode latency micro-benchmark** — response-streaming overhead. | `python -m benchmarks.browser_perf.bench_response_streaming` |
| `benchmarks/file_scanning/` | **File-scanning benchmark** — detection over documents/images (PDF/CSV/PNG/OCR). | `python -m benchmarks.file_scanning.run_benchmark` |

Rule of thumb: `eval/` and `datasets/` **score the firewall's decisions** (accuracy);
`browser_perf/` scores **latency**; `file_scanning/` scores **file/attachment scanning**.
`benchmarks/eval/mock_upstream.py` also provides the mock upstream server the core
test suite imports.

## Tests
- `tests/` — core (`domestique/`) unit, integration, and eval tests.
- `app/tests/` — desktop/browser app tests (interceptor, MITM addon, server API).
