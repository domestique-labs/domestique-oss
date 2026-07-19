# Contributing to Domestique

Thanks for helping build a local-first firewall for AI traffic. This is the Community
Edition — free and open under [Apache-2.0](./LICENSE). Contributions are welcome.

## Ground rules
- Be excellent to each other — see [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).
- Found a **security issue**? Do **not** open a public issue — see [`SECURITY.md`](./SECURITY.md).
- By contributing you agree your work is licensed under this repo's Apache-2.0 license, and you
  certify the [Developer Certificate of Origin](https://developercertificate.org/) by
  **signing off** your commits (`git commit -s`).

## Dev setup
```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"         # core + test/lint tooling
# optional detection extras:
pip install -e ".[pii,ner,browser-proxy]"
```
Run the domestique_app/tests from the **repo root** (the package is used in-tree):
```bash
python -m domestique_app                   # dashboard at http://127.0.0.1:9876/
pytest                          # test suite
```

## Standards (what CI checks)
| Check | Command | Status |
|---|---|---|
| Tests | `pytest` | **blocking** — keep it green |
| Lint | `ruff check domestique domestique_app` | informational (being burned down) |
| Format | `ruff format domestique domestique_app` | informational |
| Types | `mypy domestique` | informational (strict) |

- Target **Python 3.11+**. Config lives in `pyproject.toml` (`[tool.ruff]`, `[tool.mypy]`).
- New code should pass `ruff` and `ruff format` and add tests. We're moving lint/types toward
  blocking — don't add new violations.
- Detectors implement the `Detector` protocol: `async scan(text) -> list[Detection]`,
  stateless after construction (safe to share across concurrent requests).

## Pull requests
1. Branch from `main`; keep PRs focused.
2. `pytest` passes; new behavior has tests; run `ruff format domestique domestique_app` on touched code.
3. Sign off commits (`-s`), fill in the PR template, and link any related issue.
4. A maintainer reviews. Be patient and responsive to feedback.

## Reporting bugs / requesting features
Use the issue templates (Bug report / Feature request). Include repro steps, expected vs actual,
and platform (macOS is the fully-validated platform; Windows/Linux paths exist but are less tested).
