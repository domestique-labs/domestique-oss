# Repository Guidelines

## Project Structure & Module Organization

Domestique is a Python 3.11 project. Core proxy code lives in `domestique/`: `app.py` builds the FastAPI app, `config.py` loads settings, `models.py` defines shared objects, and subpackages cover detectors, policy, transport, and audit logging. The desktop/menu-bar app lives in `domestique_app/`, with services in `domestique_app/services/`, routes in `domestique_app/server/`, native macOS code in `domestique_app/native/`, and UI assets in `domestique_app/assets/`. Tests are split between `tests/` and `domestique_app/tests/`. Benchmarks are in `bench/` and `benchmarks/`, deployment assets in `infra/`, and docs in `docs/`.

## Build, Test, and Development Commands

- `cp .env.example .env`: create local configuration and add provider keys.
- `docker compose up`: run the proxy stack locally; the README documents the proxy on `:8000`.
- `curl localhost:8000/health`: verify the running service health endpoint.
- `python -m domestique_app --help`: check the desktop app entry point.
- `python -m pytest tests`: run the default pytest suite configured in `pyproject.toml`.
- `python -m pytest domestique_app/tests`: run desktop/app service tests when changing `domestique_app/`.
- `python -m ruff check .`: lint imports, style, security, and modernization rules.
- `python -m mypy domestique domestique_app`: run strict type checks.

Install development dependencies with `python -m pip install -e ".[dev]"`. Optional extras include `.[pii]`, `.[semantic]`, `.[local-llm]`, and `.[all]`.

## Coding Style & Naming Conventions

Use four-space indentation, type hints, and Python 3.11 features. Ruff uses 99-character lines and checks style, imports, annotations, security, bugbear, naming, and modernization rules. Prefer `snake_case` for modules, functions, and variables; `PascalCase` for classes and Pydantic models; and service names that match their file, such as `domestique_app/services/redaction.py`.

## Testing Guidelines

Use pytest with `pytest-asyncio`; async tests are auto-detected. Name test files `test_*.py` and keep focused unit tests near the affected package area. Add integration coverage in `tests/integration/` for cross-module behavior. Run `domestique_app/tests/` when changing menu-bar services, routes, or local configuration.

## Commit & Pull Request Guidelines

Current history is minimal (`init`), so use concise, imperative subjects such as `add detector registry tests` or `fix redaction audit event`. Pull requests should describe the behavior change, list tests run, link issues, and include screenshots or recordings for UI changes in `domestique_app/assets/dashboard.html` or native flows.

## Security & Configuration Tips

Never commit real provider keys or generated certificates. Keep local secrets in `.env`, update `.env.example` when adding required settings, and review changes to `domestique/policy/browser-rules.yaml`, `infra/certs/`, and `infra/dns/` carefully because they affect enforcement and deployment behavior.
