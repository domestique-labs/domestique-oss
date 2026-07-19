# Releasing `domestique`

Publishing is automated by [`.github/workflows/release.yml`](.github/workflows/release.yml).
It builds, proves the artifact installs via `pipx` on Linux/macOS/Windows, publishes to
PyPI with **Trusted Publishing** (OIDC — no stored token), and then re-proves the
published `pipx install domestique` on all three OSes.

## One-time setup (already done — recorded here for the record / re-setup)

1. **Own the name on PyPI.** The distribution name is `domestique` (users run
   `pipx install domestique`). Register/claim it on <https://pypi.org>.

2. **Register the Trusted Publisher** on the PyPI project → *Publishing* →
   *Add a new publisher* (GitHub Actions). Values must match the workflow exactly:
   - Owner: `domestique-labs`
   - Repository: `domestique-oss`
   - Workflow filename: `release.yml`
   - Environment: `pypi`

3. **Create the `pypi` GitHub environment** (repo → Settings → Environments):
   - **Required reviewers:** yourself → every publish waits for a manual approval click.
   - **Deployment branches and tags:** *Selected branches and tags* → add a **tag**
     rule `v*` (no branch rule). Blocks any non-tag ref from reaching the publish step.

## Cutting a release

1. **Bump the version.** Edit `version` in `pyproject.toml` (e.g. `0.1.0` → `0.2.0`).
   The workflow hard-fails if the tag and this value disagree, so they must match.
2. Commit (signed off — DCO): `git commit -s -m "release: v0.2.0"` and merge to `main`.
3. **Publish a GitHub Release** with tag `v0.2.0` (tag == pyproject version, `v`-prefixed).
   Publishing the release is what triggers the workflow.
4. **Approve the `publish` job** when the environment gate prompts you.
5. Watch `smoke-pypi` go green → `pipx install domestique==0.2.0` works for everyone.

## If something goes wrong

- **`build` fails on the version guard** — the tag and `pyproject.toml` version differ.
  Fix `pyproject.toml` (or delete/recreate the tag) and re-publish the release.
- **`smoke-artifact` fails** — the wheel is broken *before* anything is public. Fix and
  re-release; PyPI was never touched.
- **`smoke-pypi` fails after publish** — the release is already public. `pipx`/import
  broke post-publish (rare). Yank the bad version on PyPI and ship a patch release.

## What the smoke tests deliberately do NOT cover

The `pipx` smokes install **bare `domestique`** (no extras) and run only
`domestique --help` + `domestique demo`. That is intentional: the Tier-3 local-LLM
path needs the **Ollama daemon + model weights**, which are a runtime system
dependency, never a pip/pipx install. Tier-3 logic is covered by mocked-HTTP contract
tests in `tests/`, not here.
