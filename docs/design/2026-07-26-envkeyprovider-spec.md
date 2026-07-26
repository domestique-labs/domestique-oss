# Spec — `EnvKeyProvider` (container-friendly vault key source)

**Date:** 2026-07-26
**Status:** Design (spec only — no implementation yet)
**Related:** `2026-07-26-distribution-strategy-design.md`

## Problem

The pinned vault encrypts `~/.domestique/vault.bin` with a 32-byte AES-256 key
held by a `KeyProvider`. The only provider today, `KeyringKeyProvider`, reads
that key from the OS keyring — which **does not exist in a container/server**
(`keyring` falls back to its `fail` backend). Today that fail-safes to
session-only redaction, which is fine for stateless agents, but a self-hosted /
team-gateway deployment that wants **stable tokens across restarts** needs a
persistent pinned vault.

The 12-factor pattern for servers is to inject the master key from the
orchestrator's secret manager (Docker/K8s secret, Vault, cloud KMS), **not** an
OS keychain. This spec adds a `KeyProvider` that does exactly that.

## Design

Add `EnvKeyProvider` to `domestique/vault/pinned.py`, implementing the existing
`KeyProvider` Protocol (`get_or_create_key() -> bytes | None`).

- **Source:** reads env var `DOMESTIQUE_VAULT_KEY`, a **base64-encoded 32-byte**
  key.
- **Validation:** decode base64 and require **exactly 32 bytes**. Anything else
  (unset, undecodable, wrong length) → return `None` (unavailable), log a
  warning, never raise. This mirrors `KeyringKeyProvider`'s
  "any failure = unavailable, never crash startup" behavior.
- **No creation / no persistence:** unlike `KeyringKeyProvider` (which mints and
  stores a key on first use), `EnvKeyProvider` **never generates or writes** a
  key — the environment is the single source of truth. If the env var is absent
  it is simply unavailable.

The AES-256-GCM `PinnedVault` path is **unchanged**: it still calls
`get_or_create_key()`, still encrypts `vault.bin` at rest. In a container the
encrypted `vault.bin` persists on a **mounted volume**; the key arrives via env
and never lands on disk.

### Provider selection

`build_default_token_service` (`domestique/vault/__init__.py`) chooses the
provider. Proposed logic, keeping the existing `pinned: bool` param:

1. If `DOMESTIQUE_VAULT_KEY_PROVIDER` is set, honor it explicitly:
   `env` → `EnvKeyProvider`, `keyring` → `KeyringKeyProvider`, `none` →
   no pinned vault (session-only).
2. Otherwise **auto-select**: if `DOMESTIQUE_VAULT_KEY` is set →
   `EnvKeyProvider`; else → `KeyringKeyProvider` (today's default).

The explicit `DOMESTIQUE_VAULT_KEY_PROVIDER` override is proposed for clarity
(e.g. forcing `none` in CI, or `keyring` on a desktop that also has the env set)
— include it, but keep it a thin dispatch; do not build a plugin registry.

## Error handling / fail-safe

Identical to today's keyring-unavailable path: any failure → provider returns
`None` → `PinnedVault` disables itself → **session-scoped redaction is
unaffected**. A missing or malformed `DOMESTIQUE_VAULT_KEY` must never crash
`domestique start` and must never weaken redaction — it only forgoes
*persistence*.

## Security notes

- Key is base64 of 32 random bytes. Generate with `openssl rand -base64 32`.
- **Never commit it.** Supply via a Docker secret / K8s Secret / Vault / KMS
  and expose as `DOMESTIQUE_VAULT_KEY` to the process.
- Rotating the key makes an existing `vault.bin` undecryptable — the vault
  fail-safes (treats entries as unreadable) rather than crashing; document that
  rotation resets the pinned vault.
- Absence of the key does **not** weaken the redaction axis; only the
  persistent pinned vault is affected.

## Cross-surface note

`build_default_token_service` is called only from `_cmd_start`
(`domestique/cli.py:236`) — the **CLI wedge / proxy**, i.e. the agentic path.
Browser mode does not build the default token service here, so it is
**unaffected** by this change. (Per the repo's shared-detector rule, this is a
vault-key-source change, not a detector/policy change, so no policy files are
touched.)

## Test plan

Unit tests in `tests/unit/vault/` (new `test_env_key_provider.py`, plus a case
in the existing `build_default_token_service` selection tests):

- **Valid key:** 32 random bytes, base64-encoded in `DOMESTIQUE_VAULT_KEY` →
  `get_or_create_key()` returns exactly those 32 bytes.
- **Wrong length:** base64 of 16 or 40 bytes → returns `None`, warns, no raise.
- **Garbage / undecodable:** `"not-base64!!"` → returns `None`, warns, no raise.
- **Unset:** env var absent → returns `None`, no raise.
- **Round-trip:** build a `PinnedVault` with an `EnvKeyProvider`, `pin()` a
  value, reload from the same `vault.bin` + same env key, assert the token and
  value recover (reuse the pattern in the existing pinned-vault tests, which
  already use a static in-memory key provider).
- **Selection:** `DOMESTIQUE_VAULT_KEY` set → `build_default_token_service`
  uses `EnvKeyProvider`; unset → `KeyringKeyProvider`;
  `DOMESTIQUE_VAULT_KEY_PROVIDER=none` → session-only (no pinned vault).

Tests must set/unset env within the test (monkeypatch) and not depend on a real
keyring or a real `~/.domestique`.

## Out of scope

- Direct KMS / HashiCorp Vault integration — env is the seam; a KMS/secret
  manager *populates* `DOMESTIQUE_VAULT_KEY`. No SDKs added here.
- Running a Secret Service daemon inside the container.
- Any change to `SessionStore` or the in-memory session redaction path.
- Key rotation tooling beyond documenting the reset behavior.
