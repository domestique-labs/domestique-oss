# Distribution Strategy — Agentic-First (pipx + Docker)

**Date:** 2026-07-26
**Status:** Design (approved direction: "Approach A")
**Scope:** How the Community Edition is packaged and shipped. No code changes here.

## Goal

Drive OSS adoption **primarily for agentic workflows** — the CLI wedge
(`domestique start`), a local redacting proxy that AI agents point their
provider `base_url` at, so outbound prompts are scanned and redacted before
they leave the machine. The **browser firewall** (`domestique browser`) is a
secondary **showcase** — a way to *see* the firewall work in a normal web
browser — not the primary product.

Two audiences, two very different install stories:

- **Agentic / developer / self-host** — wants a proxy they can run anywhere,
  script, and pin. The value is the wire-level redaction, not a desktop UI.
- **Non-technical showcase user** — wants to watch their browser get
  protected. The value is the host-integrated experience.

## The channels

### pipx — primary channel

pipx is the natural fit for a host-integrated Python CLI app: it puts
`domestique` on `PATH` in an isolated environment, and `pipx inject` adds
optional extras. Critically, **pipx is the only channel that can deliver the
browser firewall**, because that feature integrates with the host OS
(generate + trust a CA in the host keychain, flip the host system proxy,
intercept the host browser via mitmproxy). This is also the invested path:
the release pipeline (#45) and cross-platform pipx detection (#52) already
target it, and `domestique browser` (#50) is a one-command launcher on top.

The documented quickstart is `pipx install domestique` → `domestique start`.
Note the package is **not yet published to PyPI**, so that command 404s today;
until a release is cut, install from a built wheel or `git+`. A brand-new user
must also bootstrap pipx itself (`brew install pipx` / `pip install --user
pipx`) — the quickstart docs should say so.

### Docker — the self-hosted proxy service + reproducible image

Docker ships the **CLI wedge as a self-hostable redacting-proxy service**
(drop it into a compose/k8s stack; route an app's or CI's LLM calls through
one container) plus a **reproducible image for the heavy ML detection tiers**
(Presidio / GLiNER / local-LLM) and for the eval harness. It is **explicitly
not the browser firewall.**

**Architectural constraint (why Docker can't do browser mode):** a container
cannot trust a CA in the host's trust store, cannot flip the host's system
proxy, and cannot intercept the host browser's traffic. So the Docker image
covers the CLI/proxy and the portable dashboard API only — never `domestique
browser`. Marketing Docker as "protect your browser" would be incorrect.

## Pros / cons

**pipx**
- Native fit for a host-integrated CLI; `domestique` on `PATH`, isolated from
  system Python; `pipx inject` for extras.
- Only channel that can deliver the browser firewall (the showcase).
- Already the invested path (#45 release, #52 detection, #50 launcher).
- Requires Python **and** pipx already present — a real bootstrap hurdle for
  non-technical users.
- Heavy ML extras are painful per-machine and drift across OSes; upgrades are
  user-driven.

**Docker**
- Reproducible, pinned, heavy-deps-baked-in — ideal for the ML tiers, CI, and
  the eval harness.
- Zero host Python; runs anywhere Docker does; clean uninstall, no host
  mutation; natural home for a team/self-hosted redacting gateway.
- **Cannot** ship the browser-protection experience (host keychain/proxy/
  browser) — strictly the CLI/proxy + dashboard API.
- Not for non-technical desktop users; networking friction (clients must be
  pointed at the container); ML tiers bloat the image and Ollama/GPU
  passthrough is fiddly.
- A second release artifact → drift risk.

## Secure-storage (vault) story per channel

The reversible-redaction vault stores value↔token mappings behind numbered
tokens (`[SSN_1]`). The **pinned vault** persists user-confirmed values to
`~/.domestique/vault.bin`, AES-256-GCM encrypted; the 32-byte key lives in a
`KeyProvider` — today `KeyringKeyProvider`, backed by the OS keyring
(Keychain / DPAPI / Secret Service). The OS keychain holds **only the key**;
the vault data is encrypted at rest.

- **pipx (host):** OS keychain is available → full persistent pinned vault.
- **Docker (container):** there is **no OS keychain** — `keyring` resolves to
  its `fail` backend. The vault **fail-safes**: `build_default_token_service`
  logs `vault_keyring_unavailable` and continues; the pinned vault disables
  itself while **session-scoped reversible redaction is unaffected**. That
  session path — mint `[SSN_1]` on egress, detokenize the response within the
  same request, all in-memory — is exactly what a **stateless agentic proxy**
  needs and requires no keychain. The only thing lost in a container is the
  *persistent* pinned vault, which is a desktop convenience (stable/"pinned"
  tokens across restarts), not core to agentic use.

Verified empirically against `main` (`1432a64`): in a clean `python:3.12-slim`
container, `keyring` is `keyring.backends.fail.Keyring`, `set_password` raises
`NoKeyringError`, `build_default_token_service()` builds without crashing, and
in-memory tokenize/detokenize round-trips correctly.

## Recommendation

1. **pipx is primary**; it carries the desktop + browser showcase.
2. **Docker default image = lean and session-only** (wedge + portable
   dashboard, zero config). This is the correct, working default for agents.
3. Offer **opt-in heavier variants** for the ML detection tiers rather than one
   giant image (mirrors the extras: `[pii]`, `[ner]`, `[local-llm]`).
4. Add persistent vault storage in containers **only when** the self-hosted /
   team-gateway story needs stable tokens across restarts — via an
   `EnvKeyProvider` that injects the master key from the orchestrator's secret
   manager (Docker/K8s secret, Vault, cloud KMS). Do **not** try to give a
   container the OS keychain. See the companion spec:
   `2026-07-26-envkeyprovider-spec.md`.

## Maintenance

Both channels already have clean-install smoke coverage — cross-OS pipx smoke
(#45) and the Docker CLI smoke harness (`docker/Dockerfile.clitest`, #55). Wire
both into CI so the two release artifacts can't silently drift. The Docker CLI
harness is the validated clean-install proof: it builds the wheel from source,
installs **only the wheel** into a pristine image, and smokes the entrypoint,
demo, portable dashboard, and wedge.

## Out of scope

- Native installers (`.pkg` / `.msi`) for non-technical desktop users. This is
  the real gap pipx leaves (Python + pipx bootstrap), worth a later decision,
  but not part of Approach A.
- Cutting the first PyPI release (separate release task; blocks the literal
  `pipx install domestique` quickstart).
