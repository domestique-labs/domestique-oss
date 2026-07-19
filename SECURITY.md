# Security Policy

Domestique is a security tool, so we take vulnerabilities in it seriously.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately through **[GitHub Private Vulnerability Reporting](https://github.com/domestique-labs/domestique-oss/security/advisories/new)** — or use the **Report a vulnerability** button under this repo's **Security** tab.

Please include: a description, affected version/commit, reproduction steps or PoC, and impact.
We aim to acknowledge within **3 business days** and to agree on a disclosure timeline with you.
Please give us reasonable time to fix before any public disclosure (coordinated disclosure).

## Scope
- The `domestique/` core engine, the API proxy (`domestique/app.py`), the browser MITM addon
  (`domestique_app/services/mitm_addon.py`), the dashboard API (`domestique_app/server/api.py`), and the CA/cert handling.
- Particularly interested in: detection bypasses (data that should be caught but isn't),
  fail-open conditions, CA/TLS interception weaknesses, and dashboard/API auth issues.

## Out of scope
- Findings that require a already-compromised host / root on the endpoint.
- The intentional fail-**closed** behavior (blocking on detector error is by design).
- Third-party dependencies (report those upstream), unless we ship an insecure default.

## Supported versions
Pre-1.0: only the latest `main` is supported. Fixes land on `main`.
