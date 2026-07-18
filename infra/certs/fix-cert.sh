#!/bin/bash
# Generate and trust the Domestique local CA on Linux.
#
# The CA is normally created only when the proxy first starts, and the app has
# no Linux trust implementation at all. This script generates the CA (if
# missing) and adds it to the system trust store so intercepted HTTPS traffic
# does not raise certificate errors. It also tries to add it to the per-user
# NSS database that Firefox/Chrome use.
#
# Run it from the project root:
#     ./infra/certs/fix-cert.sh
#
# Installing into the system trust store requires sudo.

set -euo pipefail

# This script lives in infra/certs/; the project root (where the `domestique_app` package
# and .venv live) is two levels up.
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# The `domestique_app` package lives in the project root and is not pip-installed.
export PYTHONUTF8=1
export PYTHONPATH="$ROOT"

# Prefer the project venv; fall back to python3 on PATH.
if [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PY="python3"
else
  echo "Python not found. Run 'python3 scripts/install.py' first." >&2
  exit 1
fi

CA_PEM="$HOME/.domestique/ca/domestique-ca.pem"

echo "Generating the Domestique CA (if missing) ..."
"$PY" - <<'PY'
from domestique_app.services.interceptor import generate_ca
cert, _key = generate_ca()
print("CA file:", cert)
PY

if [ ! -f "$CA_PEM" ]; then
  echo "CA was not generated at $CA_PEM" >&2
  exit 1
fi

# --- System trust store (needs sudo) ----------------------------------------
echo "Installing CA into the system trust store (sudo required) ..."
if command -v update-ca-trust >/dev/null 2>&1; then
  # RHEL / Fedora / CentOS / SUSE
  sudo cp "$CA_PEM" /etc/pki/ca-trust/source/anchors/domestique-ca.pem
  sudo update-ca-trust
  echo "Trusted via update-ca-trust."
elif command -v update-ca-certificates >/dev/null 2>&1; then
  # Debian / Ubuntu (the file must end in .crt)
  sudo cp "$CA_PEM" /usr/local/share/ca-certificates/domestique-ca.crt
  sudo update-ca-certificates
  echo "Trusted via update-ca-certificates."
elif command -v trust >/dev/null 2>&1; then
  # Arch and other p11-kit based distros
  sudo trust anchor --store "$CA_PEM"
  echo "Trusted via p11-kit (trust anchor)."
else
  echo "Could not find update-ca-trust, update-ca-certificates, or trust." >&2
  echo "Add $CA_PEM to your distribution's trust store manually." >&2
  exit 1
fi

# --- Browser NSS store (best effort) ----------------------------------------
# Linux browsers use their own NSS database, not the system trust store.
if command -v certutil >/dev/null 2>&1; then
  NSSDB="$HOME/.pki/nssdb"
  if [ -d "$NSSDB" ]; then
    if certutil -A -n "Domestique Local CA" -t "C,," -i "$CA_PEM" -d "sql:$NSSDB"; then
      echo "Added to the browser NSS store ($NSSDB)."
    else
      echo "Note: failed to add to the NSS store; import $CA_PEM in your browser manually." >&2
    fi
  else
    echo "Note: no NSS DB at $NSSDB. If browsers still warn, import $CA_PEM manually."
  fi
else
  echo "Note: 'certutil' (libnss3-tools) not found; browsers may need a manual import of $CA_PEM."
fi

echo ""
echo "Done. The system now trusts the Domestique CA, so intercepted HTTPS won't raise cert errors."
echo "If a browser still warns, restart it (or import $CA_PEM in its certificate settings)."
