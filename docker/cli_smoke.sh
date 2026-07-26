#!/usr/bin/env bash
# Clean-room CLI smoke for domestique. Runs INSIDE the container (see
# docker/Dockerfile.clitest). Exercises the surfaces that do not need macOS:
# the console entrypoint, the redaction demo, the portable dashboard, and the
# CLI wedge. Exits non-zero if any check fails.
set -uo pipefail

fail=0
pass() { printf '  \033[32m✅ %s\033[0m\n' "$1"; }
bad()  { printf '  \033[31m❌ %s\033[0m\n' "$1"; fail=1; }

# Wait until an HTTP endpoint answers (any status) or time out. $1=url $2=tries
wait_http() {
  local url="$1" tries="${2:-30}" code
  for _ in $(seq 1 "$tries"); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$url" 2>/dev/null || true)"
    [ -n "$code" ] && [ "$code" != "000" ] && return 0
    sleep 0.5
  done
  return 1
}

echo "== domestique clean-install CLI smoke =="
echo "python : $(python --version 2>&1)"
echo "home   : $HOME  (contents: $(ls -A "$HOME" 2>/dev/null | tr '\n' ' ')none)"
echo "package: $(python -c 'import domestique; print(domestique.__file__)' 2>&1)"
echo

# 1) console entrypoint resolves and reports a version
if ver="$(domestique --version 2>/dev/null)"; then
  pass "entrypoint: domestique --version -> ${ver}"
else
  bad "entrypoint: domestique --version failed"
fi

# 2) redaction demo (non-TTY -> canned before/after panel) actually redacts
demo_out="$(domestique demo </dev/null 2>&1)"
if grep -q 'AWS_ACCESS_KEY_REDACTED' <<<"$demo_out" \
   && grep -q 'US_SSN_REDACTED' <<<"$demo_out" \
   && grep -q 'EMAIL_ADDRESS_REDACTED' <<<"$demo_out"; then
  pass "demo: AWS key + SSN + email all redacted"
else
  bad "demo: expected redactions missing"
  sed 's/^/    | /' <<<"$demo_out"
fi

# 3) portable dashboard (the bundled domestique_app) boots + serves the API
python -m domestique_app --mode portable --no-browser >/tmp/dash.log 2>&1 &
dash_pid=$!
if wait_http "http://127.0.0.1:9876/api/status" 40; then
  pass "dashboard: portable app up on :9876 (/api/status answered)"
  curl -s --max-time 2 http://127.0.0.1:9876/api/status | head -c 240 | sed 's/^/    | /'; echo
else
  bad "dashboard: no response on :9876"
  sed 's/^/    | /' /tmp/dash.log
fi
kill "$dash_pid" 2>/dev/null; wait "$dash_pid" 2>/dev/null

# 4) CLI wedge boots + binds :8000
domestique start --no-setup --quiet >/tmp/wedge.log 2>&1 &
wedge_pid=$!
if wait_http "http://127.0.0.1:8000/" 30; then
  pass "wedge: redacting proxy started + bound :8000"
else
  bad "wedge: did not come up on :8000"
  sed 's/^/    | /' /tmp/wedge.log
fi
kill "$wedge_pid" 2>/dev/null; wait "$wedge_pid" 2>/dev/null

echo
if [ "$fail" -eq 0 ]; then
  printf '\033[32m== ALL CLI SMOKE CHECKS PASSED ==\033[0m\n'
else
  printf '\033[31m== SOME CHECKS FAILED ==\033[0m\n'
fi
exit "$fail"
