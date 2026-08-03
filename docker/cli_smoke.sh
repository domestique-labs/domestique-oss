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
# Proves only that something is listening -- a 500 counts. Use wait_http_ok
# when the check is meant to assert the service actually works.
wait_http() {
  local url="$1" tries="${2:-30}" code
  for _ in $(seq 1 "$tries"); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$url" 2>/dev/null || true)"
    [ -n "$code" ] && [ "$code" != "000" ] && return 0
    sleep 0.5
  done
  return 1
}

# Wait for an endpoint to answer 200 specifically. $1=url $2=tries
wait_http_ok() {
  local url="$1" tries="${2:-30}" code
  for _ in $(seq 1 "$tries"); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$url" 2>/dev/null || true)"
    [ "$code" = "200" ] && return 0
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
# Tokens are the numbered taxonomy form ([AWSKEY_1]), not the pre-0.1.0
# [AWS_ACCESS_KEY_REDACTED] spelling -- see domestique/taxonomy.py CANONICAL.
demo_out="$(domestique demo </dev/null 2>&1)"
demo_after="$(sed -n '/AFTER/,$p' <<<"$demo_out")"
if grep -q 'AWSKEY_1' <<<"$demo_out" \
   && grep -q 'SSN_1' <<<"$demo_out" \
   && grep -q 'EMAIL_1' <<<"$demo_out"; then
  # Tokens being present is not the assertion that matters; the secret being
  # GONE from what would be sent upstream is.
  if grep -q 'AKIAIOSFODNN7EXAMPLE' <<<"$demo_after"; then
    bad "demo: tokens minted but the AWS key survived into the AFTER text"
    sed 's/^/    | /' <<<"$demo_after"
  else
    pass "demo: AWS key + SSN + email all redacted, secret absent from AFTER"
  fi
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
# / is not a route (app.py serves /health and the provider front doors), so it
# answers 500 -- probing it proved only that a socket was bound. Assert /health
# returns 200 instead.
if wait_http_ok "http://127.0.0.1:8000/health" 30; then
  pass "wedge: redacting proxy up on :8000 (/health 200)"
else
  bad "wedge: did not come up healthy on :8000"
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
