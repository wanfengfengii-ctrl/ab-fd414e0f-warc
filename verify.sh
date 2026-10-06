#!/bin/sh
# One-shot verification gate used by the `verify` Compose service.
#
#   1. unit tests (strict parser + audit logic)
#   2. build/syntax check (compileall)
#   3. API smoke: valid package, bad digest, bad reference
#
# Reports via exit code and exits on its own.
set -eu

PORT="${PORT:-8080}"
cd "$(dirname "$0")"

echo "== [1/3] unit tests =="
python3 -m unittest discover -s tests -v

echo "== [2/3] build check (compileall) =="
python3 -m compileall -q app tests

echo "== [3/3] API smoke =="
SERVER_PID=""
trap 'if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi' EXIT INT TERM

if [ -z "${AUDIT_URL:-}" ]; then
    # Local (non-Compose) run: serve the API in this container ourselves.
    BASE_URL="http://127.0.0.1:${PORT}"
    PORT="$PORT" python3 -m app.server &
    SERVER_PID=$!
else
    # Compose: the api service has already passed its healthcheck.
    BASE_URL="$AUDIT_URL"
fi

ready=0
i=0
while [ "$i" -lt 50 ]; do
    if python3 - "$BASE_URL" <<'PY'
import sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1] + "/healthz", timeout=1) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
PY
    then
        ready=1
        break
    fi
    i=$((i + 1))
    sleep 0.2
done

if [ "$ready" -ne 1 ]; then
    echo "server did not become ready" >&2
    exit 1
fi

AUDIT_URL="$BASE_URL" python3 tests/smoke_api.py

echo "== ALL CHECKS PASSED =="
