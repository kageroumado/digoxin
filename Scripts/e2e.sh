#!/bin/sh
# Builds the Go service, runs it on random loopback ports with an app called
# e2e, and runs the Swift end-to-end test against it.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
build=${DIGOXIN_BUILD:-$repo/.build/e2e}
work=$(mktemp -d "${TMPDIR:-/tmp}/digoxin-e2e.XXXXXX")
mkdir -p "$build"

(cd "$repo/server" && go build -o "$build/digoxin" ./cmd/digoxin)
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
port=$(free_port)
admin=$(free_port)
cat > "$work/apps.json" <<JSON
{"apps": {"e2e": {
  "app_attest_id": "TEAMID1234.com.example.e2e",
  "properties": {"chromiumInstalled": "bool"},
  "crash_context": {"engines": "string"}
}}}
JSON
"$build/digoxin" serve -config "$work/apps.json" -data "$work/data" -addr "127.0.0.1:$port" -admin-addr "127.0.0.1:$admin" 2> "$work/server.log" &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do
  curl -fs "http://127.0.0.1:$port/healthz" > /dev/null && break
  sleep 0.3
done

status=0
DIGOXIN_E2E_URL="http://127.0.0.1:$port" DIGOXIN_E2E_ADMIN="http://127.0.0.1:$admin" \
  swift test --package-path "$repo" --scratch-path "$build/.build" --filter EndToEndTests || status=$?
echo "--- server log"
cat "$work/server.log"
exit $status
