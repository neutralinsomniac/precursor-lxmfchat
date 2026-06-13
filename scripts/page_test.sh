#!/usr/bin/env bash
# Validate the NomadNet page-browser protocol path against a REAL RNS node.
#
# Starts scripts/page_node.py (a real-RNS nomadnetwork.node destination serving
# micron pages), runs the host-client `fetch` mode against it, and checks:
#  - a small page arrives as a RESPONSE packet, parses, and yields links
#  - a large page arrives via the RNS Resource path and parses
# Exercises the anonymous (no-identify) request, the msgpack request encoding,
# and response-as-Resource handling on the wire.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LOG=/tmp/page_node.log
PY="python3"
HC="$ROOT/host-client/target/debug/reticulum-host-client"

[ -x "$HC" ] || { echo "build host-client first: (cd host-client && cargo build)"; exit 1; }

rm -f "$LOG"
"$PY" -u scripts/page_node.py > "$LOG" 2>&1 &
NODE=$!
trap 'kill "$NODE" 2>/dev/null' EXIT
sleep 8
NODEHASH=$(grep "node dest:" "$LOG" | awk '{print $3}')
[ -n "$NODEHASH" ] || { echo "node failed to start:"; cat "$LOG"; exit 1; }
echo "page node: $NODEHASH"

echo "--- fetch /page/index.mu (small: RESPONSE packet) ---"
SMALL=$(timeout 40 "$HC" fetch 127.0.0.1:4251 "$NODEHASH" /page/index.mu 30 2>&1 | grep -vE "^\[")
echo "$SMALL"
echo "--- fetch /page/big.mu (large: Resource path) ---"
BIG=$(timeout 60 "$HC" fetch 127.0.0.1:4251 "$NODEHASH" /page/big.mu 45 2>&1 | grep -vE "^\[|^\[reg|^\[bold")
echo "$BIG" | grep -E "receiving resource|PAGE OK|error|rejected|failed" || true

FAIL=0
echo "$SMALL" | grep -q ">>> PAGE OK" || { echo "FAIL: small page did not parse"; FAIL=1; }
echo "$SMALL" | grep -q 'link\[0\] "Other page"' || { echo "FAIL: links not extracted"; FAIL=1; }
echo "$SMALL" | grep -q "receiving resource" && { echo "FAIL: small page unexpectedly used Resource"; FAIL=1; }
echo "$BIG" | grep -q "receiving resource response" || { echo "FAIL: big page did not use the Resource path"; FAIL=1; }
echo "$BIG" | grep -q ">>> PAGE OK" || { echo "FAIL: big page did not parse"; FAIL=1; }

if [ "$FAIL" = 0 ]; then
  echo "PASS: page fetch works (RESPONSE packet + Resource path, anonymous request)"
  exit 0
else
  exit 1
fi
