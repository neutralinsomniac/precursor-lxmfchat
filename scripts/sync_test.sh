#!/usr/bin/env bash
# Validate the propagation-node message sync against a REAL RNS node.
#
# Starts scripts/sync_node.py (a real-RNS LXMF propagation node that serves one
# test message as a multi-part Resource), runs the host-client `sync` mode against
# it, and checks the client downloaded + decrypted + parsed the message via the
# Resource path. Exercises link.identify, the /get request/response exchange, and
# the RNS Resource receiver on the wire.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LOG=/tmp/sync_node.log
PY="python3"
HC="$ROOT/host-client/target/debug/reticulum-host-client"

[ -x "$HC" ] || { echo "build host-client first: (cd host-client && cargo build)"; exit 1; }

rm -f "$LOG"
"$PY" -u scripts/sync_node.py > "$LOG" 2>&1 &
NODE=$!
trap 'kill "$NODE" 2>/dev/null' EXIT
sleep 8
PROP=$(grep "propagation dest:" "$LOG" | awk '{print $3}')
[ -n "$PROP" ] || { echo "node failed to start:"; cat "$LOG"; exit 1; }
echo "propagation node: $PROP"

OUT=$(timeout 40 "$HC" sync 127.0.0.1:4250 "$PROP" 32 2>&1 | grep -vE "^\[|announce:")
echo "$OUT" | grep -vE "SYNCED MSG"   # show the exchange without the huge content line

if echo "$OUT" | grep -q "receiving resource" && echo "$OUT" | grep -q ">>> SYNCED MSG"; then
  echo "PASS: synced a message via the RNS Resource path"
  exit 0
else
  echo "FAIL: did not sync via Resource"
  exit 1
fi
