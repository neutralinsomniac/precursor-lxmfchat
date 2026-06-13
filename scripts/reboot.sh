#!/usr/bin/env bash
# Reboot a connected Precursor over USB without flashing (halt -> unhalt). Run
# from the repo's dev environment (direnv / nix-shell — see shell.nix).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$ROOT/scripts/reboot.py"
