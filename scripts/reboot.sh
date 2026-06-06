#!/usr/bin/env bash
# Reboot a connected Precursor over USB without flashing (halt -> unhalt). Sets the
# libusb backend path on NixOS, like scripts/flash.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIBUSB="$(nix-build --no-out-link '<nixpkgs>' -A libusb1 2>/dev/null)/lib"
export LD_LIBRARY_PATH="${LIBUSB}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$ROOT/.venv/bin/python3" "$ROOT/scripts/reboot.py"
