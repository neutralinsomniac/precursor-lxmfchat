#!/usr/bin/env bash
# Generic wrapper around xous-core/tools/usb_update.py with the libusb backend
# wired onto LD_LIBRARY_PATH (NixOS). All args are passed straight through.
#
# Examples:
#   scripts/usb.sh --config                              # print device descriptor/versions
#   scripts/usb.sh -w firmware/wf200_fw.bin              # WF200 firmware only
#   scripts/usb.sh -e firmware/ec_fw.bin -w firmware/wf200_fw.bin   # EC + WF200 (matched)
#
# USB access usually needs root: re-run as `sudo scripts/usb.sh …` (this script
# re-sets the lib path internally, so sudo dropping the env is fine).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LIBUSB="$(nix-build --no-out-link '<nixpkgs>' -A libusb1 2>/dev/null)/lib"
export LD_LIBRARY_PATH="${LIBUSB}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

exec "$ROOT/.venv/bin/python3" xous-core/tools/usb_update.py "$@"
