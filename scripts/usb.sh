#!/usr/bin/env bash
# Generic wrapper around xous-core/tools/usb_update.py. Run from the repo's dev
# environment (direnv / nix-shell — see shell.nix), which provides libusb and the
# venv's python. All args are passed straight through.
#
# Examples:
#   scripts/usb.sh --config                              # print device descriptor/versions
#   scripts/usb.sh -w firmware/wf200_fw.bin              # WF200 firmware only
#   scripts/usb.sh -e firmware/ec_fw.bin -w firmware/wf200_fw.bin   # EC + WF200 (matched)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

exec python3 xous-core/tools/usb_update.py "$@"
