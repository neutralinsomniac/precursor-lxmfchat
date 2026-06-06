#!/usr/bin/env bash
# Full official Precursor firmware update via precursorupdater: brings the SoC
# gateware + EC firmware + WF200 firmware + stock kernel/loader to the latest
# matched release. Wires up the libusb backend on LD_LIBRARY_PATH (NixOS).
#
# This OVERWRITES the kernel/loader with stock Xous — reflash the lxmfchat app
# afterwards (scripts/flash.sh, rebuilt against the new SoC if needed).
#
# Args pass through to precursorupdater, e.g.:
#   scripts/update-firmware.sh --dry-run        # show what it would do, flash nothing
#   scripts/update-firmware.sh                  # latest STABLE release (recommended)
#   scripts/update-firmware.sh -b               # bleeding-edge CI build
#
# USB needs root: run as `sudo scripts/update-firmware.sh …` (the script re-sets
# the lib path internally, so sudo dropping the env is fine).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LIBUSB="$(nix-build --no-out-link '<nixpkgs>' -A libusb1 2>/dev/null)/lib"
export LD_LIBRARY_PATH="${LIBUSB}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

exec "$ROOT/.venv/bin/python3" -m precursorupdater "$@"
