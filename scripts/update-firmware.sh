#!/usr/bin/env bash
# Full official Precursor firmware update via precursorupdater: brings the SoC
# gateware + EC firmware + WF200 firmware + stock kernel/loader to the latest
# matched release. Run from the repo's dev environment (direnv / nix-shell — see
# shell.nix), which provides libusb and the venv's precursorupdater.
#
# This OVERWRITES the kernel/loader with stock Xous — reflash the lxmfchat app
# afterwards (scripts/flash.sh, rebuilt against the new SoC if needed).
#
# Args pass through to precursorupdater, e.g.:
#   scripts/update-firmware.sh --dry-run        # show what it would do, flash nothing
#   scripts/update-firmware.sh                  # latest STABLE release (recommended)
#   scripts/update-firmware.sh -b               # bleeding-edge CI build
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

exec python3 -m precursorupdater "$@"
