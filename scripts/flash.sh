#!/usr/bin/env bash
# Flash the freshly-built Xous kernel (with the lxmfchat app) to a Precursor over
# USB.
#
# lxmfchat is an in-tree app baked into the kernel image (xous.img, ~7.4MB), so an
# app change means reflashing the whole kernel. The loader (loader.bin, ~1.3MB)
# only changes when the bootloader code does — NOT between app builds — and the
# device already has a compatible one, so by default we flash the KERNEL ONLY and
# skip the loader (saves the loader's ~1.3MB write + sign/verify each time).
# Set FLASH_LOADER=1 to also flash the loader (needed the first time, or after a
# loader/bootloader change).
#
# pyusb needs a libusb backend; on NixOS libusb-1.0.so isn't on the default loader
# path, so we resolve it via nix-build and put it on LD_LIBRARY_PATH. USB access
# usually needs root: if you get a permission/access error, re-run as
# `sudo scripts/flash.sh` (this script re-sets the lib path internally, so sudo
# stripping the environment is fine).
#
# Extra args are passed through to usb_update.py (e.g. --force, --erase-pddb).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

REL="xous-core/target/riscv32imac-unknown-xous-elf/release"
KERNEL="$REL/xous.img"
LOADER="$REL/loader.bin"
[ -f "$KERNEL" ] || { echo "missing $KERNEL — build with 'cargo xtask app-image lxmfchat …' first" >&2; exit 1; }

LIBUSB="$(nix-build --no-out-link '<nixpkgs>' -A libusb1 2>/dev/null)/lib"
export LD_LIBRARY_PATH="${LIBUSB}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

LOADER_ARGS=()
if [ "${FLASH_LOADER:-0}" = "1" ]; then
  LOADER_ARGS=(-l "$LOADER")
  echo "flashing kernel + loader"
else
  echo "flashing kernel only (set FLASH_LOADER=1 to also flash the loader)"
fi

PY="$ROOT/.venv/bin/python3"
exec "$PY" xous-core/tools/usb_update.py -k "$KERNEL" "${LOADER_ARGS[@]}" "$@"
