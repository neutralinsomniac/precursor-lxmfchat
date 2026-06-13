#!/usr/bin/env bash
# Run the LXMF chat app in Xous hosted mode on this machine.
#
# Hosted mode draws via `minifb`, which dlopens X11 libraries by bare soname
# (libX11.so.6, …). Run from the repo's dev environment (direnv / nix-shell — see
# shell.nix), which puts those on LD_LIBRARY_PATH. Requires a running X display.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "${DISPLAY:-}" ]; then
  echo "warning: \$DISPLAY is unset — minifb needs an X display to open a window." >&2
fi

cd "$ROOT/xous-core"
exec cargo xtask run "${@:-lxmfchat}"
