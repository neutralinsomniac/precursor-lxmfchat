#!/usr/bin/env bash
# Run the LXMF chat app in Xous hosted mode on this machine.
#
# Hosted mode draws via `minifb`, which dlopens X11 libraries by bare soname
# (libX11.so.6, …). On NixOS those live in /nix/store and aren't on the default
# loader path, so we resolve their runtime (`out`) outputs with nix-build and
# put them on LD_LIBRARY_PATH. Requires a running X display (DISPLAY set).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "${DISPLAY:-}" ]; then
  echo "warning: \$DISPLAY is unset — minifb needs an X display to open a window." >&2
fi

echo "resolving X11 libraries via nix-build…" >&2
LIBS="$(nix-build --no-out-link '<nixpkgs>' \
  -A libx11 -A libxcursor -A libxrandr -A libxi -A libxkbcommon 2>/dev/null)"
X11_PATH="$(echo "$LIBS" | sed 's|$|/lib|' | paste -sd:)"
export LD_LIBRARY_PATH="${X11_PATH}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

cd "$ROOT/xous-core"
exec cargo xtask run "${@:-lxmfchat}"
