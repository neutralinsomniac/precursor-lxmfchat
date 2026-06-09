#!/usr/bin/env bash
# Build the lxmfchat Xous image for the Precursor.
#
# Default: produces the SIGNED kernel (xous.img) + loader (loader.bin) under
# xous-core/target/riscv32imac-unknown-xous-elf/release/, ready for scripts/flash.sh.
#
#   scripts/build.sh            # build the signed device image
#   scripts/build.sh check      # fast host-only compile check (no image, no signing)
#
# The shallow xous-core clone has no git tags, so image signing needs an explicit
# version + rev — baked in below (override with GIT_DESCRIBE / GIT_REV if the head
# moves). Compile-time app config is passed via the environment and picked up by
# `option_env!`; override any of these on the command line:
#   LXMF_PROPAGATION_NODE   32-hex lxmf.propagation dest hash (store-and-forward node)
#   LXMF_PROPAGATION_COST   PoW stamp cost in leading-zero bits (default 13)
#   LXMF_DEFAULT_HUB        default transport hub "host:port"
# e.g.  LXMF_PROPAGATION_NODE=<32hex> scripts/build.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/xous-core"

# Compiled-in app config (override via the environment; cargo rebuilds when an
# `option_env!`-read var changes).
export LXMF_PROPAGATION_NODE="${LXMF_PROPAGATION_NODE:-d0edc092aced9a60e050cef3df86b4f2}"
# LXMF_PROPAGATION_COST and LXMF_DEFAULT_HUB are inherited from the environment if set.

GIT_DESCRIBE="${GIT_DESCRIBE:-v0.9.8-792-g2005a801}"
GIT_REV="${GIT_REV:-2005a801c917753175d3826446ce1352c119e020}"

if [ "${1:-}" = "check" ]; then
  echo "host compile check (hosted-ci, no image)…"
  exec cargo xtask hosted-ci lxmfchat
fi

echo "building signed lxmfchat image (PN=${LXMF_PROPAGATION_NODE})…"
cargo xtask app-image lxmfchat --git-describe "$GIT_DESCRIBE" --git-rev "$GIT_REV"

REL="$ROOT/xous-core/target/riscv32imac-unknown-xous-elf/release"
echo
echo "built:"
echo "  $REL/xous.img"
echo "  $REL/loader.bin"
echo "flash with: scripts/flash.sh"
