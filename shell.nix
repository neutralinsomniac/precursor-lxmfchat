# Dev environment for precursor-reticulum.
#
# Enter automatically with direnv (`.envrc` runs `use nix`), or by hand with
# `nix-shell`. Provides everything the build/flash/test scripts assume:
#
#   - X11 + libusb on LD_LIBRARY_PATH      (minifb hosted GUI; pyusb flashing)
#   - the riscv32 cross-toolchain + openssl (EC firmware build)
#   - the project's Python venv on PATH     (RNS / LXMF / pyusb / precursorupdater)
#
# Rust is intentionally NOT provided here — it stays on rustup, which owns the
# Xous targets (`rustup target add riscv32imac-unknown-xous-elf`, etc.).
{ pkgs ? import <nixpkgs> { } }:

let
  # The EC build's build.rs invokes the toolchain as `riscv-none-elf-*`, but
  # nixpkgs ships it as `riscv32-none-elf-*`. Provide renamed wrappers.
  ecGcc = pkgs.pkgsCross.riscv32-embedded.buildPackages.gcc;
  riscvShims = pkgs.runCommand "riscv-none-elf-shims" { } ''
    mkdir -p $out/bin
    for t in gcc ar as ld objcopy objdump; do
      printf '#!/bin/sh\nexec riscv32-none-elf-%s "$@"\n' "$t" > $out/bin/riscv-none-elf-$t
      chmod +x $out/bin/riscv-none-elf-$t
    done
  '';

  # Libraries dlopen'd by soname at runtime (not linked at build time), so they
  # must be on LD_LIBRARY_PATH: minifb (hosted GUI) pulls in X11; pyusb pulls in
  # libusb; pip-installed wheels (cryptography) want libstdc++.
  runtimeLibs = with pkgs; [
    libx11
    libxcursor
    libxrandr
    libxi
    libxkbcommon
    libusb1
    stdenv.cc.cc.lib
  ];
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    pkg-config
    python3
    ecGcc
    riscvShims
  ];
  buildInputs = with pkgs; [ openssl libusb1 ] ++ runtimeLibs;

  shellHook = ''
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath runtimeLibs}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    # Put the project's RNS/LXMF/pyusb venv on PATH if it's been created (see
    # `requirements.txt`); the build/flash/test scripts just call `python3`.
    if [ -d "$PWD/.venv" ]; then
      export PATH="$PWD/.venv/bin:$PATH"
    elif [ -z "''${PR_VENV_HINT_SHOWN:-}" ]; then
      echo "note: no .venv yet — create it with:" >&2
      echo "      python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
      export PR_VENV_HINT_SHOWN=1
    fi
  '';
}
