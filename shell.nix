# Dev environment for precursor-reticulum.
#
# Enter automatically with direnv (`.envrc` runs `use flake`), or by hand with
# `nix-shell`. Provides everything the build/flash/test scripts assume:
#
#   - rustup                                (the Rust multiplexer; see below)
#   - X11 + libusb on LD_LIBRARY_PATH       (minifb hosted GUI; pyusb flashing)
#   - the riscv32 cross-toolchain + openssl (EC firmware build)
#   - the project's Python venv on PATH     (RNS / LXMF / pyusb / precursorupdater)
#
# Rust comes via `rustup` rather than a fixed nixpkgs toolchain: the Xous target
# (`riscv32imac-unknown-xous-elf`) is a *custom* prebuilt sysroot that
# `cargo xtask install-toolkit` drops into the active rustup toolchain's
# writable `~/.rustup` tree — something it can't do to a read-only nix-store
# rustc. The toolchains rustup downloads are ordinary dynamically-linked
# binaries; they run on NixOS because nix-ld is configured system-wide.
{
  pkgs ? import <nixpkgs> { },
}:

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
    rustup
    pkg-config
    python3
    ecGcc
    riscvShims
  ];
  buildInputs =
    with pkgs;
    [
      openssl
      libusb1
    ]
    ++ runtimeLibs;

  shellHook = ''
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath runtimeLibs}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    if ! rustup show active-toolchain >/dev/null 2>&1; then
      echo "note: no rust toolchain yet — bootstrap with:" >&2
      echo "      rustup default stable" >&2
      echo "      rustup target add riscv32imac-unknown-none-elf" >&2
      echo "      (cd xous-core && cargo xtask install-toolkit --force)   # xous sysroot" >&2
    elif ! [ -d "$(rustc --print sysroot 2>/dev/null)/lib/rustlib/riscv32imac-unknown-xous-elf" ]; then
      echo "note: xous target sysroot not installed — run:" >&2
      echo "      (cd xous-core && cargo xtask install-toolkit --force)" >&2
    fi
    if [ -d "$PWD/.venv" ]; then
      export PATH="$PWD/.venv/bin:$PATH"
    elif [ -z "''${PR_VENV_HINT_SHOWN:-}" ]; then
      echo "note: no .venv yet — create it with:" >&2
      echo "      python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
      export PR_VENV_HINT_SHOWN=1
    fi
  '';
}
