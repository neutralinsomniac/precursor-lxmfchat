# Precursor Reticulum — an LXMF messaging client for Xous

A [Reticulum](https://reticulum.network/) **LXMF** messaging client for the
[Precursor](https://www.crowdsupply.com/sutajio-kosagi/precursor) device, which
runs the [Xous](https://betrusted.io/xous-book/) microkernel.

The client connects to the wider Reticulum network as a **leaf node** over a
single `TCPClientInterface` to a transport hub, so it does not need to perform
routing itself. It can announce its address, discover peers, and exchange
end-to-end-encrypted, signed LXMF messages.

## Repository layout

```
xous-core/                         # vendored betrusted-io/xous-core (the OS)
├─ libs/reticulum-core/            # sans-IO Reticulum subset (no I/O, no Xous deps)
│   └─ src/{constants,crypto,identity,destination,packet,hdlc,announce,transport}.rs
├─ libs/lxmf/                      # sans-IO LXMF (hand-rolled msgpack + message codec)
├─ apps/lxmfchat/                  # the Xous app (UI + net thread + PDDB), context "[reticulum]"
host-client/                       # std host client (interop testing + reference for the app)
reference/                         # RNS/LXMF Python sources + oracle scripts (rnsref.py, lxmfref.py)
scripts/interop.sh                 # live Rust <-> Python interop harness
.venv/                             # Python rns + lxmf for interop
```

`reticulum-core` and `lxmf` are deliberately **sans-IO** (no sockets, timers,
RNG or Xous dependencies): randomness, time, storage and the transport socket
are injected by the caller. This makes them unit- and interop-testable with
plain `cargo test` on the host, and lets the Xous app and the host client share
the exact same protocol code.

## What works (interop-validated against Python RNS 1.3.5 / LXMF 1.0.1)

- Identity (X25519 + Ed25519), destination hashing, packet codec, HDLC framing.
- Token (AES-256-CBC + HMAC-SHA256) / HKDF / single-destination encryption.
- Announce build + validate (HEADER_1 and HEADER_2 / transported).
- LXMF opportunistic messages: pack / sign / encrypt and parse / decrypt / verify.
- A leaf **transport** that learns peers from announces and decrypts inbound DATA.
- A **Xous app** (`apps/lxmfchat`) with a chat UI, PDDB-persisted identity/hub/peer,
  and a background net thread bridging the hub TCP socket to the transport.

Direct delivery over Links and propagation-node sync are not yet implemented
(the opportunistic path already supports 1:1 chat between online peers).

## Testing

### Unit + known-answer interop tests (host)
```
cd xous-core
cargo test -p reticulum-core -p lxmf
```
Includes byte-for-byte known-answer vectors captured from the Python reference.

### Live interop harness (host, requires the venv)
```
python3 -m venv .venv && . .venv/bin/activate && pip install rns lxmf
./scripts/interop.sh
```
Cross-checks announces, the identity token, and LXMF messages in both directions
against the Python implementation.

### Live end-to-end over a real Reticulum hub
Start a local `rnsd` transport hub with a TCP server interface:
```
. .venv/bin/activate
mkdir -p /tmp/rns-hub && cat > /tmp/rns-hub/config <<'EOF'
[reticulum]
  enable_transport = Yes
  share_instance = No
[interfaces]
  [[TCP Server Interface]]
    type = TCPServerInterface
    listen_ip = 127.0.0.1
    listen_port = 4242
EOF
rnsd --config /tmp/rns-hub &
```
Run the host client and have a Python peer message it through the hub:
```
cargo run --manifest-path host-client/Cargo.toml -- listen 127.0.0.1:4242 &
python3 reference/send_lxmf_via_rnsd.py 20f7e44b55b06cff39719106f2bd1fd2 "Hello over rnsd"
```
The client prints the received message with `sig_valid=true`.

## Building / running the Xous app

The app is `apps/lxmfchat` (registered in `apps/manifest.json`, menu name
"Reticulum LXMF", context `[reticulum]`).

- **Hosted mode** (runs on your dev machine, minifb window):
  `cd xous-core && cargo xtask run lxmfchat`
  On **NixOS**, minifb `dlopen`s X11 libs by bare soname; use the helper that puts
  them on `LD_LIBRARY_PATH` first: `scripts/run-hosted.sh` (needs `$DISPLAY` set).
- **Compile-check hosted image without running:**
  `cargo xtask hosted-ci lxmfchat`
- **Renode emulator (with TAP networking to a local rnsd):**
  `cargo xtask renode-image lxmfchat` then `renode emulation/xous-release-tap.resc`
- **Hardware:** `cargo xtask app-image lxmfchat` then flash with `tools/usb_update.py -k`
  (requires the `riscv32imac-unknown-xous-elf` target/toolchain).

In the app: focus connects to the configured hub (default `127.0.0.1:4242`) and
announces. Use the app menu to **Set hub**, **Set peer** (paste a 32-hex LXMF
address), view **My address**, or **Announce**. Type to send; inbound messages
appear in the chat scrollback (unverified-signature messages are flagged).

On device, crypto automatically uses the Precursor's hardware SHA-512 /
curve25519 / AES engines (the workspace patches `sha2`/`curve25519-dalek` and a
local `aes` crate); on the host it falls back to software.
