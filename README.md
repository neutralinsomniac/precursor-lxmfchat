# Precursor Reticulum — an LXMF messaging client for Xous

A [Reticulum](https://reticulum.network/) **LXMF** messaging client for the
[Precursor](https://www.crowdsupply.com/sutajio-kosagi/precursor) device, which
runs the [Xous](https://betrusted.io/xous-book/) microkernel.

The client connects to the wider Reticulum network as a **leaf node** over a
single `TCPClientInterface` to a transport hub. It announces its address,
discovers peers, and exchanges end-to-end-encrypted, signed LXMF messages —
including direct delivery over links, delivery confirmations, and
store-and-forward via a propagation node. All protocol features are working on
real hardware against real Reticulum peers (NomadNet, lxmd, Python LXMF).

## Repository layout

```
xous-core/                         # vendored betrusted-io/xous-core (the OS)
├─ libs/reticulum-core/            # sans-IO Reticulum subset (no I/O, no Xous deps)
│   └─ src/{constants,crypto,identity,destination,packet,hdlc,announce,
│           transport,link,resource,x25519,ed25519}.rs
├─ libs/lxmf/                      # sans-IO LXMF (msgpack + message codec + PoW stamps)
│   └─ src/{message,msgpack,stamp}.rs
├─ apps/lxmfchat/                  # the Xous app (UI + net threads + PDDB), context "[reticulum]"
host-client/                       # std host client (live testing + reference for the app)
reference/                         # RNS/LXMF Python sources + oracle/test scripts
scripts/                           # interop.sh, sync_test.sh, flash.sh, run-hosted.sh, …
shell.nix / .envrc                 # dev environment (direnv); requirements.txt for the venv
```

`reticulum-core` and `lxmf` are deliberately **sans-IO** (no sockets, timers,
RNG or Xous dependencies): randomness, time, storage and the transport socket
are injected by the caller. This makes them unit- and interop-testable with
plain `cargo test` on the host, and lets the Xous app and the host client share
the exact same protocol code.

## Development environment

The build/flash/test scripts need a Rust toolchain plus a few non-Rust pieces —
X11 (hosted GUI), libusb (flashing), a riscv32 cross-toolchain + openssl (EC
firmware), and a Python venv with RNS/LXMF. These are all provided declaratively
by `shell.nix` (including `rustup`), with [direnv](https://direnv.net/) loading
it automatically:

```
direnv allow            # once — then the env loads on cd into the repo
```

(No direnv? `nix-shell` drops you into the same environment.) The shell ships
**rustup** rather than a fixed Rust, because the Xous target is a custom prebuilt
sysroot that `cargo xtask` installs into the rustup toolchain. With the shell
active, do the one-time bootstrap (rustup downloads run on NixOS via nix-ld):

```
rustup default stable                                   # base toolchain
rustup target add riscv32imac-unknown-none-elf          # the kernel/loader target
(cd xous-core && cargo xtask install-toolkit --force)   # the xous sysroot

python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # the venv
```

(Note `riscv32imac-unknown-xous-elf` is *not* a `rustup target add` target — it's
the custom sysroot the `install-toolkit` step installs.) The shell prints these
hints until each piece is in place. After that, the scripts and `cargo xtask`
commands below Just Work — no per-command `nix-build`/`LD_LIBRARY_PATH`
wrangling.

## What works (validated against Python RNS 1.3.5 / LXMF 1.0.1, and on hardware)

Protocol:

- Identity (X25519 + Ed25519), destination hashing, packet codec, HDLC framing,
  Token (AES-256-CBC + HMAC-SHA256), HKDF, announces (HEADER_1 + HEADER_2).
- **Direct delivery over links, both directions, as primary** (the reference
  default): we accept inbound links (idempotently, so high-RTT retransmits
  can't desync the session key) and initiate outbound ones (LINKREQUEST →
  LRPROOF validation → RTT activation), with per-session forward secrecy and
  every delivered packet proved (the sender's ✓). Inbound opportunistic
  packets are decrypted and proved too. Link lifecycle matches the reference
  (inactivity-based reuse under LXMF's 600 s teardown).
- **Resource transfers, both directions** — messages too large for one link
  packet move as an RNS Resource: advertisement → windowed part requests with
  hashmap-update paging → reassembly → whole-stream decrypt → bz2
  decompression inbound (pure-Rust decoder, output capped against bz2 bombs)
  → proof (the delivery ack), up to a 256 KB device-memory budget per
  transfer. The same machinery serves outbound: large direct messages and
  large propagation-node transfers.
- **Propagation node support**, both directions: outbound store-and-forward
  fallback when direct delivery fails (message re-encrypted to the recipient +
  a mined **proof-of-work propagation stamp**, midstate-cached SHA-256 so the
  Precursor mines in seconds), and **message sync** (link → `LINKIDENTIFY` →
  `/get` request → Resource download → decrypt → delete-confirm). Sync runs
  automatically once per boot when the node's route resolves, and on demand
  from the menu.
- **Tickets/stamps**: inbound `FIELD_TICKET` tickets are stored (and recovered
  even when the sender's key arrives later, as on access-point hubs) and used
  to stamp replies to peers that enforce a stamp cost.
- **Transport routing**: HEADER_2 + next-hop rewriting for destinations more
  than one hop away (learned from relayed announces), and path requests to
  resolve keys/routes on access-point interfaces where announces don't flood.

App (`apps/lxmfchat`, the **default boot app**):

- Per-contact chat threads persisted in the PDDB; own messages right-aligned;
  status bar shows the active peer.
- Delivery marks on each bubble: `○` sent / `✓` delivered (proof received) /
  `»` stored at the propagation node / `×` failed, with a failure reason in
  the status bar ("no route found", "no acknowledgement", …). Marks update
  atomically and survive thread switches and restarts.
- Contacts auto-added when someone messages us (even key-less; upgraded when
  their announce/path-response arrives), unread badges, messages for inactive
  threads held + persisted and flushed when the thread is opened.
- Announce directory (live), peer pickers, two-field hub entry (the device
  keyboard has no `:`), vibration on receipt.
- Networking: waits for wifi (DHCP) before dialing, auto-reconnects with
  capped backoff, 30 s keepalives, and a stuck-write watchdog that resets the
  socket if a hub write wedges (Xous write timeouts are not reliable).
- **Local peering over wifi (RNS AutoInterface)** — zero-conf IPv6 link-local
  multicast peer discovery, so the device messages other local Reticulum nodes
  (another Precursor, or `rnsd`/NomadNet) with **no hub**; a local transport
  node routes onward just like a hub. Toggle under **Interfaces → Local peers**.
  Requires patched EC firmware — see [Local peering](#local-peering-over-wifi-autointerface).

## Hardware crypto caveats (Precursor)

The betrusted hardware crypto engines proved unreliable for this workload, so
the protocol crates carry vendored **software** implementations (TweetNaCl
ports, interop-validated) where needed:

- engine-25519 **X25519 returns wrong results** (Montgomery ladder bug) →
  software X25519 (`reticulum-core/src/x25519.rs`).
- engine-25519 Ed25519 is correct but **extremely slow** (~3 s sign, ~10–30 s
  verify per op) → software Ed25519 sign + verify
  (`reticulum-core/src/ed25519.rs`, RFC 8032-vector tested).
- SHA-2 and AES still use the hardware paths. A startup self-test logs
  `x25519/token/hkdf` correctness and `sign(sw)/verify(sw)` timings.
- `services/net` is patched to ignore non-unicast DHCP gateways (a zeroed
  lease otherwise panics smoltcp and kills the whole net service).

## Testing

### Unit + known-answer tests (host)
```
cd xous-core
cargo test -p reticulum-core -p lxmf
```
~50 tests, including byte-for-byte known-answer vectors captured from the
Python reference (announces, tokens, LXMF messages, tickets, stamps, RFC 8032
/ RFC 7748 vectors, Resource reassembly incl. bz2).

### Live interop harness (host)
From inside the dev shell with the venv created (see
[Development environment](#development-environment)):
```
./scripts/interop.sh        # announces, tokens, LXMF both directions vs Python
./scripts/sync_test.sh      # propagation-node sync vs a real-rns node
```

### Live end-to-end over a real Reticulum hub
Start a local `rnsd` transport hub with a TCP server interface:
```
mkdir -p /tmp/rns-hub && cat > /tmp/rns-hub/config <<'EOF'
[reticulum]
  enable_transport = Yes
  share_instance = No
[interfaces]
  [[TCP Server Interface]]
    type = TCPServerInterface
    enabled = Yes
    listen_ip = 127.0.0.1
    listen_port = 4242
EOF
rnsd --config /tmp/rns-hub &
```
Run the host client and message it from a real Python LXMF peer:
```
cargo run --manifest-path host-client/Cargo.toml -- listen 127.0.0.1:4242 60 &
python3 reference/send_lxmf_via_rnsd.py <client_address> "Hello over rnsd"       # opportunistic
python3 reference/send_direct_via_rnsd.py <client_address> "$(printf 'big%.0s' {1..2000})"  # direct link + Resource
```
The client prints received messages with `sig_valid=true`; the sender reports
`=== DELIVERED` once our proof arrives. The host client also has `send`,
`send-direct`, and `sync <hub> <propagation_node_hash>` modes.

## Building / running the Xous app

The app is `apps/lxmfchat` (menu name "Reticulum LXMF", context
`[reticulum]`). It is the **initial app focused at boot**
(`services/gam`'s `INITIAL_APP_FOCUS`); shellchat is still available from the
app menu.

Build-time configuration (baked in via `option_env!`):

- `LXMF_DEFAULT_HUB=<host:port>` — default hub (changeable on-device).
- `LXMF_PROPAGATION_NODE=<32-hex>` — the propagation node's `lxmf.propagation`
  destination hash (empty disables store-and-forward + sync).
- `LXMF_PROPAGATION_COST=<bits>` — PoW stamp cost for the node (default 13).

Targets:

- **Hosted mode** (dev machine, minifb window): `scripts/run-hosted.sh` (or
  `cd xous-core && cargo xtask run lxmfchat` — the dev shell already has X11 on
  `LD_LIBRARY_PATH`).
- **Compile-check the hosted image:** `cargo xtask hosted-ci lxmfchat`
- **Hardware image** (the vendored tree is a shallow clone with no tags, so
  pass an explicit version for image signing):
  ```
  LXMF_PROPAGATION_NODE=<32-hex> cargo xtask app-image lxmfchat \
      --git-describe v0.9.8-792-g2005a801 \
      --git-rev 2005a801c917753175d3826446ce1352c119e020
  ```
- **Flash:** `scripts/flash.sh` (wraps `tools/usb_update.py`; takes ~14 minutes;
  do not interrupt the write). `--erase-pddb` additionally wipes the PDDB — this
  regenerates the LXMF identity, i.e. a **new address**.

On device: the app connects automatically once wifi is up, announces, and
syncs from the propagation node. Menu: **Announces**, **Contacts** (pick a
thread; unread badges), **Connect**, **Announce**, **My address**, **Set
peer**, **Set hub**, **Sync messages**, **Clear history**. Type to send —
direct first, propagation fallback, with the delivery mark updating in place.

## Local peering over wifi (AutoInterface)

`apps/lxmfchat` can reach other Reticulum nodes on the same wifi with **no hub**
via RNS **AutoInterface** — zero-conf IPv6 link-local multicast peer discovery.
Toggle it on-device under **Interfaces → Local peers**; any local node running
an AutoInterface (`rnsd`/NomadNet, or another Precursor) becomes reachable, and
a local transport node routes onward exactly like a hub.

This needs **patched EC firmware**: the stock EC↔SoC bridge drops every IPv6
frame, so multicast discovery never reaches Xous. The fix is one commit on top
of the in-tree v0.9.15 EC image — it forwards IPv6 (ethertype `0x86DD`) across
the bridge (dropping only the noisy mDNS/LLMNR/SSDP link-local groups) and
**leaves the WF200 multicast RX filter at its power-on default (accept all)**.
That last part is counterintuitive: adding *any* address to that filter — even
the FMAC-documented broadcast "allow-all" — flips this firmware into a whitelist
mode it implements unreliably, dropping even all-nodes traffic. (Full diagnosis
in `UPSTREAM.md`.)

- Fork: <https://github.com/neutralinsomniac/betrusted-ec>

### Build `ec_fw.bin`

The EC is a separate RISC-V softcore image, built from the betrusted-ec tree.
One-time setup:

```
git clone https://github.com/neutralinsomniac/betrusted-ec
cd betrusted-ec
git submodule update --init --recursive
rustup target add riscv32i-unknown-none-elf
cargo update -p openssl-sys          # 0.9.58 can't parse OpenSSL 3 headers
```

This repo's `shell.nix` supplies the cross-toolchain and openssl (the build
calls the toolchain as `riscv-none-elf-*`, which `shell.nix` provides as
wrappers over nixpkgs' `riscv32-none-elf-*`). Build the EC from inside that
shell — `nix-shell` keeps the env across the `cd`, so point it at this repo's
`shell.nix`:

```
nix-shell /path/to/precursor-reticulum/shell.nix \
  --run "cd /path/to/betrusted-ec && cargo xtask hw-image"
```

(Or drop a copy of `shell.nix` + `.envrc` into your betrusted-ec fork and let
direnv handle it.) The USB-update package lands at `precursors/ec_fw.bin`
(`bt-ec.bin` is the JTAG variant).

### Flash

Stage the EC package, then apply it from the device:

```
# from this repo, inside the dev shell. This also rewrites the kernel, which is
# harmless.
scripts/flash.sh -e /path/to/betrusted-ec/precursors/ec_fw.bin
```

Then on the device: **main menu → "Force EC update"**, and let it reboot. The EC
staging slot sits inside the `--erase-pddb` wipe range, so re-stage if you ever
wipe the PDDB. Verify under **Interfaces → Local peers** — it should find a peer
within a few seconds of any local AutoInterface node beaconing.

### Peer-side (`rnsd`/NomadNet) config

The Precursor is a leaf node. To also **see announces** from a local transport
node, that node's AutoInterface must not be in `access_point` mode — RNS
deliberately blocks the announce stream (even the node's own announce) onto
access-point interfaces. Use `mode = gateway` or `mode = full` for the firehose;
in `access_point` mode the Precursor still messages on demand via path requests,
just without a browsable announce directory.

## Known limitations

- Resource transfers are capped at 256 KB (a device-memory budget: parts and
  the reassembled stream are buffered in RAM). Windowed part requests and
  hashmap-update paging handle anything up to that; RNS's multi-*segment*
  splitting (only used above 1 MB) is not supported. Sync batches advertise a
  128 KB limit, so larger backlogs arrive over multiple syncs.
- No proof-of-work **delivery** stamps (`LXStamper`): peers who enforce a
  stamp cost can only be messaged once they send us a ticket (NomadNet does
  this automatically for trusted peers). The propagation-node PoW stamp *is*
  implemented.
- We never issue tickets ourselves (we don't enforce a stamp cost).
- Single hub interface; the device clock must be set for outgoing message
  timestamps to be right on the receiving end.
