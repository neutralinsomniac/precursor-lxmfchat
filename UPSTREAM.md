# Upstream findings to report

Bugs found (and worked around in this tree) while building the LXMF client.
Each entry has a local workaround, so none of these block us — but they
affect anyone else building on these components. Device context for the
hardware items: Precursor pvt2, SoC v0.9.14, June 2026.

## betrusted-io / xous-core

### 1. engine-25519: X25519 returns wrong results (hardware)
The hardware curve25519 backend (`curve25519-dalek` betrusted fork,
`u32e_backend`, engine microcode) computes X25519 ECDH (Montgomery ladder)
**incorrectly** — silently, with no error, so the library's software fallback
never triggers. The Edwards/Ed25519 path of the same engine is *correct*
(announces and signatures verified fine), which made this hard to find: every
HKDF-derived session key was wrong, so all Token HMACs failed while signature
checks passed.
- Repro: RFC 7748 §5.2 known-answer test on device → FAIL (host → OK).
- Workaround here: vendored software X25519 (TweetNaCl port) in
  `xous-core/libs/reticulum-core/src/x25519.rs`; byte-validated against real
  Python RNS.

### 2. engine-25519: Ed25519 is extremely slow (hardware)
Measured on device via a startup self-test (`std::time::Instant` around
dalek calls): **sign ≈ 3.2 s/op, verify ≈ 10–30 s/op**. Not wrong, just
unusably slow — a chained verify (announce + link proof) blew protocol
timeouts and looked like wedged threads for a whole debugging night.
- Workaround here: vendored software Ed25519 sign + verify (TweetNaCl port,
  RFC 8032 vectors) in `xous-core/libs/reticulum-core/src/ed25519.rs`;
  software is ~0.5–1.1 s/op on the 100 MHz RV32 — 5–30× faster than the
  hardware engine.

### 3. services/net: non-unicast DHCP gateway panics the whole net service
`services/net/src/main.rs` installed the DHCP-supplied default gateway
unconditionally; a zeroed/non-unicast gateway (observed during a lease-renewal
hiccup on idle wifi) makes the next TCP retransmit resolve next-hop 0.0.0.0 and
**smoltcp asserts** (`iface/neighbor.rs:134 protocol_addr.is_unicast()`),
killing the net service until reboot while apps still believe they're
connected.
- Local fix: only `add_default_ipv4_route` when `gw.is_unicast()`, else warn
  and leave the default route unset.
- NOTE: upstream has since rewritten `services/net` entirely — check whether
  the rewrite has the same hole before reporting.

### 4. llio::LocalTime's Drop breaks libstd SystemTime process-wide
The kernel **dedupes** per-process connections to a server, and libstd caches
its connection to `timeserverpublic` in a static
(`std/os/xous/services/systime.rs`). `llio::LocalTime`'s refcounted `Drop`
calls `xous::disconnect()` when llio's count hits zero — severing the *same,
shared* connection. After dropping the last `LocalTime` in a process, every
later `SystemTime::now()` in that process panics:
`failed to request utc time in ms: the requested server could not be found`
(`std/src/sys/pal/xous/time.rs:40`).
- llio's refcount is crate-local, so it cannot know libstd holds the
  connection. Either `LocalTime` should never disconnect the well-known
  server, or libstd should reconnect on send failure.
- Workaround here: hold a process-lifetime `LocalTime`
  (`libs/chat/src/lib.rs`, `tz_offset_secs`).

### 5. libs/chat correctness fixes (PR material, not just reports)
Fixed in this tree, all pre-existing upstream:
- `Dialogue::post_find` / the `post_add` middle-insert looped `i..last`,
  **excluding the final post** — finding/updating the most-recent bubble
  silently missed (and a re-added post could be dropped).
- `post_add` replaced an existing post on `(timestamp, author)` collision —
  two messages in the same wall-clock second (inbound LXMF timestamps are
  whole seconds) silently lost one. It now always inserts.
- `ui.post_del` was an unimplemented stub that the chat server `.expect()`ed
  → guaranteed panic on first use.
- `ui::dialogue_save` did get()+write() **without delete-first**; PDDB writes
  default to `truncate=false`, so rewriting a *shorter* value leaves a stale
  tail and the key's old length. rkyv reads its root from the end of the
  value → bogus length → multi-MB allocation abort. (Worth documenting as a
  PDDB API footgun generally: shorter rewrite ⇒ delete key first or truncate.)
  Also added: envelope (magic|len|crc) validation on read, `write_all`/
  `read_to_end` instead of single `write`/`read` (short I/O fails checksums),
  scrollback caps so a dialogue can't outgrow the PDDB value limit.
- `ux-api` ScrollableList (modals radio list) had no wrap-around on
  up/down; patched `move_selection` to wrap (GAM menus already wrap).
- `ui::layout()` anchored bottom-up bubbles at a viewport size cached once
  at startup. When the IME input box grows during composition the content
  canvas shrinks, so every bubble was laid out below the canvas bottom and
  clipped away — a blank chat while composing a multi-line message. Fixed by
  re-fetching `get_canvas_bounds` at the top of every redraw. (Pairs with
  the GAM redraw gap below — both are needed for the visible fix.)

### 6. gam: IME-driven input-box resize blanks the app's content canvas with no redraw
When the IME front end grows the input box (long line wraps during
composition) or snaps it back after a send, `ChatLayout::resize_height`
shrinks/restores the **content** canvas and clears it to white — but the
`SetCanvasBounds` handler in `services/gam/src/main.rs` deliberately sends no
redraw ("every context will call redraw after it has finished fitting its
bounds"). That's true for the *requesting* context (the IME repaints its
input canvas), but the content canvas belongs to the **app**, which is never
told anything happened. Result: any `UxType::Chat` app (shellchat, mtxchat)
shows a blank content area from the moment the input box grows until
something else triggers a redraw.
- Local fix: after a granted resize via the **Gam** token (the IME is its
  only caller; modals/menus resize with App tokens and repaint themselves),
  call `context_mgr.redraw()` so the focused app repaints its content.
- Note for the report: fixing only the GAM is not sufficient for chat-lib
  apps — see the stale-viewport bullet in entry 5.

### 7. tools/usb_update.py: endpoint desync after interrupted write
After unplugging mid-write, every subsequent flash attempt fails with
`[Errno 75] Overflow`; `pyusb dev.reset()` re-enumerates but doesn't clear it.
Only a physical unplug/replug (full controller reset) recovers. Minor, but a
retry-after-reset in the tool would save confusion.

### 8. ime-frontend: input-box growth misses by 2px, then overshoots by a whole line
When typed text overflows the input box, the IME grows it by
`ic_bounds.y + last_height + 2`. Two fenceposts make that land **2px short**
of fitting the next line: `ic_bounds.y` is the canvas' normalized *inclusive*
bottom-right (height − 1), and the renderer wraps within
`height − 2·margin − 2` with a strict `<` fit test. The next keystroke
overflows again and the retry adds another full line — so every grown box
carries a permanent blank line under the line being typed. Separately, the
grow trigger (`cursor.line_height == 0`) only fires for mid-word overflow
(`reject_candidate_word`); overflow at a whitespace wrap keeps
`line_height > 0`, so the box never grows at all in that case. Reproduced
against the real typesetter in `libs/ux-api/tests/grow_sim.rs` (run with
`--features hosted,std`): heights go 27 → 47 (still overflowing) → 67
(2 lines + a 19px blank slot).
- Local fix (`services/ime-frontend/src/main.rs`): trigger on
  `line_height == 0 || overflow`, and compute the request precisely as
  `cursor.pt.y + 2·line_height + 1 + 2·margin.y + 2` (on overflow the cursor
  sits at the top of the last fitting line). Each grow now adds exactly one
  line, caret on the bottom line with ~2px slack. Also: re-read the canvas
  bounds for the post-grow redraw (the `granted` Point is the *content*
  canvas' screen-space corner for ChatLayout, not the input canvas size), and
  remember a refused request (`grow_refused`) so a height-capped box doesn't
  spam resize/redraw on every keystroke.

### 10. services/net: wildcard UDP binds never receive unicast
`std_udp_bind` converts the requested address with smoltcp's
`From<IpEndpoint> for IpListenEndpoint`, which wraps it in `Some(...)`
unconditionally — so a libstd `UdpSocket::bind("0.0.0.0:p")` binds to the
*literal* unspecified address. smoltcp's `udp::Socket::accepts` then rejects
every unicast datagram (`Some(0.0.0.0) != Some(dst)`; only broadcast/multicast
destinations pass). Any portable code that binds wildcard and expects unicast
UDP replies silently receives nothing.
- Local fix: map an unspecified bind address to a true wildcard listen
  (`IpListenEndpoint { addr: None, .. }`) in `std_udp.rs`.
- Related additions in this tree (PR material, needed for Reticulum
  AutoInterface): the interface now gets an EUI-64 IPv6 link-local address
  (`fe80::…`, derived from the MAC) alongside the DHCP v4 address
  (`iface-max-addr-count-3`); new `JoinMulticastV6`/`LeaveMulticastV6` net
  opcodes + `NetManager::{join,leave}_multicast_v6` (libstd's
  `join_multicast_v6` is an unimplementable stub on Xous, the netstack owns
  group membership).

### 11. services/dns: resolver UDP socket never rebinds — DNS dead after a network switch
The DNS resolver (`services/dns/src/main.rs`, `Resolver::new`) binds one
`UdpSocket` at startup and reuses it for every query. Switching WiFi networks
changes the device's IP underneath that long-lived socket, leaving its binding
stale: `send_to`/`recv` then fail and every lookup returns
`DnsResponseCode::NetworkError` — while ping-by-IP still works (Ping uses its own
socket) and `net debug` shows the DNS server set correctly. Only a reboot (which
recreates the socket) recovers. The dns service has no IP-change hook to rebind
on — the server list is managed inside `net::protocols::DnsServerManager`, not
via dns opcodes.
- Local fix: `resolve()` retries once on `NetworkError`, rebinding the socket
  against the live interface first (`bind_dns_socket` helper + `rebind()`);
  `NoServerSpecified` is left alone (config gap, not a stale socket).
- Exact sub-mechanism (source IP pinned at bind vs per-socket smoltcp state)
  unconfirmed on HW, but rebind = what a reboot does for the socket.

### 12. services/net: RX interrupt never re-polled on resume — wifi RX wedges after sleep
The EC holds its host-interrupt line asserted (level) until the SoC ACKs a
pending interrupt, but the SoC side only fires on a fresh *edge*
(`betrusted-ec/sw/src/com_bus.rs`). At startup the net service drains pending
interrupts with `ints_get_active` right after enabling them
(`services/net/src/main.rs`), but the **resume** handler only re-enables — it
never polls. Across the multi-service suspend/resume ordering (net=Early,
com=Late, plus llio) the EC's set-mask retrigger edge gets lost, so RX/events
that arrived while suspended are never delivered: the EC RX buffer just fills
(`net debug` shows `drops` climbing) and DNS/ping replies never reach smoltcp.
Looks like "can't send" but is "can't receive"; `tx_errs` stays 0 and toggling
the wifi kill switch (forces a new edge) recovers it, dumping the whole backlog.
- Local fix: the net resume handler sends itself one `ComInterrupt` after
  re-enabling, forcing a poll (mirrors startup) that drains the pending vector
  and restarts the per-packet ack→re-edge chain. No-op when nothing is pending.

### 13. services/net: scan-finished interrupt doesn't expedite the join — slow reassociate
The connection manager (`services/net/src/connection_manager.rs`) acts on a
`WlanSsidScanFinished` interrupt only by setting `scan_state = Idle`; the
actual AP join is issued from the periodic `Poll` management pass, which is
gated by the inactivity-interval ramp (`activity_interval.fetch_add(interval)
> interval`). So a scan that finishes during a quiet period (the interval has
ramped up) waits the better part of the next multi-second tick before the join
is even attempted — most visible right after resume, where every second of
dead link is felt (and compounds with the disassociate-on-suspend reassociate
path).
- Local fix: on `WlanSsidScanFinished`, set an `expedite_poll` flag and send
  the manager an immediate `Poll`; `Poll` runs the management pass when
  `activity_timeout || expedite_poll`, so the join fires right away instead of
  waiting for the inactivity timer. (Behaviorally a latency fix, not a
  correctness one — the join always happened eventually.)

### 14. services/net: socket read/write timeouts never fire while the link is quiet
The `NetPump` handler early-returned when `iface.poll()` reported no readiness
change (`if !iface.poll(..) { continue; }`) — but the waiter scan it skipped is
also the only place `expiry` deadlines are evaluated. On an idle or stalled
link, poll() returns false on every 900 ms self-pump, so a blocked
`recv_timeout`/`send` with a timeout simply never returned: reconnect
watchdogs built on socket timeouts silently never ran, converting any
transient RX stall into a permanent app-level hang. (This is the mechanism
that made several of the wifi-drop failure modes *unrecoverable* instead of
transient.)
- Local fix: run the waiter/expiry scan on every pump regardless of poll()'s
  return value (the scan is a few small arrays; cost is negligible).

### 15. services/net + com: silent-drop hardening from the wifi-drop investigation
A cluster of local fixes (July 2026) after diagnosing random silent drops of
all connectivity; each is PR material in its own right:
- `WlanTxErr`/`WlanRxErr` were never unmasked in `set_com_ints` and had no
  handler arm — a wedged WF200 TX queue was invisible (see the EC section).
  Now unmasked, logged, and counted.
- The connection-manager watchdog treated DHCP `Renewing`/`Rebinding` as a
  mismatch and tore down a healthy link mid-renewal (RFC 2131: the lease is
  still valid). Now treated as healthy.
- The Connected-but-silent watchdog branch only force-drained interrupts and
  never escalated — a zombie association (AP deauth the WF200 never reported)
  was permanent. Now escalates to `wlan_leave` + reset after 2 fruitless
  drains.
- Watchdog liveness was keyed on ANY `WlanRxReady` (broadcast chatter blinds
  it to unicast-only deafness / TX death). Added a unicast TX-vs-RX zombie
  detector in the connection manager, fed by per-direction unicast frame
  counters in the device layer.
- The COM server never issued `LINK_SYNC` at runtime: one slow EC reply
  skewed the reply FIFO and every later multi-word read (RX frames, interrupt
  vectors) decoded as garbage until a wifi toggle. Timed-out reads now mark
  the link stale and the main loop resyncs (+ ping verify) before the next
  opcode.
- The vendored smoltcp neighbor-cache patch (`11fbe44`) had shipped only half
  the fix: `lookup()` never returned the `StaleProbe` answer the dispatch code
  was written for, so an expired entry still blocked all egress to that
  neighbor (gateway ⇒ every TCP flow; LL peer ⇒ local UDP) pending a full
  ARP/NS round trip over the lossy RX path. The stale-while-revalidate lookup
  half now exists (covered by `test_stale_while_revalidate`).

## betrusted-io / betrusted-ec

### EC net bridge drops all IPv6 — no IPv6 connectivity possible on Precursor wifi
Found while bringing up Reticulum AutoInterface (IPv6 link-local multicast
discovery). Verified end-to-end on hardware + wire captures, June 2026:
- **RX**: `sw/net/src/lib.rs handle_frame` forwards only `ETHERTYPE_IPV4` and
  `ETHERTYPE_ARP` to the COM net bridge; everything else — explicitly
  including IPv6 — is binned `DropEType`. Inbound IPv6 (neighbor
  solicitations, UDP, everything) never reaches the SoC. The Xous net stack
  compiles smoltcp with `proto-ipv6` and happily configures v6 addresses, but
  no v6 frame can ever arrive.
- **RX (radio)**: nothing ever calls `sl_wfx_add_multicast_addr`, so the
  WF200's multicast whitelist is presumably in its default state; even with
  the EtherType filter fixed, `33:33:*` frames may still be dropped at the
  radio until the whitelist admits them (broadcast addr = allow-all).
- **TX**: `send_net_packet` is unfiltered, and the SoC-side counter confirms
  multicast frames are handed to `sl_wfx_send_ethernet_frame` — but they
  never appear on the air (tcpdump on the same AP sees other STAs' multicast
  to the same group fine). A WF200 error would be logged EC-side
  (`SendFrameErr`) and raises `INT_WLAN_TX_ERROR` — which the **xous-core
  net service ignores** (no `ComIntSources::WlanTxErr` arm), so TX rejection
  is invisible to the host. Root cause of the TX drop (firmware rejection vs
  silent eat) still to be pinned via EC logs.
- Net effect: AutoInterface (and any IPv6) requires EC firmware changes:
  forward `ETHERTYPE_IPV6` to `ComFwd`, open the WF200 multicast whitelist,
  and surface TX errors.

## smoltcp 0.11 (vendored at `xous-core/imports/smoltcp`)

smoltcp 0.11's `join_multicast_group` returns `Ipv6NotSupported` and its
IPv6 RX accept path only admits all-nodes + solicited-node multicast — so
nothing built on it can *receive* IPv6 multicast (IPv6 multicast landed
upstream in 0.12, but services/net is written against 0.11 APIs). Vendored
0.11.0 with a minimal patch: an `ipv6_multicast_groups` table checked in
`has_multicast_group`, populated via new `join/leave_multicast_group_v6`
methods. No MLD reports are emitted — fine on WiFi APs and non-snooping
switches, where multicast is flooded. Long-term the right move is upgrading
services/net to smoltcp 0.12+.

## paolobarbolini / bzip2-rs

### 9. Decoder preallocates by declared block size, not content (OOM on small targets)
`block/mod.rs` allocates the BWT working array as
`Vec::with_capacity(header.max_blocksize())` — for a `BZh9` stream (Python's
`bz2` default) that's 900,000 × 4 B = **3.6 MB up front**, even when the
actual block holds a few KB. On a 16 MB-RAM device this is an instant abort.
The array only ever grows via `push`/`resize` to the actual block content, so
lazy allocation works with no behavior change.
- Workaround here: vendored copy in `xous-core/libs/bzip2-rs` with lazy `tt`
  allocation + a clamp on supported block content.

## Future work to propose upstream (TODO, not yet written)

### gam/modals: first-class Okay/Cancel in radio-list dialogs (F2/F3)
The modals `get_radiobutton` API has no "dismiss" concept — it blocks until
some item label is returned. So any cancellable picker must inject a
synthetic `[cancel]` list row, and confirming means scrolling past every
entry to the built-in `Okay` line. Local additions in this tree (commits
`81a6e60`, `08dac5c`): F2 confirms the highlighted item from anywhere in the
list; F3 confirms the item labeled `gam::modal::CANCEL_SENTINEL` *if the
list has one* (deliberately conservative so other apps' dialogs can't be
misfired); the app relabels the F-key tray okay/cancel while a picker is up.
The proper rewrite to attempt upstream: give RadioButtons (and likely
CheckBoxes) native accept/cancel semantics — F3 closes and reports
"cancelled" through the modals API itself (an `Option`/status return rather
than a reserved label), F2 as the accept accelerator, and standard key hints
rendered by the modal — so apps need neither the synthetic `[cancel]` row
nor the sentinel convention. Needs an API-compatibility story for existing
`get_radiobutton` callers (vault, mtxchat, dns, …), which is why it stayed
a local accelerator hack here.

## Not reportable (red herrings we disproved)

- "std Mutex parking loses wakeups on hardware" — wrong; the hang was our own
  lock-in-match-scrutinee self-deadlock.
- "socket write timeouts don't fire on hardware" — unproven as an OS bug; the
  observed wedge had the same self-deadlock cause. (Our stuck-write watchdog
  remains as cheap insurance.)
