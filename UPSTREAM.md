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

## paolobarbolini / bzip2-rs

### 8. Decoder preallocates by declared block size, not content (OOM on small targets)
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
