//! LXMF chat app logic for Xous/Precursor.
//!
//! Owns the identity (persisted in the PDDB), the sans-IO [`Transport`], the TCP
//! connection to a Reticulum hub, and the chat UI. A background thread
//! ([`net::rx_thread`]) reads HDLC frames off the socket, drives the transport,
//! and posts inbound LXMF messages into the chat UI; the main thread sends
//! announces and outbound messages.

mod net;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use chat::{Chat, ChatOp, Post};
use xous_ipc::Buffer;
use pddb::Pddb;
use reticulum_core::constants::{KEY_HALF, KEYSIZE, NAME_HASH_LENGTH, RATCHET_SIZE, TRUNCATED_HASHLENGTH};
use reticulum_core::destination::single_destination_hash;
use reticulum_core::identity::{PrivateIdentity, PublicIdentity};
use reticulum_core::transport::{KnownDest, Transport};
use trng::Trng;
use xous::CID;
use xous_names::XousNames;

pub use net::Shared;

const PDDB_DICT: &str = "lxmf.state";
const CONTACTS_DICT: &str = "lxmf.contacts";
/// Messages received for a contact while it wasn't the active conversation,
/// persisted so they (and the unread badge) survive an app restart. One key per
/// contact (hex dest hash); value is length-prefixed `(ts, author, text)` records.
const PENDING_DICT: &str = "lxmf.pending";
/// Outbound tickets a stamp-cost peer has trusted us with. One key per peer
/// (hex dest hash); value is `expiry(8 BE) || ticket(16)`. Used to stamp replies
/// to peers who enforce a stamp cost (see [`net::Shared::tickets`]).
const TICKETS_DICT: &str = "lxmf.tickets";
/// Held delivery-mark updates (✓/⇪/✗) for threads not yet opened. One key per
/// contact (hex dest hash); value is length-prefixed `(ts, status, text)` records.
const DELIVERY_DICT: &str = "lxmf.delivery";
const KEY_IDENTITY: &str = "identity";
const KEY_HUB: &str = "hub";
const KEY_PEER: &str = "peer";
/// Each contact gets its own dialogue (scrollback) stored under this dict,
/// keyed by the hex of its destination hash. `DIALOGUE_WELCOME` is shown before
/// any peer is selected.
pub(crate) const DIALOGUE_DICT: &str = "lxmf.dialogue";
const DIALOGUE_WELCOME: &str = "welcome";

/// Cap the Announces picker to a length the modal can comfortably show.
const ANNOUNCE_LIST_MAX: usize = 32;
/// First entry in peer pickers, lets the user back out without choosing.
const CANCEL_LABEL: &str = "[cancel]";

/// Default Reticulum hub (`TCPClientInterface` target) used until one is set via
/// the in-app "Set hub" menu (which persists to the PDDB and takes precedence).
/// Override at build time, e.g.:
///   `LXMF_DEFAULT_HUB=192.168.1.50:4242 cargo xtask app-image lxmfchat …`
const DEFAULT_HUB: &str = match option_env!("LXMF_DEFAULT_HUB") {
    Some(h) => h,
    None => "127.0.0.1:4242",
};

/// LXMF propagation node used as a store-and-forward fallback when a message
/// can't be delivered directly. Set it to the node's `lxmf.propagation`
/// destination hash, 32 hex chars (16 bytes), at build time:
///   `LXMF_PROPAGATION_NODE=<32-hex> cargo xtask app-image lxmfchat …`
/// Empty (the default) disables the fallback (a message that can't be delivered
/// directly is then marked failed). Example: "a1b2c3…".
const PROPAGATION_NODE_HEX: &str = match option_env!("LXMF_PROPAGATION_NODE") {
    Some(h) => h,
    None => "",
};

/// The configured propagation node's destination hash, if any (see
/// [`PROPAGATION_NODE_HEX`]).
pub(crate) fn propagation_node() -> Option<[u8; TRUNCATED_HASHLENGTH]> {
    if PROPAGATION_NODE_HEX.is_empty() {
        return None;
    }
    parse_addr(PROPAGATION_NODE_HEX)
}

/// Proof-of-work cost (leading zero bits) the propagation node requires on each
/// stored message's stamp. A node advertises `PROPAGATION_COST` (default 16) with
/// a `STAMP_COST_FLEXIBILITY` (default 3), so it accepts stamps down to
/// `cost - flexibility` (= 13). We target that minimum accepted value so the
/// Precursor mines as few attempts as possible while still being accepted.
/// Override at build time with `LXMF_PROPAGATION_COST=<bits>`.
const PROPAGATION_COST_STR: &str = match option_env!("LXMF_PROPAGATION_COST") {
    Some(c) => c,
    None => "13",
};

/// The configured propagation-node stamp cost in leading-zero bits (see
/// [`PROPAGATION_COST_STR`]).
pub(crate) fn propagation_cost() -> u32 {
    PROPAGATION_COST_STR.parse().unwrap_or(13)
}

/// Current wall-clock time in seconds (Xous std SystemTime, same as chat::now()).
fn now() -> u64 { chat::now() }

/// Fill `dest` with TRNG bytes.
pub(crate) fn fill_random(trng: &Trng, dest: &mut [u8]) {
    let words = (dest.len() + 3) / 4;
    let mut w = vec![0u32; words];
    trng.fill_buf(&mut w).expect("trng");
    let mut bytes = Vec::with_capacity(words * 4);
    for word in &w {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    dest.copy_from_slice(&bytes[..dest.len()]);
}

fn hex(b: &[u8]) -> String { reticulum_core::hex(b) }

pub struct LxmfChat<'a> {
    chat: &'a Chat,
    chat_cid: CID,
    pddb: Pddb,
    trng: Trng,
    shared: Arc<Shared>,
    hub: String,
    /// Whether the background connection manager (auto-reconnect) is running.
    manager_started: bool,
}

impl<'a> LxmfChat<'a> {
    pub fn new(chat: &'a Chat) -> LxmfChat<'a> {
        let xns = XousNames::new().unwrap();
        let trng = Trng::new(&xns).unwrap();
        let pddb = Pddb::new();
        pddb.try_mount();

        let priv_bytes = load_or_create_identity(&pddb, &trng);
        let mut x = [0u8; KEY_HALF];
        let mut e = [0u8; KEY_HALF];
        x.copy_from_slice(&priv_bytes[..KEY_HALF]);
        e.copy_from_slice(&priv_bytes[KEY_HALF..]);
        let identity = PrivateIdentity::from_bytes(&x, &e);
        let our_dh = single_destination_hash("lxmf", &["delivery"], &identity.hash());

        let mut transport = Transport::new(identity);
        transport.register_destination(our_dh);

        // Load persisted contacts (learned from past announces) so they are
        // immediately listable and messageable, even before a fresh announce.
        let mut contacts_map = BTreeMap::new();
        load_contacts(&pddb, &mut transport, &mut contacts_map);

        // Restore messages that arrived but weren't read before the last restart,
        // and their unread badges.
        let mut pending_map = BTreeMap::new();
        let mut unread_map = BTreeMap::new();
        load_pending(&pddb, &mut pending_map, &mut unread_map);

        // Restore outbound tickets so we can keep replying to stamp-cost peers
        // who've trusted us, across restarts.
        let mut tickets_map = BTreeMap::new();
        load_tickets(&pddb, &mut tickets_map);

        // Restore delivery-mark updates that were held for threads we hadn't opened
        // yet, so a ✓/⇪/✗ that landed while another conversation was active (or
        // before a restart) is still applied when the thread is opened.
        let mut delivery_map = BTreeMap::new();
        load_delivery_updates(&pddb, &mut delivery_map);

        let hub = read_string(&pddb, KEY_HUB).unwrap_or_else(|| DEFAULT_HUB.to_string());
        let current_peer = read_string(&pddb, KEY_PEER).and_then(|s| parse_addr(&s));

        let chat_cid = chat.cid();
        let shared = Arc::new(Shared {
            transport: Mutex::new(transport),
            writer: Mutex::new(None),
            connected: core::sync::atomic::AtomicBool::new(false),
            ctl: Mutex::new(None),
            write_started: core::sync::atomic::AtomicU32::new(0),
            beat_sync: core::sync::atomic::AtomicU32::new(0),
            beat_pump: core::sync::atomic::AtomicU32::new(0),
            beat_read: core::sync::atomic::AtomicU32::new(0),
            sync_stage: core::sync::atomic::AtomicU32::new(0),
            beat_frames: core::sync::atomic::AtomicU32::new(0),
            frame_stage: core::sync::atomic::AtomicU32::new(0),
            sync_stage_at: core::sync::atomic::AtomicU32::new(0),
            beat_sync_done: core::sync::atomic::AtomicU32::new(0),
            beat_ka: core::sync::atomic::AtomicU32::new(0),
            tspan: core::sync::atomic::AtomicU32::new(0),
            our_dh,
            dialogue_id: DIALOGUE_WELCOME.to_string(),
            seen: Mutex::new(BTreeMap::new()),
            contacts: Mutex::new(contacts_map),
            current_peer: Mutex::new(current_peer),
            recent_msg_ids: Mutex::new(Vec::new()),
            last_ts: Mutex::new(0),
            sync: Mutex::new(net::SyncState::new()),
            llio: llio::Llio::new(&xns),
            hub: Mutex::new(hub.clone()),
            unread: Mutex::new(unread_map),
            pending: Mutex::new(pending_map),
            tickets: Mutex::new(tickets_map),
            ticket_pending: Mutex::new(BTreeMap::new()),
            outbox: Mutex::new(Vec::new()),
            delivery_updates: Mutex::new(delivery_map),
        });

        // Open the last conversation we were in (if any), else a welcome thread.
        let initial_key = current_peer.map(|p| hex(&p)).unwrap_or_else(|| DIALOGUE_WELCOME.to_string());
        chat.dialogue_set(DIALOGUE_DICT, Some(&initial_key)).ok();

        // One-shot on-device crypto self-test. The host baseline is
        // "x25519:OK token:OK hkdf:08ed4e4cbcd2"; any divergence here means the
        // hardware crypto backend differs from software and is why ECDH-derived
        // link/opportunistic keys fail HMAC while announces still work.
        let st = reticulum_core::self_test();
        // Time one Ed25519 sign (hardware dalek) and one verify (vendored
        // software): hardware VERIFY was measured at tens of seconds per call on
        // this device (it stalled sync + sends behind the transport lock), which
        // is why verify is software now. This line keeps both costs visible.
        let st = {
            let t0 = std::time::Instant::now();
            let sig = shared.transport.lock().unwrap().identity().sign(b"selftest timing");
            let sign_ms = t0.elapsed().as_millis();
            let pubid = shared.transport.lock().unwrap().identity().public().clone();
            let t1 = std::time::Instant::now();
            let ok = pubid.validate(&sig, b"selftest timing");
            let verify_ms = t1.elapsed().as_millis();
            format!("{st} sign(sw):{sign_ms}ms verify(sw):{verify_ms}ms:{}", if ok { "OK" } else { "FAIL" })
        };
        log::info!("crypto self-test: {}", st);
        let post = Post {
            dialogue_id: initial_key.clone(),
            author: "selftest".to_string(),
            timestamp: now(),
            text: st,
            attach_url: None,
        };
        if let Ok(b) = Buffer::into_buf(post) {
            b.send(chat_cid, ChatOp::PostAdd as u32).ok();
        }
        xous::send_message(chat_cid, xous::Message::new_scalar(ChatOp::DialogueSave as usize, 0, 0, 0, 0)).ok();

        log::info!("lxmf delivery address {}", hex(&our_dh));
        LxmfChat { chat, chat_cid, pddb, trng, shared, hub, manager_started: false }
    }

    pub fn our_address(&self) -> String { hex(&self.shared.our_dh) }

    pub fn redraw(&self) { self.chat.redraw(); }

    /// Ensure we're connected to the configured hub. Starts the background
    /// connection manager (which auto-reconnects on drop) on first call; on
    /// later calls it points the manager at the current hub and forces a fresh
    /// (re)connect so a "Set hub" / explicit "Connect" takes effect immediately.
    pub fn connect(&mut self) {
        *self.shared.hub.lock().unwrap() = self.hub.clone();
        if !self.manager_started {
            self.manager_started = true;
            let shared = self.shared.clone();
            let cid = self.chat_cid;
            std::thread::spawn(move || net::connection_manager(shared, cid));
            // One keepalive + stuck-write-watchdog thread for the app's lifetime
            // (survives reconnects).
            let ka = self.shared.clone();
            let ka_cid = self.chat_cid;
            std::thread::spawn(move || net::keepalive_thread(ka, ka_cid));
            // One outbox pump thread: drives delivery timeouts + propagation
            // fallback so sent messages reach a terminal mark (✓/⇪/✗).
            let pump = self.shared.clone();
            let pump_cid = self.chat_cid;
            std::thread::spawn(move || net::outbox_pump_thread(pump, pump_cid));
            // A SEPARATE thread for propagation-node sync, so a slow outbox op
            // (a stalled hub write, or PoW-stamp mining) on the pump thread can't
            // stall the sync request — and vice-versa.
            let synct = self.shared.clone();
            let sync_cid = self.chat_cid;
            std::thread::spawn(move || net::sync_thread(synct, sync_cid));
            return;
        }
        // Manager already running: drop any live socket so it reconnects to the
        // (possibly newly-set) hub. If already disconnected it's mid-backoff and
        // will pick up the new hub on its next attempt. Shutdown goes through the
        // control clone — the writer mutex may be held by an in-flight (possibly
        // stuck) write, and the main thread must never block on it.
        if let Some(ctl) = self.shared.ctl.lock().unwrap().take() {
            ctl.shutdown(std::net::Shutdown::Both).ok();
        }
        self.chat.set_status_text(&format!("reconnecting to {}…", self.hub));
    }

    /// Announce our lxmf.delivery destination on the hub.
    pub fn announce(&mut self) {
        let mut r5 = [0u8; 5];
        fill_random(&self.trng, &mut r5);
        let raw = {
            let tp = self.shared.transport.lock().unwrap();
            tp.make_announce_with("lxmf", &["delivery"], b"precursor", &r5, now())
        };
        if self.write_framed(&raw) {
            self.chat.set_status_text("announced");
        }
    }

    /// Download messages stored for us at the configured propagation node. Only
    /// flags the request — the pump thread does the actual link + hub writes, so
    /// this returns immediately and never blocks the UI on a hub write.
    pub fn sync_now(&self) {
        net::request_sync(&self.shared);
        // Liveness snapshot, rendered by the MAIN thread from lock-free atomics
        // (so it displays no matter which mutex/thread is wedged): s/p/r =
        // sync/pump/read thread heartbeats, g = last sync-path stage reached
        // (see net.rs stage table), c = connected. Press Sync twice ~15 s apart:
        // s should advance by ~15 and g should move — whichever number FREEZES
        // identifies the wedged thread / exact blocking statement.
        use core::sync::atomic::Ordering;
        let s = self.shared.beat_sync.load(Ordering::SeqCst);
        // s = passes started / completed: "s66/65" frozen with started ahead
        // means the sync thread is blocked INSIDE a pass; both frozen means it
        // isn't being scheduled at all.
        let sd = self.shared.beat_sync_done.load(Ordering::SeqCst);
        let p = self.shared.beat_pump.load(Ordering::SeqCst);
        let r = self.shared.beat_read.load(Ordering::SeqCst);
        let g = self.shared.sync_stage.load(Ordering::SeqCst);
        // Age of the current sync stage: "g16+43" = sitting at stage 16 for 43s,
        // i.e. blocked in the statement right after that marker.
        let ga = self.shared.sync_stage_at.load(Ordering::SeqCst);
        let gage = if ga == 0 { 0 } else { (now() as u32).saturating_sub(ga) };
        let c = self.shared.connected.load(Ordering::SeqCst) as u32;
        // f = frames fully processed : where the in-flight frame is (net.rs
        // frame_stage; a frozen ":2" = stuck inside Transport::handle_frame —
        // i.e. a hardware-crypto call hung while holding the transport lock).
        let f = self.shared.beat_frames.load(Ordering::SeqCst);
        let fs = self.shared.frame_stage.load(Ordering::SeqCst);
        // k = keepalive/watchdog heartbeat; w = seconds the current hub write
        // has been in flight (0 = none). k advancing while w grows past ~25 means
        // the watchdog's shutdown() cannot unblock a stuck write.
        let k = self.shared.beat_ka.load(Ordering::SeqCst);
        let ws = self.shared.write_started.load(Ordering::SeqCst);
        let w = if ws == 0 { 0 } else { (now() as u32).saturating_sub(ws) };
        // t = seconds the LAST completed Transport::handle_frame took — a direct
        // measurement of hardware-crypto (Ed25519/SHA engine) speed per frame.
        let t = self.shared.tspan.load(Ordering::SeqCst);
        self.chat.set_status_text(&format!(
            "sync requested… [s{s}/{sd} p{p} r{r} f{f}:{fs} t{t} g{g}+{gage} c{c} k{k} w{w}]"
        ));
    }

    /// Send an opportunistic LXMF message to the current peer.
    pub fn post(&mut self, text: &str) {
        let peer = match *self.shared.current_peer.lock().unwrap() {
            Some(p) => p,
            None => {
                self.chat.set_status_text("pick someone first (menu → Contacts)");
                return;
            }
        };
        // Direct delivery needs the peer's key. If we don't have it (e.g. we never
        // saw its announce on an access_point interface), ask for it and bail —
        // the reply arrives as an announce; the user retries in a moment.
        if self.shared.transport.lock().unwrap().known(&peer).is_none() {
            net::request_peer_key(&self.shared, &self.trng, &peer);
            self.chat.set_status_text("requesting peer's key… try again in a moment");
            return;
        }

        // Echo our own message FIRST, before the heavier sign + PDDB work below, so
        // the bubble appears the instant Enter is pressed (responsiveness). It gets
        // a "pending" mark; the delivery engine swaps it to ✓/⇪/×. Force the display
        // timestamp to the most recent slot so a wrong device clock can't bury it
        // above peers' (correctly-timestamped) messages.
        let display_ts = {
            let mut lt = self.shared.last_ts.lock().unwrap();
            let ts = now().max(*lt + 1);
            *lt = ts;
            ts
        };
        self.chat
            .post_add(chat::SELF_AUTHOR, display_ts, &net::bubble_text(text, net::MARK_PENDING), None)
            .ok();
        xous::send_message(
            self.chat_cid,
            xous::Message::new_scalar(chat::ChatOp::DialogueSave as usize, 0, 0, 0, 0),
        )
        .ok();

        // If this peer enforces a stamp cost but has trusted us with a ticket,
        // use it to stamp the message (no proof-of-work needed). Expired tickets
        // are dropped.
        let ticket = {
            let mut t = self.shared.tickets.lock().unwrap();
            match t.get(&peer) {
                Some((expiry, _)) if *expiry <= now() => {
                    t.remove(&peer);
                    None
                }
                Some((_, ticket)) => Some(*ticket),
                None => None,
            }
        };

        // Pack + sign the full LXMF message once. It's delivered as direct link
        // DATA (and re-wrapped for the propagation node if direct delivery fails).
        let packed = {
            let tp = self.shared.transport.lock().unwrap();
            lxmf::message::pack(
                tp.identity(),
                &peer,
                &self.shared.our_dh,
                now() as f64,
                b"",
                text.as_bytes(),
                &lxmf::message::Fields::new(),
                ticket.as_ref(),
            )
            .packed
        };

        // Messaging someone saves them to contacts.
        let name = self
            .shared
            .contacts
            .lock()
            .unwrap()
            .get(&peer)
            .cloned()
            .or_else(|| self.shared.seen.lock().unwrap().get(&peer).map(|(n, _)| n.clone()))
            .unwrap_or_else(|| hex(&peer));
        save_contact(&self.shared, &self.pddb, &peer, &name);

        // Hand off to the delivery engine: direct link first, propagation fallback.
        net::enqueue_outbound(
            &self.shared,
            self.chat_cid,
            &self.pddb,
            &self.trng,
            peer,
            display_ts,
            text.to_string(),
            packed,
        );
    }

    /// Present `entries` as a radio list and return the chosen (addr, name).
    fn pick_peer(
        &self,
        modals: &modals::Modals,
        entries: Vec<([u8; TRUNCATED_HASHLENGTH], String)>,
        prompt: &str,
        empty_msg: &str,
    ) -> Option<([u8; TRUNCATED_HASHLENGTH], String)> {
        if entries.is_empty() {
            modals.show_notification(empty_msg, None).ok();
            return None;
        }
        // First item is a cancel/back option so the list can always be dismissed.
        // "name (abcd1234)" — name plus the first 4 bytes of the address.
        let mut labels: Vec<String> = Vec::with_capacity(entries.len() + 1);
        labels.push(String::from(CANCEL_LABEL));
        labels.extend(entries.iter().map(|(h, n)| format!("{} ({})", n, hex(&h[..4]))));
        modals.add_list(labels.iter().map(|s| s.as_str()).collect()).ok();
        match modals.get_radiobutton(prompt) {
            Ok(choice) if choice != CANCEL_LABEL => {
                // index 0 is cancel, so entries are offset by one
                labels.iter().position(|l| *l == choice).filter(|&i| i > 0).map(|i| entries[i - 1].clone())
            }
            _ => None,
        }
    }

    /// Make `addr` the active conversation: set it as the send target, persist
    /// it as the "last peer", and switch the chat UI to that peer's own thread.
    fn activate_peer(&self, addr: &[u8; TRUNCATED_HASHLENGTH]) {
        *self.shared.current_peer.lock().unwrap() = Some(*addr);
        write_string(&self.pddb, KEY_PEER, &hex(addr));
        self.chat.dialogue_set(DIALOGUE_DICT, Some(&hex(addr))).ok();
        // Flush messages that arrived for this peer while we were viewing someone
        // else, into the now-active thread, and clear its unread badge.
        let queued = self.shared.pending.lock().unwrap().remove(addr).unwrap_or_default();
        let had_queued = !queued.is_empty();
        for (author, ts, text) in queued {
            {
                let mut lt = self.shared.last_ts.lock().unwrap();
                *lt = (*lt).max(ts);
            }
            self.chat.post_add(&author, ts, &text, None).ok();
        }
        self.shared.unread.lock().unwrap().remove(addr);
        if had_queued {
            delete_pending(&self.pddb, addr);
            xous::send_message(
                self.chat_cid,
                xous::Message::new_scalar(ChatOp::DialogueSave as usize, 0, 0, 0, 0),
            )
            .ok();
        }
        // Apply any delivery-mark updates (✓/⇪/✗) that landed for this thread while
        // it wasn't the active one — now that it's open, swap the bubbles.
        net::apply_delivery_updates(&self.shared, self.chat_cid, &self.pddb, addr);
        // Show who this conversation is with in the status bar (persists while
        // idle), so it's always clear which thread you're in.
        let label = format!("\u{25c9} {}", self.peer_name(addr));
        self.chat.set_status_idle_text(&label);
        self.chat.set_status_text(&label);
    }

    /// Best human-readable name for a peer: a saved contact / announced display
    /// name, falling back to a short prefix of its address hash.
    fn peer_name(&self, addr: &[u8; TRUNCATED_HASHLENGTH]) -> String {
        self.shared
            .contacts
            .lock()
            .unwrap()
            .get(addr)
            .cloned()
            .or_else(|| self.shared.seen.lock().unwrap().get(addr).map(|(n, _)| n.clone()))
            .unwrap_or_else(|| format!("{}…", &hex(addr)[..8]))
    }

    /// Browse the live directory of seen announces; picking one opens that
    /// peer's thread and saves the peer to your contacts.
    pub fn show_announces_interactive(&mut self, modals: &modals::Modals) {
        // Collect, then show the most-recently-seen first, capped to a sane length.
        let mut all: Vec<([u8; TRUNCATED_HASHLENGTH], String, u64)> = {
            self.shared.seen.lock().unwrap().iter().map(|(k, (n, t))| (*k, n.clone(), *t)).collect()
        };
        all.sort_by(|a, b| b.2.cmp(&a.2));
        all.truncate(ANNOUNCE_LIST_MAX);
        let entries: Vec<_> = all.into_iter().map(|(h, n, _)| (h, n)).collect();
        if let Some((addr, name)) =
            self.pick_peer(modals, entries, "Message who?", "No LXMF announces seen yet — Connect and wait.")
        {
            self.activate_peer(&addr);
            save_contact(&self.shared, &self.pddb, &addr, &name);
            self.chat.set_status_text(&format!("messaging {}", name));
        }
    }

    /// Pick from your saved contacts (people you've messaged or who've messaged
    /// you). Persisted across reboots; opens that peer's thread.
    pub fn message_contact_interactive(&mut self, modals: &modals::Modals) {
        let unread = self.shared.unread.lock().unwrap().clone();
        let mut entries: Vec<_> =
            { self.shared.contacts.lock().unwrap().iter().map(|(k, v)| (*k, v.clone())).collect() };
        // Contacts with unread messages float to the top of the list.
        entries.sort_by(|a, b| {
            let (ua, ub) = (unread.get(&a.0).copied().unwrap_or(0), unread.get(&b.0).copied().unwrap_or(0));
            ub.cmp(&ua).then_with(|| a.1.to_lowercase().cmp(&b.1.to_lowercase()))
        });
        // Annotate names with an unread badge, e.g. "alice [3]".
        let entries: Vec<_> = entries
            .into_iter()
            .map(|(h, n)| match unread.get(&h).copied().unwrap_or(0) {
                0 => (h, n),
                u => (h, format!("{} [{}]", n, u)),
            })
            .collect();
        if let Some((addr, name)) =
            self.pick_peer(modals, entries, "Message who?", "No saved contacts yet — use Announces to find peers.")
        {
            self.activate_peer(&addr);
            self.chat.set_status_text(&format!("messaging {}", name));
        }
    }

    /// Wipe the message history of the currently-open conversation, after a
    /// confirmation. The contact, its key, and any stamp ticket are kept — only
    /// the posts (and any queued/undelivered state for this thread) are removed.
    pub fn clear_history_interactive(&mut self, modals: &modals::Modals) {
        // The active thread is the current peer's, or the welcome thread if none.
        let peer = *self.shared.current_peer.lock().unwrap();
        let (key, label) = match peer {
            Some(addr) => (hex(&addr), self.peer_name(&addr)),
            None => (DIALOGUE_WELCOME.to_string(), "this thread".to_string()),
        };

        // Confirm — wiping is irreversible.
        modals
            .add_list(vec![CANCEL_LABEL, "Clear history"])
            .ok();
        let confirmed = matches!(
            modals.get_radiobutton(&format!("Wipe all messages with {}?", label)),
            Ok(choice) if choice == "Clear history"
        );
        if !confirmed {
            return;
        }

        // 1. Drop the persisted dialogue, then re-point the chat UI at the (now
        //    missing) key so it loads a fresh, empty thread and redraws.
        self.pddb.delete_key(DIALOGUE_DICT, &key, None).ok();
        self.pddb.sync().ok();
        self.chat.dialogue_set(DIALOGUE_DICT, Some(&key)).ok();

        // 2. Clear this thread's queued/undelivered state so nothing repopulates
        //    it: held inbound messages, unread badge, deferred delivery marks, and
        //    any in-flight outbound entries. (Contact + ticket are left intact.)
        if let Some(addr) = peer {
            self.shared.pending.lock().unwrap().remove(&addr);
            self.shared.unread.lock().unwrap().remove(&addr);
            self.shared.delivery_updates.lock().unwrap().remove(&addr);
            self.shared.outbox.lock().unwrap().retain(|m| m.peer != addr);
            delete_pending(&self.pddb, &addr);
            delete_delivery_updates(&self.pddb, &addr);
        }

        self.chat.set_status_text(&format!("cleared history with {}", label));
    }

    /// Fallback: manually set the peer by pasting a 32-hex LXMF address.
    pub fn set_peer_interactive(&mut self, modals: &modals::Modals) {
        match modals
            .alert_builder("Peer LXMF address (32 hex)")
            .field(None, None)
            .build()
        {
            Ok(p) => {
                let s = p.first().as_str().trim().to_string();
                match parse_addr(&s) {
                    Some(addr) => {
                        self.activate_peer(&addr);
                        self.chat.set_status_text(&format!("peer set: {}", &s));
                    }
                    None => self.chat.set_status_text("invalid address (need 32 hex chars)"),
                }
            }
            Err(_) => {}
        }
    }

    /// Prompt for and store the hub address. Host and port are taken as two
    /// separate fields so no `:` needs to be typed (some keyboard layouts can't
    /// enter a colon). Port defaults to 4242 if left blank.
    pub fn set_hub_interactive(&mut self, modals: &modals::Modals) {
        let (cur_host, cur_port) = match self.hub.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => (self.hub.clone(), String::from("4242")),
        };
        // Plain hint placeholders (cleared on first keystroke); leaving a field
        // blank keeps the current value, so you can change just one of them.
        match modals
            .alert_builder("Hub host/IP, then port (blank = keep)")
            .field(Some(cur_host.clone()), None)
            .field(Some(cur_port.clone()), None)
            .build()
        {
            Ok(p) => {
                let c = p.content();
                let host_in = c.first().map(|f| f.as_str().trim().to_string()).unwrap_or_default();
                let port_in = c.get(1).map(|f| f.as_str().trim().to_string()).unwrap_or_default();
                let host_in = if host_in.is_empty() { cur_host.clone() } else { host_in };
                let port_in = if port_in.is_empty() { cur_port.clone() } else { port_in };
                // Tolerate a full "host:port" typed into the host field.
                let (host, port) = match host_in.rsplit_once(':') {
                    Some((h, p)) => (h.to_string(), p.to_string()),
                    None => (host_in, port_in),
                };
                let port_ok = port.parse::<u16>().map(|n| n > 0).unwrap_or(false);
                if host.is_empty() {
                    self.chat.set_status_text("invalid hub: host is empty");
                } else if !port_ok {
                    self.chat.set_status_text(&format!("invalid hub: '{}' is not a valid port", port));
                } else {
                    let hub = format!("{}:{}", host, port);
                    self.hub = hub.clone();
                    write_string(&self.pddb, KEY_HUB, &hub);
                    self.chat.set_status_text(&format!("hub set: {} — now Connect", &hub));
                }
            }
            Err(_) => {}
        }
    }

    /// Send a raw packet to the hub from the MAIN (UI) thread. Routed through
    /// `net::write_to_hub`, whose bounded mutex wait + stuck-write watchdog mean
    /// this can delay the UI a couple of seconds at worst, never freeze it.
    fn write_framed(&self, raw: &[u8]) -> bool {
        if !self.shared.connected.load(core::sync::atomic::Ordering::SeqCst) {
            self.chat.set_status_text("not connected (menu → Connect)");
            return false;
        }
        if net::write_to_hub(&self.shared, raw) {
            true
        } else {
            self.chat.set_status_text("send failed (connection resetting…)");
            false
        }
    }
}

fn parse_addr(s: &str) -> Option<[u8; TRUNCATED_HASHLENGTH]> {
    let s = s.trim();
    if s.len() != TRUNCATED_HASHLENGTH * 2 {
        return None;
    }
    let mut out = [0u8; TRUNCATED_HASHLENGTH];
    for i in 0..TRUNCATED_HASHLENGTH {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn load_or_create_identity(pddb: &Pddb, trng: &Trng) -> [u8; KEYSIZE] {
    // Try to read an existing identity.
    if let Ok(mut key) = pddb.get(PDDB_DICT, KEY_IDENTITY, None, true, false, Some(KEYSIZE), None::<fn()>) {
        let mut buf = [0u8; KEYSIZE];
        if let Ok(KEYSIZE) = key.read(&mut buf) {
            return buf;
        }
    }
    // Otherwise generate and persist a new one.
    let mut id = [0u8; KEYSIZE];
    fill_random(trng, &mut id);
    if let Ok(mut key) = pddb.get(PDDB_DICT, KEY_IDENTITY, None, true, true, Some(KEYSIZE), None::<fn()>) {
        key.write(&id).ok();
        pddb.sync().ok();
    }
    id
}

fn read_string(pddb: &Pddb, key: &str) -> Option<String> {
    match pddb.get(PDDB_DICT, key, None, true, false, None, None::<fn()>) {
        Ok(mut k) => {
            let mut buf = Vec::new();
            match k.read_to_end(&mut buf) {
                Ok(_) if !buf.is_empty() => String::from_utf8(buf).ok(),
                _ => None,
            }
        }
        Err(_) => None,
    }
}

fn write_string(pddb: &Pddb, key: &str, value: &str) {
    pddb.delete_key(PDDB_DICT, key, None).ok();
    if let Ok(mut k) = pddb.get(PDDB_DICT, key, None, true, true, Some(value.len()), None::<fn()>) {
        k.write(value.as_bytes()).ok();
        pddb.sync().ok();
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Persist a contact under the contacts dict, keyed by hex(dest_hash).
/// Value layout (NUL-separated): `name [\0 pubkey_hex(128) [\0 ratchet_hex(64)]]`.
/// The key may be absent — someone can message us before we have their key (the
/// normal case on an access_point interface); we still want them listed, and the
/// key is filled in later when their announce/path-response arrives.
pub(crate) fn persist_contact(
    pddb: &Pddb,
    dest_hash: &[u8; TRUNCATED_HASHLENGTH],
    name: &str,
    pubkey: Option<&[u8; KEYSIZE]>,
    ratchet: Option<&[u8; RATCHET_SIZE]>,
) {
    let mut val = String::new();
    val.push_str(name);
    if let Some(pk) = pubkey {
        val.push('\u{0}');
        val.push_str(&reticulum_core::hex(pk));
        if let Some(r) = ratchet {
            val.push('\u{0}');
            val.push_str(&reticulum_core::hex(r));
        }
    }
    let key = reticulum_core::hex(dest_hash);
    pddb.delete_key(CONTACTS_DICT, &key, None).ok();
    if let Ok(mut k) = pddb.get(CONTACTS_DICT, &key, None, true, true, Some(val.len()), None::<fn()>) {
        k.write(val.as_bytes()).ok();
        pddb.sync().ok();
    }
}

/// Length-prefixed encoding of held messages: per record `ts(8 BE) ||
/// author_len(4 BE) || author || text_len(4 BE) || text`. Robust to any bytes in
/// the author/text (unlike a delimiter-based scheme).
fn serialize_pending(msgs: &[(String, u64, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (author, ts, text) in msgs {
        out.extend_from_slice(&ts.to_be_bytes());
        out.extend_from_slice(&(author.len() as u32).to_be_bytes());
        out.extend_from_slice(author.as_bytes());
        out.extend_from_slice(&(text.len() as u32).to_be_bytes());
        out.extend_from_slice(text.as_bytes());
    }
    out
}

fn deserialize_pending(buf: &[u8]) -> Vec<(String, u64, String)> {
    fn read_u64(b: &[u8]) -> u64 {
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        u64::from_be_bytes(a)
    }
    fn read_u32(b: &[u8]) -> usize {
        let mut a = [0u8; 4];
        a.copy_from_slice(b);
        u32::from_be_bytes(a) as usize
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + 12 <= buf.len() {
        let ts = read_u64(&buf[i..i + 8]);
        i += 8;
        let alen = read_u32(&buf[i..i + 4]);
        i += 4;
        if i + alen + 4 > buf.len() {
            break;
        }
        let author = String::from_utf8_lossy(&buf[i..i + alen]).into_owned();
        i += alen;
        let tlen = read_u32(&buf[i..i + 4]);
        i += 4;
        if i + tlen > buf.len() {
            break;
        }
        let text = String::from_utf8_lossy(&buf[i..i + tlen]).into_owned();
        i += tlen;
        out.push((author, ts, text));
    }
    out
}

/// Write a contact's full held-message list to the PDDB (empty list deletes the
/// key). Called from the network thread each time a message is held.
pub(crate) fn persist_pending(
    pddb: &Pddb,
    dest_hash: &[u8; TRUNCATED_HASHLENGTH],
    msgs: &[(String, u64, String)],
) {
    let key = reticulum_core::hex(dest_hash);
    pddb.delete_key(PENDING_DICT, &key, None).ok();
    if !msgs.is_empty() {
        let val = serialize_pending(msgs);
        if let Ok(mut k) = pddb.get(PENDING_DICT, &key, None, true, true, Some(val.len()), None::<fn()>) {
            k.write(&val).ok();
        }
    }
    pddb.sync().ok();
}

/// Drop a contact's held messages from the PDDB (after they've been flushed into
/// the thread on open).
pub(crate) fn delete_pending(pddb: &Pddb, dest_hash: &[u8; TRUNCATED_HASHLENGTH]) {
    pddb.delete_key(PENDING_DICT, &reticulum_core::hex(dest_hash), None).ok();
    pddb.sync().ok();
}

/// Load persisted held messages + their unread counts at startup.
fn load_pending(
    pddb: &Pddb,
    pending: &mut BTreeMap<[u8; TRUNCATED_HASHLENGTH], Vec<(String, u64, String)>>,
    unread: &mut BTreeMap<[u8; TRUNCATED_HASHLENGTH], u32>,
) {
    let keys = match pddb.list_keys(PENDING_DICT, None) {
        Ok(k) => k,
        Err(_) => return,
    };
    for key in keys {
        let dh = match parse_addr(&key) {
            Some(d) => d,
            None => continue,
        };
        let mut buf = Vec::new();
        if let Ok(mut k) = pddb.get(PENDING_DICT, &key, None, false, false, None, None::<fn()>) {
            if k.read_to_end(&mut buf).is_err() {
                continue;
            }
        } else {
            continue;
        }
        let msgs = deserialize_pending(&buf);
        if !msgs.is_empty() {
            unread.insert(dh, msgs.len() as u32);
            pending.insert(dh, msgs);
        }
    }
}

/// Persist an outbound ticket for `dest_hash`. Value: `expiry(8 BE) || ticket(16)`.
pub(crate) fn persist_ticket(
    pddb: &Pddb,
    dest_hash: &[u8; TRUNCATED_HASHLENGTH],
    expiry: u64,
    ticket: &[u8; TRUNCATED_HASHLENGTH],
) {
    let mut val = Vec::with_capacity(8 + ticket.len());
    val.extend_from_slice(&expiry.to_be_bytes());
    val.extend_from_slice(ticket);
    let key = reticulum_core::hex(dest_hash);
    pddb.delete_key(TICKETS_DICT, &key, None).ok();
    if let Ok(mut k) = pddb.get(TICKETS_DICT, &key, None, true, true, Some(val.len()), None::<fn()>) {
        k.write(&val).ok();
        pddb.sync().ok();
    }
}

/// Load persisted outbound tickets at startup, skipping any that have expired.
fn load_tickets(
    pddb: &Pddb,
    tickets: &mut BTreeMap<[u8; TRUNCATED_HASHLENGTH], (u64, [u8; TRUNCATED_HASHLENGTH])>,
) {
    let keys = match pddb.list_keys(TICKETS_DICT, None) {
        Ok(k) => k,
        Err(_) => return,
    };
    let now = now();
    for key in keys {
        let dh = match parse_addr(&key) {
            Some(d) => d,
            None => continue,
        };
        let mut buf = Vec::new();
        if let Ok(mut k) = pddb.get(TICKETS_DICT, &key, None, false, false, None, None::<fn()>) {
            if k.read_to_end(&mut buf).is_err() || buf.len() != 8 + TRUNCATED_HASHLENGTH {
                continue;
            }
        } else {
            continue;
        }
        let mut eb = [0u8; 8];
        eb.copy_from_slice(&buf[..8]);
        let expiry = u64::from_be_bytes(eb);
        if expiry <= now {
            pddb.delete_key(TICKETS_DICT, &key, None).ok();
            continue;
        }
        let mut ticket = [0u8; TRUNCATED_HASHLENGTH];
        ticket.copy_from_slice(&buf[8..]);
        tickets.insert(dh, (expiry, ticket));
    }
}

/// Persist a contact's held delivery-mark updates. Per record:
/// `display_ts(8 BE) || status(1) || text_len(4 BE) || text`. Empty list deletes.
pub(crate) fn persist_delivery_updates(
    pddb: &Pddb,
    peer: &[u8; TRUNCATED_HASHLENGTH],
    updates: &[net::DeliveryUpdate],
) {
    let key = reticulum_core::hex(peer);
    pddb.delete_key(DELIVERY_DICT, &key, None).ok();
    if !updates.is_empty() {
        let mut val = Vec::new();
        for u in updates {
            val.extend_from_slice(&u.display_ts.to_be_bytes());
            val.push(u.status);
            val.extend_from_slice(&(u.text.len() as u32).to_be_bytes());
            val.extend_from_slice(u.text.as_bytes());
        }
        if let Ok(mut k) = pddb.get(DELIVERY_DICT, &key, None, true, true, Some(val.len()), None::<fn()>) {
            k.write(&val).ok();
        }
    }
    pddb.sync().ok();
}

/// Drop a contact's held delivery-mark updates (after they've been applied).
pub(crate) fn delete_delivery_updates(pddb: &Pddb, peer: &[u8; TRUNCATED_HASHLENGTH]) {
    pddb.delete_key(DELIVERY_DICT, &reticulum_core::hex(peer), None).ok();
    pddb.sync().ok();
}

/// Load held delivery-mark updates at startup.
fn load_delivery_updates(
    pddb: &Pddb,
    map: &mut BTreeMap<[u8; TRUNCATED_HASHLENGTH], Vec<net::DeliveryUpdate>>,
) {
    let keys = match pddb.list_keys(DELIVERY_DICT, None) {
        Ok(k) => k,
        Err(_) => return,
    };
    for key in keys {
        let dh = match parse_addr(&key) {
            Some(d) => d,
            None => continue,
        };
        let mut buf = Vec::new();
        if let Ok(mut k) = pddb.get(DELIVERY_DICT, &key, None, false, false, None, None::<fn()>) {
            if k.read_to_end(&mut buf).is_err() {
                continue;
            }
        } else {
            continue;
        }
        let mut out = Vec::new();
        let mut i = 0;
        while i + 13 <= buf.len() {
            let mut ts8 = [0u8; 8];
            ts8.copy_from_slice(&buf[i..i + 8]);
            let display_ts = u64::from_be_bytes(ts8);
            i += 8;
            let status = buf[i];
            i += 1;
            let mut l4 = [0u8; 4];
            l4.copy_from_slice(&buf[i..i + 4]);
            let tlen = u32::from_be_bytes(l4) as usize;
            i += 4;
            if i + tlen > buf.len() {
                break;
            }
            let text = String::from_utf8_lossy(&buf[i..i + tlen]).into_owned();
            i += tlen;
            out.push(net::DeliveryUpdate { display_ts, text, status });
        }
        if !out.is_empty() {
            map.insert(dh, out);
        }
    }
}

/// The 10-byte name hash of the LXMF delivery aspect, used to filter announces
/// down to messageable LXMF peers (vs propagation nodes / other apps).
pub(crate) fn lxmf_delivery_name_hash() -> [u8; NAME_HASH_LENGTH] {
    reticulum_core::destination::name_hash("lxmf", &["delivery"])
}

/// Extract a peer's display name from an LXMF delivery announce's app_data.
/// v0.5.0+ format is msgpack `[display_name, stamp_cost, supported]`; older
/// announces carry the raw UTF-8 name. Returns None if there's no usable name.
pub(crate) fn lxmf_display_name(app_data: &[u8]) -> Option<String> {
    if app_data.is_empty() {
        return None;
    }
    let b0 = app_data[0];
    let raw = if (0x90..=0x9f).contains(&b0) || b0 == 0xdc {
        match lxmf::msgpack::decode(app_data) {
            Ok(lxmf::msgpack::Value::Array(arr)) => match arr.into_iter().next() {
                Some(lxmf::msgpack::Value::Bin(b)) => String::from_utf8_lossy(&b).into_owned(),
                Some(lxmf::msgpack::Value::Str(s)) => s,
                _ => return None,
            },
            _ => return None,
        }
    } else {
        String::from_utf8_lossy(app_data).into_owned()
    };
    let trimmed = raw.replace('\u{0}', "").trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

/// Save a peer to the contact list. Always lists them (anyone who messages us
/// becomes a contact, even before we have their key); the persisted record
/// includes the public key if we have it, so they're messageable across a
/// restart, and is upgraded later (when their announce/path-response arrives) if
/// not.
pub(crate) fn save_contact(
    shared: &Shared,
    pddb: &Pddb,
    dest_hash: &[u8; TRUNCATED_HASHLENGTH],
    name: &str,
) {
    shared.contacts.lock().unwrap().insert(*dest_hash, name.to_string());
    let key_material = {
        let tp = shared.transport.lock().unwrap();
        tp.known(dest_hash).map(|k| (k.identity.public_key(), k.ratchet))
    };
    match key_material {
        Some((pubkey, ratchet)) => persist_contact(pddb, dest_hash, name, Some(&pubkey), ratchet.as_ref()),
        None => persist_contact(pddb, dest_hash, name, None, None),
    }
}

/// Load persisted contacts into the transport (so they are messageable) and a
/// display-name map (so they are listable), at startup.
fn load_contacts(
    pddb: &Pddb,
    transport: &mut Transport,
    contacts: &mut BTreeMap<[u8; TRUNCATED_HASHLENGTH], String>,
) {
    let keys = match pddb.list_keys(CONTACTS_DICT, None) {
        Ok(k) => k,
        Err(_) => return, // dict may not exist yet
    };
    for key in keys {
        let dh = match parse_addr(&key) {
            Some(d) => d,
            None => continue,
        };
        let mut buf = Vec::new();
        match pddb.get(CONTACTS_DICT, &key, None, false, false, None, None::<fn()>) {
            Ok(mut k) => {
                if k.read_to_end(&mut buf).is_err() {
                    continue;
                }
            }
            Err(_) => continue,
        }
        let s = String::from_utf8_lossy(&buf).into_owned();
        let mut parts = s.split('\u{0}');
        let name = parts.next().unwrap_or("").to_string();
        let pubkey = parts.next().and_then(unhex).filter(|p| p.len() == KEYSIZE);
        match pubkey {
            Some(pubkey) => {
                let ratchet: Option<[u8; RATCHET_SIZE]> = parts
                    .next()
                    .and_then(unhex)
                    .and_then(|r| <[u8; RATCHET_SIZE]>::try_from(r.as_slice()).ok());
                if let Ok(identity) = PublicIdentity::from_public_key(&pubkey) {
                    transport.remember(
                        dh,
                        KnownDest {
                            identity,
                            name_hash: [0u8; NAME_HASH_LENGTH],
                            ratchet,
                            app_data: name.as_bytes().to_vec(),
                        },
                    );
                    contacts.insert(dh, name);
                }
            }
            // Keyless contact (messaged us before we had their key): list it.
            // Messaging will trigger a path request to (re)learn the key.
            None => {
                contacts.insert(dh, name);
            }
        }
    }
}
