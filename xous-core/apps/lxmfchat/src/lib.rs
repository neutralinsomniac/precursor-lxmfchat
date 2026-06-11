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

use chat::{Chat, ChatOp};
use pddb::Pddb;
use reticulum_core::constants::{KEY_HALF, KEYSIZE, NAME_HASH_LENGTH, RATCHET_SIZE, TRUNCATED_HASHLENGTH};
use reticulum_core::destination::single_destination_hash;
use reticulum_core::identity::{PrivateIdentity, PublicIdentity};
use reticulum_core::transport::{KnownDest, Transport};
use trng::Trng;
use xous::CID;
use xous_names::XousNames;

pub use net::Shared;
use net::plock;

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
/// Saved NomadNet nodes for the page browser: key = hex dest hash, value = name.
const NODES_DICT: &str = "lxmf.nodes";
const KEY_IDENTITY: &str = "identity";
const KEY_HUB: &str = "hub";
const KEY_PEER: &str = "peer";
/// PDDB key for our announced display name.
const KEY_NAME: &str = "name";
/// Display name announced when none has been set yet.
const DEFAULT_DISPLAY_NAME: &str = "precursor";
/// Sanity cap on the announced name (it travels in every announce packet).
const DISPLAY_NAME_MAX: usize = 32;
/// Each contact gets its own dialogue (scrollback) stored under this dict,
/// keyed by the hex of its destination hash. `DIALOGUE_WELCOME` is shown before
/// any peer is selected.
pub(crate) const DIALOGUE_DICT: &str = "lxmf.dialogue";
const DIALOGUE_WELCOME: &str = "welcome";

/// Cap the Announces picker to a length the modal can comfortably show.
const ANNOUNCE_LIST_MAX: usize = 32;
/// First entry in peer pickers, lets the user back out without choosing.
/// Matching the gam sentinel makes the F3 key choose it (radio modals treat
/// F3 as "cancel" when an item carries exactly this label).
const CANCEL_LABEL: &str = gam::modal::CANCEL_SENTINEL;

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

        // Restore the saved NomadNet nodes for the page browser.
        let mut saved_nodes_map = BTreeMap::new();
        load_nodes(&pddb, &mut saved_nodes_map);

        let hub = read_string(&pddb, KEY_HUB).unwrap_or_else(|| DEFAULT_HUB.to_string());
        let current_peer = read_string(&pddb, KEY_PEER).and_then(|s| parse_addr(&s));
        let display_name =
            read_string(&pddb, KEY_NAME).unwrap_or_else(|| DEFAULT_DISPLAY_NAME.to_string());

        let chat_cid = chat.cid();
        let shared = Arc::new(Shared {
            transport: Mutex::new(transport),
            writer: Mutex::new(None),
            connected: core::sync::atomic::AtomicBool::new(false),
            ctl: Mutex::new(None),
            write_started: core::sync::atomic::AtomicU32::new(0),
            last_inbound: core::sync::atomic::AtomicU32::new(0),
            our_dh,
            display_name: Mutex::new(display_name),
            dialogue_id: DIALOGUE_WELCOME.to_string(),
            seen: Mutex::new(BTreeMap::new()),
            contacts: Mutex::new(contacts_map),
            current_peer: Mutex::new(current_peer),
            prev_peer: Mutex::new(None),
            recent_msg_ids: Mutex::new(Vec::new()),
            last_ts: Mutex::new(0),
            sync: Mutex::new(net::SyncState::new()),
            nodes_seen: Mutex::new(BTreeMap::new()),
            saved_nodes: Mutex::new(saved_nodes_map),
            browser: Mutex::new(net::BrowserState::new()),
            in_resources: Mutex::new(BTreeMap::new()),
            stamp_costs: Mutex::new(BTreeMap::new()),
            found_addrs: Mutex::new(load_found_addrs(&pddb)),
            backchannels: Mutex::new(BTreeMap::new()),
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
        // F3 is a fixed action; F1/F2 labels are kept current by
        // refresh_idle_status. Unread badges were restored from the PDDB, so
        // surface the F1 jump hint right away.
        chat::cf_icontray_set(chat_cid, 2, "sync");
        net::refresh_idle_status(&shared, chat_cid);

        // One-shot crypto self-test + sign/verify timing, LOG-ONLY (it posted a
        // chat message to the welcome thread during the hardware-crypto
        // debugging; the device baselines are recorded — x25519/token/hkdf OK,
        // sign(sw) ~550 ms, verify(sw) ~1.1 s vs 3.2 s / ~30 s on the engine).
        let st = reticulum_core::self_test();
        let st = {
            let t0 = std::time::Instant::now();
            let sig = plock(&shared.transport).identity().sign(b"selftest timing");
            let sign_ms = t0.elapsed().as_millis();
            let pubid = plock(&shared.transport).identity().public().clone();
            let t1 = std::time::Instant::now();
            let ok = pubid.validate(&sig, b"selftest timing");
            let verify_ms = t1.elapsed().as_millis();
            format!("{st} sign(sw):{sign_ms}ms verify(sw):{verify_ms}ms:{}", if ok { "OK" } else { "FAIL" })
        };
        log::info!("crypto self-test: {}", st);

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
        *plock(&self.shared.hub) = self.hub.clone();
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
            // And one for the node page browser, for the same reason.
            let browse = self.shared.clone();
            let browse_cid = self.chat_cid;
            std::thread::spawn(move || net::browser_thread(browse, browse_cid));
            return;
        }
        // Manager already running: force the connection down so it reconnects
        // to the (possibly newly-set) hub. If already disconnected it's
        // mid-backoff and will pick up the new hub on its next attempt.
        net::force_reconnect(&self.shared, self.chat_cid, &format!("reconnecting to {}…", self.hub));
    }

    /// Announce our lxmf.delivery destination on the hub.
    pub fn announce(&mut self) {
        let mut r5 = [0u8; 5];
        fill_random(&self.trng, &mut r5);
        let name = plock(&self.shared.display_name).clone();
        let raw = {
            let tp = plock(&self.shared.transport);
            tp.make_announce_with("lxmf", &["delivery"], name.as_bytes(), &r5, now())
        };
        if self.write_framed(&raw) {
            self.chat.set_status_text(&format!("announced as {name}"));
        }
    }

    /// Prompt for and store the display name we announce (what peers see in
    /// their announce/contact lists). Persisted; takes effect immediately with
    /// a fresh announce. Note peers who already saved us keep whatever name
    /// they saved until their client updates it from the new announce.
    pub fn set_name_interactive(&mut self, modals: &modals::Modals) {
        let current = plock(&self.shared.display_name).clone();
        match modals.alert_builder("Announced name").field(Some(current.clone()), None).build() {
            Ok(p) => {
                let mut name = p.first().as_str().trim().to_string();
                name.truncate(DISPLAY_NAME_MAX);
                if name.is_empty() || name == current {
                    return;
                }
                *plock(&self.shared.display_name) = name.clone();
                write_string(&self.pddb, KEY_NAME, &name);
                if self.shared.connected.load(core::sync::atomic::Ordering::SeqCst) {
                    self.announce(); // tell the network right away
                } else {
                    self.chat.set_status_text(&format!("name set: {name} (announced on connect)"));
                }
            }
            Err(_) => {}
        }
    }

    /// Download messages stored for us at the configured propagation node. Only
    /// flags the request — the pump thread does the actual link + hub writes, so
    /// this returns immediately and never blocks the UI on a hub write.
    pub fn sync_now(&self) {
        net::request_sync(&self.shared);
        self.chat.set_status_text("sync requested…");
    }

    /// Send an opportunistic LXMF message to the current peer.
    pub fn post(&mut self, text: &str) {
        // The input line still works while a page is on screen, but a "send"
        // there is almost certainly a mistake — the conversation isn't visible.
        if self.browsing() {
            self.chat.set_status_text("exit the browser first (F3) to send messages");
            return;
        }
        let peer = match *plock(&self.shared.current_peer) {
            Some(p) => p,
            None => {
                self.chat.set_status_text("pick someone first (menu → Contacts)");
                return;
            }
        };
        // NOTE: the peer's key is NOT required here. A message to a peer whose
        // key we don't have yet still enqueues (and echoes a ○ bubble); the
        // delivery engine requests the key, sends the moment the announce
        // arrives, and fails visibly ("no route found") if it never does. An
        // earlier version bailed out here — silently eating the typed message.

        // Echo our own message FIRST, before the heavier sign + PDDB work below, so
        // the bubble appears the instant Enter is pressed (responsiveness). It gets
        // a "pending" mark; the delivery engine swaps it to ✓/⇪/×. Force the display
        // timestamp to the most recent slot so a wrong device clock can't bury it
        // above peers' (correctly-timestamped) messages.
        let display_ts = {
            let mut lt = plock(&self.shared.last_ts);
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
            let mut t = plock(&self.shared.tickets);
            match t.get(&peer) {
                Some((expiry, _)) if *expiry <= now() => {
                    t.remove(&peer);
                    None
                }
                Some((_, ticket)) => Some(*ticket),
                None => None,
            }
        };

        // No ticket but the peer's announce demands a stamp cost? The message
        // then needs a mined proof-of-work stamp. Mining takes seconds (or
        // minutes for high costs) so it happens on the PUMP thread, never
        // here on the UI thread — the message is enqueued unstamped and held
        // until the stamp is appended (see net::compute_pending_delivery_stamp).
        let needs_stamp = if ticket.is_some() {
            None
        } else {
            plock(&self.shared.stamp_costs).get(&peer).copied()
        };

        // Pack + sign the full LXMF message once. It's delivered as direct link
        // DATA (and re-wrapped for the propagation node if direct delivery fails).
        let packed = {
            let tp = plock(&self.shared.transport);
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
            .or_else(|| plock(&self.shared.seen).get(&peer).map(|(n, _)| n.clone()))
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
            needs_stamp,
            ticket.is_some(),
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
        self.show_picker_fkey_hints();
        let choice = modals.get_radiobutton(prompt);
        self.restore_fkey_hints();
        match choice {
            Ok(choice) if choice != CANCEL_LABEL => {
                // index 0 is cancel, so entries are offset by one
                labels.iter().position(|l| *l == choice).filter(|&i| i > 0).map(|i| entries[i - 1].clone())
            }
            _ => None,
        }
    }

    /// Relabel the F-key tray with what the keys do inside a radio-list modal
    /// (F2 picks the highlighted item, F3 cancels; F1 does nothing there).
    /// Must run BEFORE the modal is raised: the tray only repaints while the
    /// chat context still has focus. Pair with `restore_fkey_hints`.
    fn show_picker_fkey_hints(&self) {
        chat::cf_icontray_set(self.chat_cid, 0, "");
        chat::cf_icontray_set(self.chat_cid, 1, "okay");
        chat::cf_icontray_set(self.chat_cid, 2, "cancel");
    }

    /// Put the chat-view F-key labels back once a modal has closed.
    fn restore_fkey_hints(&self) {
        chat::cf_icontray_set(self.chat_cid, 2, "sync");
        net::refresh_idle_status(&self.shared, self.chat_cid);
    }

    /// Make `addr` the active conversation: set it as the send target, persist
    /// it as the "last peer", and switch the chat UI to that peer's own thread.
    fn activate_peer(&self, addr: &[u8; TRUNCATED_HASHLENGTH]) {
        {
            let mut cur = plock(&self.shared.current_peer);
            if *cur != Some(*addr) {
                // Remember where we came from, so F2 can jump back (and a
                // second F2 returns — this records the swap each time).
                *plock(&self.shared.prev_peer) = *cur;
            }
            *cur = Some(*addr);
        }
        write_string(&self.pddb, KEY_PEER, &hex(addr));
        self.chat.dialogue_set(DIALOGUE_DICT, Some(&hex(addr))).ok();
        // Flush messages that arrived for this peer while we were viewing someone
        // else, into the now-active thread, and clear its unread badge.
        let queued = plock(&self.shared.pending).remove(addr).unwrap_or_default();
        let had_queued = !queued.is_empty();
        for (author, ts, text) in queued {
            {
                let mut lt = plock(&self.shared.last_ts);
                *lt = (*lt).max(ts);
            }
            self.chat.post_add(&author, ts, &text, None).ok();
        }
        plock(&self.shared.unread).remove(addr);
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
        // idle, with the F1 next-unread hint), so it's always clear which
        // thread you're in.
        self.chat.set_status_text(&format!("\u{25c9} {}", self.peer_name(addr)));
        net::refresh_idle_status(&self.shared, self.chat_cid);
    }

    /// F1: open the chat that's been waiting longest with unread messages.
    /// Opening it clears its badge, so the next press moves on to the next
    /// unread chat; the status bar always shows where F1 goes.
    pub fn jump_to_unread(&self) {
        match net::first_unread(&self.shared) {
            Some((addr, _)) => self.activate_peer(&addr),
            None => self.chat.set_status_text("no unread messages"),
        }
    }

    /// F2: jump back to the conversation you were in before this one.
    /// Pressing it again returns — activate_peer records each swap.
    pub fn jump_back(&self) {
        let prev = *plock(&self.shared.prev_peer);
        match prev {
            Some(p) if *plock(&self.shared.current_peer) != Some(p) => self.activate_peer(&p),
            _ => self.chat.set_status_text("no previous conversation"),
        }
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
            .or_else(|| plock(&self.shared.seen).get(addr).map(|(n, _)| n.clone()))
            .unwrap_or_else(|| format!("{}…", &hex(addr)[..8]))
    }

    /// Browse the live directory of seen announces; picking one opens that
    /// peer's thread and saves the peer to your contacts.
    pub fn show_announces_interactive(&mut self, modals: &modals::Modals) {
        // Collect, then show the most-recently-seen first, capped to a sane length.
        let mut all: Vec<([u8; TRUNCATED_HASHLENGTH], String, u64)> = {
            plock(&self.shared.seen).iter().map(|(k, (n, t))| (*k, n.clone(), *t)).collect()
        };
        all.sort_by(|a, b| b.2.cmp(&a.2));
        all.truncate(ANNOUNCE_LIST_MAX);
        let entries: Vec<_> = all.into_iter().map(|(h, n, _)| (h, n)).collect();
        if let Some((addr, name)) =
            self.pick_peer(modals, entries, "Message who?", "No LXMF announces seen yet — Connect and wait.")
        {
            self.activate_peer(&addr);
            save_contact(&self.shared, &self.pddb, &addr, &name);
        }
    }

    /// Pick from your saved contacts (people you've messaged or who've messaged
    /// you). Persisted across reboots; opens that peer's thread.
    pub fn message_contact_interactive(&mut self, modals: &modals::Modals) {
        let unread = plock(&self.shared.unread).clone();
        let mut entries: Vec<_> =
            { plock(&self.shared.contacts).iter().map(|(k, v)| (*k, v.clone())).collect() };
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
        if let Some((addr, _)) =
            self.pick_peer(modals, entries, "Message who?", "No saved contacts yet — use Announces to find peers.")
        {
            // activate_peer already shows "◉ <name>" in the status bar; don't
            // overwrite it (the picker label may carry an unread badge, which
            // only makes sense inside the list).
            self.activate_peer(&addr);
        }
    }

    /// Add a contact from an LXMF address someone sent us in a message
    /// ("here's Bob: <32 hex>") — no announce and no manual hex entry needed.
    /// Lists addresses spotted in inbound message text, newest first; picking
    /// one prompts for a name, saves the contact (key-less at first — the key
    /// arrives via the usual path request when you message them, like any
    /// contact saved without an announce), and opens their thread.
    pub fn import_contact_interactive(&mut self, modals: &modals::Modals) {
        let entries: Vec<_> = {
            plock(&self.shared.found_addrs)
                .iter()
                .rev()
                .map(|(a, from, _)| (*a, format!("from {}", from)))
                .collect()
        };
        let (addr, _) = match self.pick_peer(
            modals,
            entries,
            "Import which address?",
            "No addresses received — have someone send one in a message.",
        ) {
            Some(p) => p,
            None => return,
        };
        match modals
            .alert_builder(&format!("Name for {}…", &hex(&addr)[..8]))
            .field(None, None)
            .build()
        {
            Ok(p) => {
                let name = p.first().as_str().trim().to_string();
                let name = if name.is_empty() { hex(&addr) } else { name };
                save_contact(&self.shared, &self.pddb, &addr, &name);
                {
                    let mut found = plock(&self.shared.found_addrs);
                    found.retain(|(a, _, _)| *a != addr);
                    persist_found_addrs(&self.pddb, &found);
                }
                self.activate_peer(&addr);
                self.chat.set_status_text(&format!("added {}", name));
            }
            Err(_) => {}
        }
    }

    /// Pick a saved contact and give it a new display name (shown in the
    /// contact list, bubble headers, and the status bar). Address, key
    /// material, ticket, and message history are untouched. A manually-set
    /// name is sticky: the peer's announces no longer overwrite it (only
    /// placeholder bare-address names get upgraded — see the Announce
    /// handler in net.rs). Existing bubbles keep the author name they were
    /// posted under; new messages use the new name.
    pub fn rename_contact_interactive(&mut self, modals: &modals::Modals) {
        let mut entries: Vec<_> =
            { plock(&self.shared.contacts).iter().map(|(k, v)| (*k, v.clone())).collect() };
        entries.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));
        let (addr, current) =
            match self.pick_peer(modals, entries, "Rename who?", "No saved contacts yet.") {
                Some(p) => p,
                None => return,
            };
        match modals
            .alert_builder(&format!("New name for {}", current))
            .field(Some(current.clone()), None)
            .build()
        {
            Ok(p) => {
                let new_name = p.first().as_str().trim().to_string();
                if new_name.is_empty() || new_name == current {
                    return;
                }
                save_contact(&self.shared, &self.pddb, &addr, &new_name);
                // If this peer's thread is the active one, refresh its label.
                if *plock(&self.shared.current_peer) == Some(addr) {
                    let label = format!("\u{25c9} {}", new_name);
                    self.chat.set_status_idle_text(&label);
                    self.chat.set_status_text(&label);
                } else {
                    self.chat.set_status_text(&format!("renamed to {}", new_name));
                }
            }
            Err(_) => {}
        }
    }

    /// Wipe the message history of the currently-open conversation, after a
    /// confirmation. The contact, its key, and any stamp ticket are kept — only
    /// the posts (and any queued/undelivered state for this thread) are removed.
    pub fn clear_history_interactive(&mut self, modals: &modals::Modals) {
        // The active thread is the current peer's, or the welcome thread if none.
        let peer = *plock(&self.shared.current_peer);
        let (key, label) = match peer {
            Some(addr) => (hex(&addr), self.peer_name(&addr)),
            None => (DIALOGUE_WELCOME.to_string(), "this thread".to_string()),
        };

        // Confirm — wiping is irreversible.
        modals
            .add_list(vec![CANCEL_LABEL, "Clear history"])
            .ok();
        self.show_picker_fkey_hints();
        let choice = modals.get_radiobutton(&format!("Wipe all messages with {}?", label));
        self.restore_fkey_hints();
        let confirmed = matches!(choice, Ok(choice) if choice == "Clear history");
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
            plock(&self.shared.pending).remove(&addr);
            plock(&self.shared.unread).remove(&addr);
            plock(&self.shared.delivery_updates).remove(&addr);
            plock(&self.shared.outbox).retain(|m| m.peer != addr);
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

    /// Whether the page browser's document view is on screen — the F-keys and
    /// arrow events switch to browser bindings while it is.
    pub fn browsing(&self) -> bool { plock(&self.shared.browser).viewing }

    /// Browse a NomadNet node: pick from saved nodes + announces seen this
    /// session (saved first, then most recently announced), fetch its index page.
    pub fn browse_node_interactive(&mut self, modals: &modals::Modals) {
        let mut entries: Vec<([u8; TRUNCATED_HASHLENGTH], String)> =
            { plock(&self.shared.saved_nodes).iter().map(|(k, v)| (*k, v.clone())).collect() };
        let mut announced: Vec<([u8; TRUNCATED_HASHLENGTH], String, u64)> = {
            plock(&self.shared.nodes_seen)
                .iter()
                .filter(|(k, _)| !entries.iter().any(|(e, _)| e == *k))
                .map(|(k, (n, t))| (*k, n.clone(), *t))
                .collect()
        };
        announced.sort_by(|a, b| b.2.cmp(&a.2));
        entries.extend(announced.into_iter().map(|(h, n, _)| (h, n)));
        entries.truncate(ANNOUNCE_LIST_MAX);
        if let Some((addr, name)) = self.pick_peer(
            modals,
            entries,
            "Browse which node?",
            "No nodes known yet — wait for an announce, or use Browse address.",
        ) {
            self.start_browse(&addr, &name);
        }
    }

    /// Browse a node by its 32-hex destination hash (for nodes that haven't
    /// announced where we can hear them).
    pub fn browse_address_interactive(&mut self, modals: &modals::Modals) {
        match modals.alert_builder("Node address (32 hex)").field(None, None).build() {
            Ok(p) => {
                let s = p.first().as_str().trim().to_string();
                match parse_addr(&s) {
                    Some(addr) => {
                        let name = plock(&self.shared.nodes_seen)
                            .get(&addr)
                            .map(|(n, _)| n.clone())
                            .unwrap_or_else(|| format!("{}…", &s[..8]));
                        self.start_browse(&addr, &name);
                    }
                    None => self.chat.set_status_text("invalid address (need 32 hex chars)"),
                }
            }
            Err(_) => {}
        }
    }

    /// Save the node and kick off the index-page fetch (the browser thread does
    /// the network work; the document view appears when the page arrives).
    fn start_browse(&mut self, addr: &[u8; TRUNCATED_HASHLENGTH], name: &str) {
        plock(&self.shared.saved_nodes).insert(*addr, name.to_string());
        persist_node(&self.pddb, addr, name);
        net::request_page(&self.shared, self.chat_cid, *addr, net::PAGE_PATH_DEFAULT, false);
    }

    /// F2 while browsing: follow the link under the document cursor.
    pub fn follow_link(&self) {
        if self.browsing() {
            net::follow_selected_link(&self.shared, self.chat_cid);
        }
    }

    /// F1 while browsing: go back one page. With a dedicated exit key (F3),
    /// an empty stack just says so instead of surprise-exiting the browser.
    pub fn browser_back(&self) {
        if self.browsing() && !net::browser_back(&self.shared, self.chat_cid) {
            self.chat.set_status_text("no page to go back to (F3 exits)");
        }
    }

    /// F3 while browsing: leave the browser and return to the conversation.
    pub fn browser_exit(&self) { net::browser_exit(&self.shared, self.chat_cid); }

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

pub(crate) fn parse_addr(s: &str) -> Option<[u8; TRUNCATED_HASHLENGTH]> {
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

/// PDDB key (under `PDDB_DICT`) for addresses received in message text and not
/// yet imported as contacts. Records: `addr(16) || ts(8 BE) || from_len(4 BE)
/// || from`. Persisted so an address received before a reboot is still
/// importable after it (the restored scrollback never re-runs `deliver_lxmf`,
/// so it can't be re-scanned).
const KEY_FOUND_ADDRS: &str = "found_addrs";

/// Write the whole found-address list (empty list deletes the key).
/// Delete-then-write with `write_all`: a shorter rewrite must not leave a
/// stale tail (PDDB writes don't truncate).
pub(crate) fn persist_found_addrs(pddb: &Pddb, list: &[([u8; TRUNCATED_HASHLENGTH], String, u64)]) {
    pddb.delete_key(PDDB_DICT, KEY_FOUND_ADDRS, None).ok();
    if list.is_empty() {
        pddb.sync().ok();
        return;
    }
    let mut buf = Vec::new();
    for (addr, from, ts) in list {
        buf.extend_from_slice(addr);
        buf.extend_from_slice(&ts.to_be_bytes());
        buf.extend_from_slice(&(from.len() as u32).to_be_bytes());
        buf.extend_from_slice(from.as_bytes());
    }
    if let Ok(mut k) = pddb.get(PDDB_DICT, KEY_FOUND_ADDRS, None, true, true, Some(buf.len()), None::<fn()>)
    {
        k.write_all(&buf).ok();
        pddb.sync().ok();
    }
}

/// Load the persisted found-address list at startup (tolerates a missing key;
/// a malformed record ends the parse — better a short list than a bogus one).
fn load_found_addrs(pddb: &Pddb) -> Vec<([u8; TRUNCATED_HASHLENGTH], String, u64)> {
    let mut buf = Vec::new();
    match pddb.get(PDDB_DICT, KEY_FOUND_ADDRS, None, false, false, None, None::<fn()>) {
        Ok(mut k) => {
            if k.read_to_end(&mut buf).is_err() {
                return Vec::new();
            }
        }
        Err(_) => return Vec::new(),
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + TRUNCATED_HASHLENGTH + 12 <= buf.len() {
        let mut addr = [0u8; TRUNCATED_HASHLENGTH];
        addr.copy_from_slice(&buf[i..i + TRUNCATED_HASHLENGTH]);
        i += TRUNCATED_HASHLENGTH;
        let mut ts8 = [0u8; 8];
        ts8.copy_from_slice(&buf[i..i + 8]);
        i += 8;
        let mut len4 = [0u8; 4];
        len4.copy_from_slice(&buf[i..i + 4]);
        i += 4;
        let flen = u32::from_be_bytes(len4) as usize;
        if i + flen > buf.len() {
            break;
        }
        let from = String::from_utf8_lossy(&buf[i..i + flen]).into_owned();
        i += flen;
        out.push((addr, from, u64::from_be_bytes(ts8)));
    }
    out
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

/// The 10-byte name hash of the NomadNet node aspect — announces matching it
/// are page-serving nodes for the browser (app_data = node name, raw utf-8).
pub(crate) fn nomad_node_name_hash() -> [u8; NAME_HASH_LENGTH] {
    reticulum_core::destination::name_hash("nomadnetwork", &["node"])
}

/// Persist a browsed node (value = name only; the node's key/route are session
/// state re-learned via path request, like keyless contacts).
pub(crate) fn persist_node(pddb: &Pddb, dest_hash: &[u8; TRUNCATED_HASHLENGTH], name: &str) {
    let key = reticulum_core::hex(dest_hash);
    pddb.delete_key(NODES_DICT, &key, None).ok(); // delete-then-write: no stale tail
    if let Ok(mut k) = pddb.get(NODES_DICT, &key, None, true, true, Some(name.len()), None::<fn()>) {
        k.write_all(name.as_bytes()).ok();
    }
}

/// Load the saved-nodes list at startup.
fn load_nodes(pddb: &Pddb, nodes: &mut BTreeMap<[u8; TRUNCATED_HASHLENGTH], String>) {
    let keys = match pddb.list_keys(NODES_DICT, None) {
        Ok(k) => k,
        Err(_) => return, // dict may not exist yet
    };
    for key in keys {
        let dh = match parse_addr(&key) {
            Some(d) => d,
            None => continue,
        };
        let mut buf = Vec::new();
        match pddb.get(NODES_DICT, &key, None, false, false, None, None::<fn()>) {
            Ok(mut k) => {
                if k.read_to_end(&mut buf).is_err() {
                    continue;
                }
            }
            Err(_) => continue,
        }
        let name = String::from_utf8_lossy(&buf).trim().to_string();
        let name = if name.is_empty() { key } else { name };
        nodes.insert(dh, name);
    }
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

/// The delivery stamp cost (leading-zero bits) a peer's announce demands, if
/// any — element 1 of the v0.5+ msgpack announce app_data (mirrors
/// `LXMF.stamp_cost_from_app_data`). None = no stamp required (including the
/// pre-0.5 raw-name announce format, which can't carry a cost).
pub(crate) fn lxmf_stamp_cost(app_data: &[u8]) -> Option<u32> {
    if app_data.is_empty() {
        return None;
    }
    let b0 = app_data[0];
    if !((0x90..=0x9f).contains(&b0) || b0 == 0xdc) {
        return None;
    }
    match lxmf::msgpack::decode(app_data) {
        Ok(lxmf::msgpack::Value::Array(arr)) => match arr.get(1) {
            Some(lxmf::msgpack::Value::Int(c)) if *c > 0 => Some(*c as u32),
            _ => None,
        },
        _ => None,
    }
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
    plock(&shared.contacts).insert(*dest_hash, name.to_string());
    let key_material = {
        let tp = plock(&shared.transport);
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
