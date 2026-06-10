//! Background network thread: reads HDLC frames off the hub TCP socket, drives
//! the sans-IO [`Transport`], learns/persists contacts from announces, answers
//! inbound link requests, and posts inbound LXMF messages into the chat UI.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use chat::{ChatOp, Post};
use pddb::Pddb;
use reticulum_core::constants::{
    CONTEXT_REQUEST, CONTEXT_RESOURCE, CONTEXT_RESOURCE_ADV, CONTEXT_RESOURCE_REQ, CONTEXT_RESPONSE,
    IV_LENGTH, KEY_HALF, TRUNCATED_HASHLENGTH,
};
use reticulum_core::crypto::{full_hash, truncated_hash};
use reticulum_core::hdlc::{Deframer, frame};
use reticulum_core::resource::ResourceReceiver;
use reticulum_core::transport::{Event, Transport};
use lxmf::msgpack::{self, Value};
use trng::Trng;
use xous::CID;
use xous_ipc::Buffer;
use xous_names::XousNames;

// Delivery-status marks appended to a sent message's bubble. Kept as swappable
// consts because the device font is limited — if any glyph renders as tofu,
// change it here (the geometric/dingbat ranges ◉ ✉ are known to render).
// Glyphs MUST exist in the device fonts or they render as a `<?>` tofu box. Verified
// against libs/blitstr2/src/fonts: `○` (ja/kr), `✓` (ja), `×` and `»` (regular). The
// earlier `✗` (U+2717) and `⇪` (U+21EA) are in NO font → tofu; replaced.
pub const MARK_PENDING: &str = "○"; // sent, awaiting acknowledgement
pub const MARK_DELIVERED: &str = "✓"; // recipient acknowledged
pub const MARK_QUEUED: &str = "»"; // handed to the propagation node (stored, not yet delivered)
pub const MARK_FAILED: &str = "×"; // direct + propagation both failed

pub const STATUS_DELIVERED: u8 = 1;
pub const STATUS_QUEUED: u8 = 2;
pub const STATUS_FAILED: u8 = 3;

/// The glyph for a persisted delivery status code.
pub fn status_mark(status: u8) -> &'static str {
    match status {
        STATUS_DELIVERED => MARK_DELIVERED,
        STATUS_QUEUED => MARK_QUEUED,
        _ => MARK_FAILED,
    }
}

/// A sent message's bubble text: the body followed by a delivery mark.
pub fn bubble_text(text: &str, mark: &str) -> String {
    format!("{text}  {mark}")
}

// Outbound delivery timing (seconds). Generous, because the hub link to a remote
// peer can have multi-second RTT (NomadNet links seen at ~4.6 s).
const PROOF_TIMEOUT: u64 = 18; // await a propagation-node proof before failing
const LINK_RETRY: u64 = 15; // re-request a link to the propagation node
const KEY_RETRY: u64 = 5; // re-request a peer/PN key if still unknown
// Direct (opportunistic) and propagation delivery get SEPARATE, independent time
// budgets — mirroring LXMF, where each delivery method has its own attempt budget
// rather than a shared deadline. The propagation clock starts fresh when a message
// escalates to the node, so a slow direct phase can't starve it (propagation needs
// a link handshake + multi-second PoW stamp + proof, so it needs its own room).
const DIRECT_DEADLINE: u64 = 90; // budget for direct/opportunistic delivery (✗)
const PROP_DEADLINE: u64 = 120; // budget for propagation, from escalation (✗)
const DELIVERY_RETRY: u64 = 10; // re-send opportunistically if no proof yet (LXMF: 10s)
const MAX_ATTEMPTS: u8 = 5; // opportunistic delivery tries before escalating (LXMF: 5)
const MAX_ROUTE_TRIES: u8 = 3; // path requests (× KEY_RETRY) before escalating to the PN
/// Whether to sync from the propagation node automatically on first connect.
/// Disabled for now — sync is triggered manually via the "Sync messages" menu.
const AUTO_SYNC_ON_CONNECT: bool = false;

/// An outbound message tracked until it is delivered (✓), stored at the
/// propagation node (⇪), or given up on (✗). Driven by [`pump_outbox`].
pub struct OutboundMsg {
    pub peer: [u8; TRUNCATED_HASHLENGTH],
    /// The timestamp the bubble was posted with — its key for find/swap.
    pub display_ts: u64,
    pub text: String,
    /// Full packed LXMF message (`dest||source||sig||payload`), sent as link DATA
    /// for direct delivery and re-wrapped for propagation.
    pub packed: Vec<u8>,
    /// Currently attempting propagation-node delivery (vs direct).
    pub via_pn: bool,
    /// A propagation attempt has already been made (don't loop forever).
    pub tried_pn: bool,
    /// Packet hash of the in-flight DATA packet awaiting a proof, if any.
    pub in_flight: Option<[u8; 32]>,
    /// Number of opportunistic delivery attempts made (before escalating to PN).
    pub attempts: u8,
    /// Number of times we re-requested a route to the peer without one arriving.
    /// Past [`MAX_ROUTE_TRIES`] we give up on direct delivery and escalate to the
    /// propagation node (which it can still reach even when the peer is offline) —
    /// mirrors LXMF falling back to propagation after its pathless tries.
    pub route_tries: u8,
    /// Cached propagation blob (message encrypted to the recipient + the node's
    /// PoW stamp). Computed once, lock-free (the stamp takes a few seconds), then
    /// reused on retries. None until the propagation fallback computes it.
    pub pn_blob: Option<Vec<u8>>,
    /// Unix seconds: when [`pump_outbox`] should next act on this message.
    pub next_action: u64,
    /// Unix seconds the message was enqueued (for reference/logging).
    pub created: u64,
    /// Unix-seconds wall-clock bound for the CURRENT delivery phase. Set to
    /// `created + DIRECT_DEADLINE` for the direct/opportunistic phase, then RESET
    /// to `now + PROP_DEADLINE` when the message escalates to the propagation node,
    /// so each phase gets its own independent budget (mirrors LXMF's per-method
    /// attempt budgets). Past this, the message fails (✗).
    pub deadline: u64,
}

/// A delivery-mark update for a thread that wasn't active when it occurred, held
/// until the user opens that thread (then applied) — mirrors the inbound
/// `pending` queue. Persisted so marks survive a restart.
pub struct DeliveryUpdate {
    pub display_ts: u64,
    pub text: String,
    pub status: u8,
}

/// Stage of a propagation-node message sync (mirrors LXMF's `PR_*` states).
#[derive(Clone, Copy, PartialEq)]
enum SyncPhase {
    Idle,
    /// Waiting for the link to the node to come up.
    Linking,
    /// Sent `/get [None,None]`; awaiting the list of available message ids.
    ListRequested,
    /// Sent `/get [wants,…]`; awaiting (and assembling) the message blobs.
    GetRequested,
}

/// State of an in-progress (or idle) propagation-node sync. One at a time.
pub struct SyncState {
    phase: SyncPhase,
    /// The established outbound link id to the propagation node.
    link_id: Option<[u8; TRUNCATED_HASHLENGTH]>,
    /// In-progress Resource download (the list or the message batch).
    receiver: Option<ResourceReceiver>,
    /// Wall-clock deadline; sync aborts if it stalls past this.
    deadline: u64,
    /// One-shot guard so we auto-sync only once per app run (on first connect).
    auto_done: bool,
    /// Set by [`request_sync`] (the menu, on the main thread) and consumed by the
    /// pump thread, so the actual link + hub writes never run on the main thread
    /// (a blocking hub write there would freeze the whole UI).
    requested: bool,
    /// Earliest time the sync thread should act on `requested` — the retry
    /// backoff while we wait for the node's key/route to resolve.
    next_attempt: u64,
    /// Times a requested sync was deferred for want of the node's key/route.
    /// Bounded by [`SYNC_ROUTE_TRIES`] so an unreachable node fails visibly
    /// instead of "finding the propagation node…" forever.
    route_tries: u8,
    /// LINKREQUESTs sent this sync. Shown in the status line (".. try N"): a
    /// counter that stops advancing tells us the sync thread is wedged, while
    /// one that advances with no node response means the requests are lost on
    /// the network — exactly the distinction we can't see otherwise on device.
    link_tries: u8,
}

impl SyncState {
    pub fn new() -> SyncState {
        SyncState {
            phase: SyncPhase::Idle,
            link_id: None,
            receiver: None,
            deadline: 0,
            auto_done: false,
            requested: false,
            next_attempt: 0,
            route_tries: 0,
            link_tries: 0,
        }
    }
}

/// State shared between the app's main thread and the network RX thread.
pub struct Shared {
    pub transport: Mutex<Transport>,
    /// The write half of the hub connection (None until connected).
    ///
    /// LOCK DISCIPLINE: only [`write_to_hub`] (with a BOUNDED try_lock wait) and
    /// the connection manager may take this. A hub write on real hardware can
    /// block indefinitely (the 10 s socket write timeout has been observed not
    /// to save us), and a thread blocking on this mutex forever wedged the sync
    /// thread, the pump, and even the manager's reconnect — all at once.
    pub writer: Mutex<Option<TcpStream>>,
    /// Whether a hub connection is currently up — readable without touching
    /// `writer` (so an is-connected check can never block behind a stuck write).
    /// Maintained by the connection manager and the write-error path.
    pub connected: core::sync::atomic::AtomicBool,
    /// A control clone of the live socket, used to `shutdown()` it from OUTSIDE
    /// a stuck write (the stuck thread holds `writer`, so the watchdog needs an
    /// independent handle to unblock it). Never held across I/O.
    pub ctl: Mutex<Option<TcpStream>>,
    /// Unix seconds (truncated to u32) when the in-flight hub write started; 0
    /// when no write is in flight. The keepalive thread's watchdog kills the
    /// socket if this stays nonzero too long, which errors the blocked write out
    /// and lets the connection manager reconnect.
    pub write_started: core::sync::atomic::AtomicU32,
    /// LIVENESS DIAGNOSTICS, displayed by the MAIN thread in `sync_now`'s status
    /// line (`[sN pN rN gN cN]`). Lock-free on purpose: the main thread must be
    /// able to render them no matter which mutex is wedged. Heartbeats tick once
    /// per loop iteration of their thread; `sync_stage` records the last numbered
    /// step the sync path reached (see [`stage`] constants), so a wedged sync
    /// pinpoints the exact statement it blocked on.
    pub beat_sync: core::sync::atomic::AtomicU32,
    pub beat_pump: core::sync::atomic::AtomicU32,
    pub beat_read: core::sync::atomic::AtomicU32,
    pub sync_stage: core::sync::atomic::AtomicU32,
    /// The hub to (re)connect to, as `host:port`. Read by the connection manager
    /// each cycle so a "Set hub" takes effect on the next (re)connect.
    pub hub: Mutex<String>,
    /// Our own lxmf.delivery destination hash.
    pub our_dh: [u8; TRUNCATED_HASHLENGTH],
    /// PDDB dialogue key the chat UI is bound to.
    pub dialogue_id: String,
    /// Live directory of LXMF announces seen this session:
    /// dest hash -> (display name, last-seen unix seconds). In-memory only.
    pub seen: Mutex<BTreeMap<[u8; TRUNCATED_HASHLENGTH], (String, u64)>>,
    /// Saved contacts (people we've messaged or who've messaged us): dest hash
    /// -> display name. Persisted to the PDDB and loaded at startup.
    pub contacts: Mutex<BTreeMap<[u8; TRUNCATED_HASHLENGTH], String>>,
    /// The peer we are currently messaging (set by a picker, or auto-set to the
    /// sender of an inbound message when none is selected).
    pub current_peer: Mutex<Option<[u8; TRUNCATED_HASHLENGTH]>>,
    /// Recently delivered LXMF message ids, to drop duplicate retransmissions.
    pub recent_msg_ids: Mutex<Vec<[u8; 32]>>,
    /// Per-contact count of messages received while their thread was NOT the
    /// active conversation. Shown as a badge in the contacts list; cleared when
    /// the thread is opened.
    pub unread: Mutex<BTreeMap<[u8; TRUNCATED_HASHLENGTH], u32>>,
    /// Messages received for a contact other than the active conversation, held
    /// (author, timestamp, text) until the user opens that thread, then flushed
    /// into it. In-memory only (not yet persisted across an app restart).
    pub pending: Mutex<BTreeMap<[u8; TRUNCATED_HASHLENGTH], Vec<(String, u64, String)>>>,
    /// Outbound tickets: dest hash -> (expiry unix seconds, 16-byte ticket). A
    /// peer that enforces a stamp cost can trust us by sending a ticket inside an
    /// inbound message's `FIELD_TICKET`; we store it here and stamp our replies
    /// with it (see `LxmfChat::post`) instead of computing a proof-of-work stamp.
    /// Persisted to the PDDB and loaded at startup.
    pub tickets: Mutex<BTreeMap<[u8; TRUNCATED_HASHLENGTH], (u64, [u8; TRUNCATED_HASHLENGTH])>>,
    /// Raw bytes of inbound messages that carried a ticket but couldn't be
    /// signature-verified yet (we didn't have the sender's key — common on an
    /// access-point interface). Keyed by source hash; re-checked when that peer's
    /// key arrives (see the `Announce` handler), so the ticket isn't lost.
    pub ticket_pending: Mutex<BTreeMap<[u8; TRUNCATED_HASHLENGTH], Vec<u8>>>,
    /// Messages sent and awaiting delivery confirmation, driven by [`pump_outbox`]:
    /// direct delivery first, then propagation-node fallback, updating the bubble's
    /// delivery mark as the state changes.
    pub outbox: Mutex<Vec<OutboundMsg>>,
    /// Delivery-mark updates for threads that weren't active when the update
    /// occurred (dest hash -> queued updates); applied when the thread is opened.
    pub delivery_updates: Mutex<BTreeMap<[u8; TRUNCATED_HASHLENGTH], Vec<DeliveryUpdate>>>,
    /// Highest message timestamp shown in any thread so far. The chat UI sorts
    /// posts by timestamp; the Precursor's wall clock can be wrong (e.g. the UTC
    /// offset is reset by a PDDB wipe), so we stamp our own outgoing echo with
    /// `max(now, last_ts+1)` to guarantee it sorts to the bottom of the thread
    /// instead of being buried above peers' (correctly-timestamped) messages.
    pub last_ts: Mutex<u64>,
    /// Propagation-node message sync state machine (download stored messages).
    pub sync: Mutex<SyncState>,
    /// Low-level I/O handle, used to buzz the vibration motor on a new inbound
    /// message. `vibe` is a fire-and-forget scalar, safe to call from any thread.
    pub llio: llio::Llio,
}

fn hex(b: &[u8]) -> String { reticulum_core::hex(b) }

/// Short human label for a peer (contact/announce name, else a hex prefix), for
/// transient status messages.
fn peer_label(shared: &Arc<Shared>, peer: &[u8; TRUNCATED_HASHLENGTH]) -> String {
    shared
        .contacts
        .lock()
        .unwrap()
        .get(peer)
        .cloned()
        .or_else(|| shared.seen.lock().unwrap().get(peer).map(|(n, _)| n.clone()))
        .unwrap_or_else(|| hex(&peer[..4]))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Connection manager: keeps a live connection to `shared.hub`, automatically
/// reconnecting (with capped backoff) whenever it drops. Runs for the lifetime
/// of the app — one instance, started on the first `connect()`. On each
/// successful connect it announces our destination and runs the read loop until
/// the socket closes, then loops to reconnect.
pub fn connection_manager(shared: Arc<Shared>, chat_cid: CID) {
    let pddb = Pddb::new();
    let trng = match XousNames::new().ok().and_then(|xns| Trng::new(&xns).ok()) {
        Some(t) => t,
        None => {
            log::error!("lxmf connection manager: TRNG init failed");
            return;
        }
    };
    let mut backoff = 2u64;
    loop {
        let hub = shared.hub.lock().unwrap().clone();
        let parsed = hub
            .rsplit_once(':')
            .and_then(|(h, p)| p.parse::<u16>().ok().map(|n| (h.to_string(), n)));
        let (host, port) = match parsed {
            Some(hp) => hp,
            None => {
                chat::cf_set_status_text(chat_cid, &format!("bad hub address: {hub}"));
                std::thread::sleep(std::time::Duration::from_secs(15));
                continue;
            }
        };

        chat::cf_set_status_text(chat_cid, &format!("connecting to {hub}…"));
        match TcpStream::connect((host.as_str(), port)) {
            Ok(stream) => {
                stream.set_nodelay(true).ok();
                // Bound hub writes so a stalled socket (e.g. during a resource
                // transfer) can't block a writer forever and wedge the threads
                // that share it (no-op if the Xous TcpStream ignores it).
                stream.set_write_timeout(Some(std::time::Duration::from_secs(10))).ok();
                let clones = stream.try_clone().and_then(|r| stream.try_clone().map(|c| (r, c)));
                match clones {
                    Ok((reader, ctl)) => {
                        *shared.writer.lock().unwrap() = Some(stream);
                        *shared.ctl.lock().unwrap() = Some(ctl);
                        shared.connected.store(true, core::sync::atomic::Ordering::SeqCst);
                        backoff = 2;
                        chat::cf_set_status_text(chat_cid, &format!("connected to {hub}"));
                        send_announce(&shared, &trng);
                        // Proactively learn the propagation node's route now, so a
                        // later store-and-forward fallback doesn't have to discover
                        // it mid-escalation (which burns the retry deadline).
                        request_propagation_path(&shared, &trng);
                        read_until_closed(&shared, chat_cid, &pddb, &trng, reader);
                        shared.connected.store(false, core::sync::atomic::Ordering::SeqCst);
                        shared.ctl.lock().unwrap().take();
                        // Clear the writer with a BOUNDED wait: a write stuck on
                        // the dying socket may hold the mutex until the watchdog
                        // breaks it — never let the manager (the only thing that
                        // can reconnect us) block behind that.
                        for _ in 0..40 {
                            match shared.writer.try_lock() {
                                Ok(mut g) => {
                                    g.take();
                                    break;
                                }
                                Err(std::sync::TryLockError::WouldBlock) => {
                                    std::thread::sleep(std::time::Duration::from_millis(50))
                                }
                                Err(std::sync::TryLockError::Poisoned(_)) => break,
                            }
                        }
                        // The hub routes link traffic and proofs by interface
                        // session: every link / pending request / receipt is dead
                        // after a reconnect. Drop them so nothing reuses a link
                        // the hub can no longer route responses back on.
                        shared.transport.lock().unwrap().connection_reset();
                        let sync_active = { shared.sync.lock().unwrap().phase != SyncPhase::Idle };
                        if sync_active {
                            sync_finish(&shared, chat_cid, "connection lost — try again");
                        }
                        chat::cf_set_status_text(chat_cid, "hub connection lost — reconnecting…");
                    }
                    Err(e) => {
                        shared.connected.store(false, core::sync::atomic::Ordering::SeqCst);
                        chat::cf_set_status_text(chat_cid, &format!("socket clone failed: {e}"));
                    }
                }
            }
            Err(e) => {
                chat::cf_set_status_text(chat_cid, &format!("connect to {hub} failed: {e} — retrying…"));
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(backoff));
        backoff = (backoff * 2).min(30);
    }
}

/// Read HDLC frames until the socket closes (then returns so the manager can
/// reconnect).
fn read_until_closed(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, trng: &Trng, mut stream: TcpStream) {
    let mut deframer = Deframer::new();
    let mut buf = [0u8; 2048];
    log::info!("lxmf read loop started");
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                log::info!("hub connection closed");
                break;
            }
            Ok(n) => {
                shared.beat_read.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
                for frame in deframer.push(&buf[..n]) {
                    handle_frame(shared, chat_cid, pddb, trng, &frame);
                }
            }
            Err(e) => {
                log::warn!("hub read error: {e}");
                break;
            }
        }
    }
}

/// Announce our lxmf.delivery destination on the current connection.
fn send_announce(shared: &Arc<Shared>, trng: &Trng) {
    let mut r5 = [0u8; 5];
    crate::fill_random(trng, &mut r5);
    let raw = {
        let tp = shared.transport.lock().unwrap();
        tp.make_announce_with("lxmf", &["delivery"], b"precursor", &r5, now_secs())
    };
    write_to_hub(shared, &raw);
}

/// Ask the hub for a route to the configured propagation node (if any), so its
/// key + next-hop are learned ahead of any store-and-forward fallback. Like any
/// peer on an access-point hub, the node must have announced for the hub to
/// answer; a no-op if no propagation node is configured.
fn request_propagation_path(shared: &Arc<Shared>, trng: &Trng) {
    if let Some(pn) = crate::propagation_node() {
        request_peer_key(shared, trng, &pn);
        log::info!("requested propagation node path {}", hex(&pn));
    }
}

fn handle_frame(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, trng: &Trng, frame_bytes: &[u8]) {
    // Fresh per-link ephemeral X25519 key material, drawn from the TRNG only when
    // the transport needs to answer a link request.
    let mut gen_ephemeral = || {
        let mut b = [0u8; KEY_HALF];
        crate::fill_random(trng, &mut b);
        b
    };
    let event = { shared.transport.lock().unwrap().handle_frame(frame_bytes, &mut gen_ephemeral) };

    match event {
        Event::Announce { destination_hash, info } => {
            // Only list LXMF *delivery* destinations — skip propagation-node and
            // other-app announces, whose app_data isn't a messageable peer name.
            if info.name_hash != crate::lxmf_delivery_name_hash() {
                return;
            }
            // Announces populate the live directory only; they are NOT saved as
            // contacts until you actually message them (or they message you).
            let name = crate::lxmf_display_name(&info.app_data).unwrap_or_else(|| hex(&destination_hash));
            shared.seen.lock().unwrap().insert(destination_hash, (name.clone(), now_secs()));
            // If this is already a saved contact (e.g. someone who messaged us
            // before we had their key — common on an access_point interface),
            // upgrade their record now that we have the key + a display name.
            let is_contact = shared.contacts.lock().unwrap().contains_key(&destination_hash);
            if is_contact {
                crate::save_contact(shared, pddb, &destination_hash, &name);
            }
            // Now that we have this peer's key, recover a ticket from any earlier
            // message we couldn't verify at the time (access-point interface).
            let cached = shared.ticket_pending.lock().unwrap().remove(&destination_hash);
            if let Some(bytes) = cached {
                verify_and_store_ticket(shared, chat_cid, pddb, &destination_hash, &info.identity, &bytes);
            }
        }
        // Opportunistic delivery: the destination hash is stripped on the wire, so
        // prepend ours to reconstruct the full LXMF blob.
        Event::Data { destination_hash, plaintext } => {
            let mut lxmf_bytes = destination_hash.to_vec();
            lxmf_bytes.extend_from_slice(&plaintext);
            deliver_lxmf(shared, chat_cid, pddb, trng, &lxmf_bytes, true);
        }
        // We accepted an inbound link request: send the proof so the initiator
        // starts transmitting the message over the link.
        Event::LinkEstablished { link_id, proof } => {
            log::info!("accepted inbound link {}", hex(&link_id));
            write_to_hub(shared, &proof);
            // Transient status only — NOT a persisted post. A persisted
            // "receiving" line per link was confusing on retransmits (a new link
            // is established each retry, but the message itself is de-duplicated),
            // making it look like a message arrived with no content. The delivered
            // message is the real feedback.
            chat::cf_set_status_text(chat_cid, "incoming message…");
        }
        // Direct delivery over a link: the plaintext is already the full LXMF
        // blob. Send the packet proof back so the sender confirms delivery (and
        // stops retrying / tearing the link down).
        Event::LinkData { plaintext, proof, .. } => {
            write_to_hub(shared, &proof);
            deliver_lxmf(shared, chat_cid, pddb, trng, &plaintext, true);
        }
        // A link we initiated is up. Real RNS responders only activate the link —
        // and start accepting data — once they receive an RTT packet, so send it
        // before any data (or the data is silently dropped). Then send queued msgs.
        Event::OutboundLinkUp { link_id, target } => {
            log::info!("outbound link {} up to {}", hex(&link_id), hex(&target));
            let mut iv = [0u8; IV_LENGTH];
            crate::fill_random(trng, &mut iv);
            let rtt = { shared.transport.lock().unwrap().make_link_rtt(&link_id, &iv) };
            if let Some(rtt) = rtt {
                write_to_hub(shared, &rtt);
            }
            sync_on_link_up(shared, chat_cid, trng, link_id, target);
            pump_outbox(shared, chat_cid, pddb, trng);
        }
        // A packet proof confirmed one of our sent messages reached its target.
        Event::Delivered { packet_hash } => {
            mark_delivered(shared, chat_cid, pddb, &packet_hash);
        }
        // Response / resource-transfer data on a link we opened (propagation-node
        // sync): drive the sync state machine.
        Event::OutLinkData { link_id, context, plaintext } => {
            sync_on_outlink_data(shared, chat_cid, pddb, trng, link_id, context, plaintext);
        }
        // The responder closed a link we initiated (transport already forgot it).
        // If a sync was mid-flight on it, abort now and let the user retry over a
        // fresh link instead of waiting out the 2-minute watchdog.
        Event::OutLinkClosed { link_id } => {
            log::info!("outbound link {} closed by responder", hex(&link_id));
            let sync_was_on_it = {
                let s = shared.sync.lock().unwrap();
                s.phase != SyncPhase::Idle && s.link_id == Some(link_id)
            };
            if sync_was_on_it {
                sync_finish(shared, chat_cid, "node closed the link — try again");
            }
        }
        Event::DataUndecryptable { destination_hash, reason } => {
            // Log-only — NEVER a persisted post. A repeated undecryptable packet
            // (stale ratchet, retransmit, AP-hub cross-traffic) would otherwise
            // flood the dialogue and overflow the PDDB on the next read.
            log::warn!("undecryptable DATA to {}: {}", hex(&destination_hash), reason);
        }
        // NOTE: link-control / unrouted / dropped frames are logged only, never
        // posted to the chat. Posting them persisted a flood of entries (each
        // post is DialogueSave'd) during an announce storm, which ballooned the
        // PDDB. Keep the persistent thread for real messages only.
        Event::AddressedUnhandled { destination_hash, packet_type, context } => {
            log::debug!(
                "link {} addressed-but-unhandled type={} ctx=0x{:02x}",
                hex(&destination_hash), packet_type, context
            );
        }
        Event::Unhandled { destination_hash, packet_type, context } => {
            log::debug!(
                "unrouted packet to {} type={} ctx=0x{:02x}",
                hex(&destination_hash), packet_type, context
            );
        }
        Event::Dropped(why) => log::debug!("dropped frame: {}", why),
    }
}

/// Store a freshly-received outbound ticket (keyed by the peer) if it is newer
/// than any we hold and not expired, and let the user know they can now reply.
fn store_ticket(
    shared: &Arc<Shared>,
    chat_cid: CID,
    pddb: &Pddb,
    src_hash: &[u8; TRUNCATED_HASHLENGTH],
    t: &lxmf::message::InboundTicket,
) {
    if t.expires <= now_secs() {
        return;
    }
    let keep = shared.tickets.lock().unwrap().get(src_hash).map_or(true, |(exp, _)| t.expires >= *exp);
    if !keep {
        return;
    }
    shared.tickets.lock().unwrap().insert(*src_hash, (t.expires, t.ticket));
    crate::persist_ticket(pddb, src_hash, t.expires, &t.ticket);
    let label = peer_label(shared, src_hash);
    chat::cf_set_status_text(chat_cid, &format!("received a ticket from {label} — you can now reply"));
    log::info!("stored outbound ticket for {} (expires {})", hex(src_hash), t.expires);
}

/// Re-verify a previously-cached message (now that we have `identity`) and store
/// any ticket it carried. Recovers a ticket from a message we couldn't verify
/// when it first arrived (we hadn't learned the sender's key yet).
fn verify_and_store_ticket(
    shared: &Arc<Shared>,
    chat_cid: CID,
    pddb: &Pddb,
    src_hash: &[u8; TRUNCATED_HASHLENGTH],
    identity: &reticulum_core::identity::PublicIdentity,
    lxmf_bytes: &[u8],
) {
    if let Ok(m) = lxmf::message::parse(lxmf_bytes, Some(identity)) {
        if m.signature_validated {
            if let Some(t) = lxmf::message::extract_ticket(&m.fields) {
                store_ticket(shared, chat_cid, pddb, src_hash, &t);
            }
        }
    }
}

/// Parse a full LXMF blob (`dest||source||sig||payload`), verify, de-duplicate,
/// route into the sender's thread, and post it.
/// `notify`: buzz the vibration motor for this message (live receipt). The sync
/// path passes false and buzzes once for the whole batch instead.
fn deliver_lxmf(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, trng: &Trng, lxmf_bytes: &[u8], notify: bool) {
    if lxmf_bytes.len() < 2 * TRUNCATED_HASHLENGTH {
        return;
    }
    let mut src_hash = [0u8; TRUNCATED_HASHLENGTH];
    src_hash.copy_from_slice(&lxmf_bytes[TRUNCATED_HASHLENGTH..2 * TRUNCATED_HASHLENGTH]);

    let src_id = { shared.transport.lock().unwrap().known(&src_hash).map(|k| k.identity.clone()) };
    // If we don't have the sender's public key (common on an access_point
    // interface, where we never see announces), ask the network for it now, so a
    // reply is possible by the time the user reads this message.
    if src_id.is_none() {
        request_peer_key(shared, trng, &src_hash);
    }
    let m = match lxmf::message::parse(lxmf_bytes, src_id.as_ref()) {
        Ok(m) => m,
        Err(e) => {
            // Log-only — a repeated unparseable blob must not flood the dialogue.
            log::warn!("inbound LXMF parse failed: {:?}", e);
            return;
        }
    };

    // Drop duplicates (link senders retransmit until they get a receipt).
    {
        let mut ids = shared.recent_msg_ids.lock().unwrap();
        if ids.contains(&m.message_id) {
            return;
        }
        ids.push(m.message_id);
        if ids.len() > 64 {
            ids.remove(0);
        }
    }

    // A genuinely new inbound message — buzz the vibration motor as a notification
    // (live receipt only; the sync path buzzes once per batch).
    if notify {
        shared.llio.vibe(llio::VibePattern::Long).ok();
    }

    let author = shared
        .contacts
        .lock()
        .unwrap()
        .get(&src_hash)
        .cloned()
        .or_else(|| shared.seen.lock().unwrap().get(&src_hash).map(|(n, _)| n.clone()))
        .unwrap_or_else(|| hex(&src_hash));
    let mut text = m.content_string();
    if !m.signature_validated {
        text.push_str("  ⚠(unverified)");
    }

    crate::save_contact(shared, pddb, &src_hash, &author);

    // If this peer trusts us with a ticket (so we can satisfy their stamp cost
    // when replying), remember it. Only honour tickets from a verified sender — an
    // unsigned message could otherwise plant a bogus one. If we can't verify yet
    // (no key, common on an access-point interface), cache the message and recover
    // the ticket when the key arrives (see the Announce handler) rather than
    // losing it — the sender only re-issues a ticket about once a day.
    if m.signature_validated {
        if let Some(t) = lxmf::message::extract_ticket(&m.fields) {
            store_ticket(shared, chat_cid, pddb, &src_hash, &t);
        }
    } else if lxmf::message::extract_ticket(&m.fields).is_some() {
        shared.ticket_pending.lock().unwrap().insert(src_hash, lxmf_bytes.to_vec());
        log::info!("cached unverified ticket message from {} pending key", hex(&src_hash));
    }

    let ts = m.timestamp as u64;
    let active = *shared.current_peer.lock().unwrap();
    if active == Some(src_hash) {
        // The conversation we're currently viewing: show it immediately.
        {
            let mut lt = shared.last_ts.lock().unwrap();
            *lt = (*lt).max(ts);
        }
        chat::cf_set_status_idle_text(chat_cid, &format!("\u{25c9} {author}"));
        post_to_chat(shared, chat_cid, &author, ts, &text);
    } else {
        // A different contact: do NOT disturb the active conversation. Hold the
        // message and bump that contact's unread badge; it'll be flushed into the
        // thread when the user opens it (see `activate_peer`).
        {
            let mut p = shared.pending.lock().unwrap();
            let list = p.entry(src_hash).or_default();
            list.push((author.clone(), ts, text));
            // Persist so held messages + the unread badge survive an app restart.
            crate::persist_pending(pddb, &src_hash, list);
        }
        *shared.unread.lock().unwrap().entry(src_hash).or_default() += 1;
        chat::cf_set_status_text(chat_cid, &format!("\u{2709} new message from {author}"));
    }
}

/// Keep the hub TCP connection from being idled out by a NAT/firewall/hub.
///
/// RNS relies on OS-level `SO_KEEPALIVE`, which Xous `std` doesn't expose, so a
/// quiet connection gets dropped after a while. We instead send a periodic empty
/// HDLC frame: RNS discards any frame smaller than a packet header, so it's a
/// protocol-safe no-op, but the outbound bytes refresh the idle timers. One
/// thread runs per connection and exits when the write fails (connection gone).
pub fn keepalive_thread(shared: Arc<Shared>, chat_cid: CID) {
    use core::sync::atomic::Ordering;
    const TICK_SECS: u64 = 5;
    const KEEPALIVE_TICKS: u64 = 6; // empty frame every 30 s
    // Runs for the app's lifetime (one instance). Two jobs:
    // 1. STUCK-WRITE WATCHDOG (every tick): a hub write that's been in flight
    //    past WRITE_STUCK_SECS has hung the writer mutex (the socket write
    //    timeout demonstrably doesn't always fire on hardware) — shut the socket
    //    down via the control clone, which errors the blocked write out, releases
    //    the mutex, ends the read loop, and lets the manager reconnect. Without
    //    this, ONE stuck write silently wedged sync + sends + reconnect forever.
    // 2. KEEPALIVE (every 6th tick): send an empty HDLC frame (a protocol-safe
    //    no-op RNS discards) so NAT/hub idle timers don't drop a quiet link, and
    //    so a silently-dead socket is detected within ~30 s.
    let mut ticks: u64 = 0;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(TICK_SECS));
        ticks += 1;
        let started = shared.write_started.load(Ordering::SeqCst);
        if started != 0 && (now_secs() as u32).saturating_sub(started) > WRITE_STUCK_SECS {
            log::warn!("hub write stuck >{WRITE_STUCK_SECS}s — shutting the socket down to unwedge it");
            chat::cf_set_status_text(chat_cid, "hub write stalled — resetting connection…");
            shared.write_started.store(0, Ordering::SeqCst);
            shared.connected.store(false, Ordering::SeqCst);
            if let Some(c) = shared.ctl.lock().unwrap().take() {
                c.shutdown(std::net::Shutdown::Both).ok();
            }
            continue;
        }
        if ticks % KEEPALIVE_TICKS == 0 && shared.connected.load(Ordering::SeqCst) {
            write_to_hub(&shared, &[]);
        }
    }
}

/// Ask the network to (re-)announce `target` so we learn its public key. Used
/// when we receive from, or want to message, a peer we have no key for — the
/// normal case on an access_point interface where announces aren't flooded to us.
pub fn request_peer_key(shared: &Arc<Shared>, trng: &Trng, target: &[u8; TRUNCATED_HASHLENGTH]) {
    let mut tag = [0u8; TRUNCATED_HASHLENGTH];
    crate::fill_random(trng, &mut tag);
    let raw = { shared.transport.lock().unwrap().make_path_request(target, &tag) };
    write_to_hub(shared, &raw);
    log::info!("sent path request for {}", hex(target));
}

/// A hub write counts as stuck after this long; the keepalive thread's watchdog
/// then shuts the socket down out from under it, erroring the write out.
const WRITE_STUCK_SECS: u32 = 20;

/// Frame and write `raw` to the hub. Returns true only if the bytes were fully
/// written; false if there is no connection, the writer was busy too long, or
/// the write failed (callers that need delivery — like the sync state machine —
/// surface that instead of silently doing nothing).
///
/// Never blocks unboundedly: the writer mutex is acquired with a ~2 s bounded
/// wait (a healthy write completes in milliseconds; a longer hold means a wedged
/// write that the watchdog will kill), and the write itself is marked in
/// `write_started` so the watchdog can detect and break a hang.
pub(crate) fn write_to_hub(shared: &Arc<Shared>, raw: &[u8]) -> bool {
    use core::sync::atomic::Ordering;
    let framed = frame(raw);
    let mut guard = None;
    for _ in 0..40 {
        match shared.writer.try_lock() {
            Ok(g) => {
                guard = Some(g);
                break;
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(std::sync::TryLockError::Poisoned(_)) => return false,
        }
    }
    let mut guard = match guard {
        Some(g) => g,
        None => {
            log::warn!("hub writer busy >2s, dropping a {}-byte frame", framed.len());
            return false;
        }
    };
    match guard.as_mut() {
        Some(w) => {
            shared.write_started.store(now_secs() as u32, Ordering::SeqCst);
            let res = w.write_all(&framed).and_then(|_| w.flush());
            shared.write_started.store(0, Ordering::SeqCst);
            if res.is_err() {
                // A failed/timed-out write means the connection is dead OR the HDLC
                // stream is now half-written and desynced. Don't keep limping along
                // (that silently drops every later message): shut the socket so the
                // read loop returns and the connection manager reconnects cleanly.
                w.shutdown(std::net::Shutdown::Both).ok();
                *guard = None;
                shared.connected.store(false, Ordering::SeqCst);
                shared.ctl.lock().unwrap().take();
                false
            } else {
                true
            }
        }
        None => false,
    }
}

// ---- Propagation-node message sync (download stored messages) -----------------
//
// Mirrors LXMF's `request_messages_from_propagation_node`: open a link to the
// node's lxmf.propagation destination, identify, then issue RNS requests to the
// "/get" handler: first `[None,None]` to list the transient ids waiting for us,
// then `[wants,haves,limit]` to download them (as a Resource), feed each through
// `deliver_lxmf`, and finally `[None,haves]` so the node deletes what we received.

/// LXMF `/get` request path; its hash selects the node's message-get handler.
const SYNC_GET_PATH: &[u8] = b"/get";
/// Per-transfer message size limit we advertise (KB). LXMF's default is 1000, but
/// our Resource receiver is single-segment only (no hashmap updates): ~74 parts ≈
/// 31 KB max. Advertise less than that so the node trims each batch to what we
/// can actually receive — anything left over comes on the next sync.
const SYNC_DELIVERY_LIMIT: i64 = 28;
/// Abort a sync that stalls past this many seconds.
const SYNC_DEADLINE_SECS: u64 = 120;
/// Retry cadence and bound while a requested sync waits for the propagation
/// node's key/route (a path request is in flight): every 3 s, up to 20 tries
/// (~1 min), then fail visibly.
const SYNC_ROUTE_RETRY_SECS: u64 = 3;
const SYNC_ROUTE_TRIES: u8 = 20;

/// Begin a propagation-node sync (from the menu or auto on first connect). Ensures
/// the node's key + route, (re)uses or opens the link, and kicks the exchange.
pub fn start_sync(shared: &Arc<Shared>, chat_cid: CID, trng: &Trng) {
    stage(shared, 11);
    let pn = match crate::propagation_node() {
        Some(p) => p,
        None => {
            chat::cf_set_status_text_forced(chat_cid, "no propagation node configured");
            return;
        }
    };
    if shared.sync.lock().unwrap().phase != SyncPhase::Idle {
        chat::cf_set_status_text_forced(chat_cid, "sync already in progress");
        return;
    }
    stage(shared, 12);
    let now = now_secs();
    // No hub connection: nothing we send can go anywhere. Wait for the manager
    // to reconnect (same bounded retry as the no-route case below) instead of
    // burning the request on writes that go nowhere. Atomic flag, NOT the writer
    // mutex — this check must never block behind a stuck write.
    if !shared.connected.load(core::sync::atomic::Ordering::SeqCst) {
        let give_up = {
            let mut s = shared.sync.lock().unwrap();
            s.route_tries = s.route_tries.saturating_add(1);
            if s.route_tries <= SYNC_ROUTE_TRIES {
                s.requested = true;
                s.next_attempt = now + SYNC_ROUTE_RETRY_SECS;
                false
            } else {
                true
            }
        };
        if give_up {
            sync_finish(shared, chat_cid, "not connected to the hub");
        } else {
            chat::cf_set_status_text_forced(chat_cid, "sync: waiting for hub connection…");
        }
        return;
    }
    stage(shared, 13);
    let (known, have_path) = {
        let tp = shared.transport.lock().unwrap();
        (tp.known(&pn).cloned(), tp.has_path(&pn))
    };
    stage(shared, 14);
    let known = match (known, have_path) {
        (Some(k), true) => k,
        _ => {
            // No key/route for the node yet: fire a path request and RE-ARM the
            // request flag so the sync thread retries once the response lands —
            // consuming the flag here with no retry left the status stuck at
            // "finding…" forever. Bounded so an unreachable node fails visibly.
            let give_up = {
                let mut s = shared.sync.lock().unwrap();
                s.route_tries = s.route_tries.saturating_add(1);
                if s.route_tries <= SYNC_ROUTE_TRIES {
                    s.requested = true;
                    s.next_attempt = now + SYNC_ROUTE_RETRY_SECS;
                    false
                } else {
                    true
                }
            };
            if give_up {
                sync_finish(shared, chat_cid, "no route to the propagation node");
                return;
            }
            // Status BEFORE the hub write, so it shows even if the write stalls.
            chat::cf_set_status_text_forced(chat_cid, "sync: finding the propagation node…");
            request_peer_key(shared, trng, &pn);
            return;
        }
    };
    {
        let mut s = shared.sync.lock().unwrap();
        s.phase = SyncPhase::Linking;
        s.receiver = None;
        s.deadline = now + SYNC_DEADLINE_SECS;
        s.link_id = None;
        s.route_tries = 0;
        s.next_attempt = 0;
        s.link_tries = 0;
    }
    stage(shared, 15);
    match { shared.transport.lock().unwrap().outbound_link_for(&pn, now) } {
        Some(lid) => {
            shared.sync.lock().unwrap().link_id = Some(lid);
            sync_send_identify_and_list(shared, chat_cid, trng, lid);
        }
        None => {
            stage(shared, 16);
            // The hop count distinguishes a HEADER_1 (hops ≤ 1, direct) from a
            // HEADER_2 (routed) link request — and the try counter advancing
            // proves the sync thread is alive and writing. Status BEFORE the
            // write so it shows even if the write stalls.
            let hops = { shared.transport.lock().unwrap().path_hops(&pn) };
            let hops = hops.map(|h| h.to_string()).unwrap_or_else(|| "?".to_string());
            chat::cf_set_status_text_forced(
                chat_cid,
                &format!("sync: contacting node (try 1, hops {hops})…"),
            );
            let outcome = send_pn_link_request(shared, trng, &pn, &known.identity, now);
            stage(shared, 17);
            match outcome {
                LinkReqOutcome::WriteFailed => {
                    sync_finish(shared, chat_cid, "hub write failed — try again");
                }
                LinkReqOutcome::Sent | LinkReqOutcome::Pending => {
                    shared.sync.lock().unwrap().link_tries = 1;
                }
            }
        }
    }
}

/// What happened when we tried to (re)send a LINKREQUEST to the propagation node.
enum LinkReqOutcome {
    /// A fresh request was framed and fully written to the hub.
    Sent,
    /// A recent request is still pending an LRPROOF — nothing sent (correct).
    Pending,
    /// No connection, or the hub write failed: nothing went out.
    WriteFailed,
}

/// Send a LINKREQUEST to the propagation node unless one is already pending and
/// recent (expired pending entries are pruned by `pending_link_to`, which is what
/// lets a lost request be retried at all).
fn send_pn_link_request(
    shared: &Arc<Shared>,
    trng: &Trng,
    pn: &[u8; TRUNCATED_HASHLENGTH],
    pn_identity: &reticulum_core::identity::PublicIdentity,
    now: u64,
) -> LinkReqOutcome {
    let raw = {
        let mut tp = shared.transport.lock().unwrap();
        if tp.pending_link_to(pn, now) {
            None
        } else {
            let mut ex = [0u8; KEY_HALF];
            let mut ed = [0u8; KEY_HALF];
            crate::fill_random(trng, &mut ex);
            crate::fill_random(trng, &mut ed);
            Some(tp.make_link_request(pn, pn_identity, &ex, &ed, now).0)
        }
    };
    match raw {
        None => LinkReqOutcome::Pending,
        Some(raw) => {
            if write_to_hub(shared, &raw) {
                LinkReqOutcome::Sent
            } else {
                LinkReqOutcome::WriteFailed
            }
        }
    }
}

/// Continue a pending sync once the link to the node comes up (from the
/// `OutboundLinkUp` event). No-op unless we're mid-sync to this node.
fn sync_on_link_up(shared: &Arc<Shared>, chat_cid: CID, trng: &Trng, link_id: [u8; TRUNCATED_HASHLENGTH], target: [u8; TRUNCATED_HASHLENGTH]) {
    if crate::propagation_node() != Some(target) {
        return;
    }
    let go = {
        let mut s = shared.sync.lock().unwrap();
        if s.phase == SyncPhase::Linking {
            s.link_id = Some(link_id);
            true
        } else {
            false
        }
    };
    if go {
        sync_send_identify_and_list(shared, chat_cid, trng, link_id);
    }
}

/// Identify to the node and request the list of available message ids.
fn sync_send_identify_and_list(shared: &Arc<Shared>, chat_cid: CID, trng: &Trng, link_id: [u8; TRUNCATED_HASHLENGTH]) {
    shared.sync.lock().unwrap().phase = SyncPhase::ListRequested;
    chat::cf_set_status_text_forced(chat_cid, "sync: requesting message list…");
    let mut iv = [0u8; IV_LENGTH];
    crate::fill_random(trng, &mut iv);
    if let Some(idp) = { shared.transport.lock().unwrap().make_out_link_identify(&link_id, &iv) } {
        write_to_hub(shared, &idp);
    }
    // `/get [None, None]` → list of transient ids.
    sync_send_get(shared, trng, link_id, Value::Array(vec![Value::Nil, Value::Nil]));
}

/// Send an RNS request to the node's `/get` handler with `data` as the argument.
fn sync_send_get(shared: &Arc<Shared>, trng: &Trng, link_id: [u8; TRUNCATED_HASHLENGTH], data: Value) {
    let path_hash = truncated_hash(SYNC_GET_PATH);
    let req = Value::Array(vec![Value::F64(now_secs() as f64), Value::Bin(path_hash.to_vec()), data]);
    let packed = msgpack::encode(&req);
    let mut iv = [0u8; IV_LENGTH];
    crate::fill_random(trng, &mut iv);
    if let Some(raw) = { shared.transport.lock().unwrap().make_out_link_context(&link_id, CONTEXT_REQUEST, &packed, &iv) } {
        write_to_hub(shared, &raw);
    }
}

/// Dispatch decrypted out-link data for the active sync (RESPONSE packet, or a
/// RESOURCE advertisement / parts carrying the response).
fn sync_on_outlink_data(
    shared: &Arc<Shared>,
    chat_cid: CID,
    pddb: &Pddb,
    trng: &Trng,
    link_id: [u8; TRUNCATED_HASHLENGTH],
    context: u8,
    plaintext: Vec<u8>,
) {
    {
        let s = shared.sync.lock().unwrap();
        if s.link_id != Some(link_id) || s.phase == SyncPhase::Idle {
            return;
        }
    }
    match context {
        CONTEXT_RESPONSE => {
            if let Some(resp) = parse_rns_response(&plaintext) {
                handle_sync_response(shared, chat_cid, pddb, trng, link_id, resp);
            }
        }
        CONTEXT_RESOURCE_ADV => match ResourceReceiver::accept(&plaintext) {
            Ok(rx) => {
                let req = rx.request_data();
                shared.sync.lock().unwrap().receiver = Some(rx);
                let mut iv = [0u8; IV_LENGTH];
                crate::fill_random(trng, &mut iv);
                if let Some(raw) = { shared.transport.lock().unwrap().make_out_link_context(&link_id, CONTEXT_RESOURCE_REQ, &req, &iv) } {
                    write_to_hub(shared, &raw);
                }
                chat::cf_set_status_text_forced(chat_cid, "sync: downloading…");
            }
            Err(e) => {
                log::warn!("sync resource advertisement rejected: {e}");
                sync_finish(shared, chat_cid, "sync failed (unsupported resource)");
            }
        },
        CONTEXT_RESOURCE => {
            let complete = {
                let mut s = shared.sync.lock().unwrap();
                match &mut s.receiver {
                    Some(rx) => {
                        rx.receive_part(&plaintext);
                        rx.is_complete()
                    }
                    None => false,
                }
            };
            if !complete {
                return;
            }
            // The receiver can vanish between these lock acquisitions (the sync
            // thread's watchdog may sync_finish a stalled sync at any moment), so
            // never unwrap it — bail out instead of panicking the read thread.
            let (stream, encrypted) = {
                let s = shared.sync.lock().unwrap();
                match s.receiver.as_ref() {
                    Some(rx) => (rx.concat(), rx.encrypted()),
                    None => return,
                }
            };
            let plain = if encrypted {
                match { shared.transport.lock().unwrap().decrypt_out_link(&link_id, &stream) } {
                    Some(p) => p,
                    None => {
                        sync_finish(shared, chat_cid, "sync failed (decrypt)");
                        return;
                    }
                }
            } else {
                stream
            };
            let finished = {
                let s = shared.sync.lock().unwrap();
                match s.receiver.as_ref() {
                    Some(rx) => rx.finish(&plain),
                    None => return,
                }
            };
            match finished {
                Ok((payload, proof)) => {
                    if let Some(raw) = { shared.transport.lock().unwrap().make_out_link_resource_proof(&link_id, &proof) } {
                        write_to_hub(shared, &raw);
                    }
                    shared.sync.lock().unwrap().receiver = None;
                    if let Some(resp) = parse_rns_response(&payload) {
                        handle_sync_response(shared, chat_cid, pddb, trng, link_id, resp);
                    }
                }
                Err(e) => {
                    log::warn!("sync resource invalid: {e}");
                    sync_finish(shared, chat_cid, "sync failed (resource)");
                }
            }
        }
        _ => {}
    }
}

/// A `/get` response arrived (the `response` element of `[request_id, response]`).
fn handle_sync_response(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, trng: &Trng, link_id: [u8; TRUNCATED_HASHLENGTH], resp: Value) {
    // Error codes: 240 = no identity, 241 = no access.
    if let Value::Int(code) = resp {
        let why = match code {
            240 => "node needs identification",
            241 => "node denied access",
            _ => "node error",
        };
        sync_finish(shared, chat_cid, why);
        return;
    }
    let phase = shared.sync.lock().unwrap().phase;
    match phase {
        SyncPhase::ListRequested => {
            let ids: Vec<Value> = resp.as_array().map(|a| a.to_vec()).unwrap_or_default();
            if ids.is_empty() {
                sync_finish(shared, chat_cid, "no new messages");
                return;
            }
            let n = ids.len();
            // Request all listed messages: `/get [wants, [], limit]`.
            let data = Value::Array(vec![Value::Array(ids), Value::Array(Vec::new()), Value::Int(SYNC_DELIVERY_LIMIT)]);
            sync_send_get(shared, trng, link_id, data);
            shared.sync.lock().unwrap().phase = SyncPhase::GetRequested;
            chat::cf_set_status_text_forced(chat_cid, &format!("sync: downloading {n} message(s)…"));
        }
        SyncPhase::GetRequested => {
            let blobs: Vec<Value> = resp.as_array().map(|a| a.to_vec()).unwrap_or_default();
            let mut haves: Vec<Value> = Vec::new();
            let mut count = 0;
            for b in &blobs {
                if let Some(bin) = b.as_bin() {
                    deliver_synced_message(shared, chat_cid, pddb, trng, bin);
                    // Confirm by transient id so the node deletes it (LXMF uses
                    // full_hash of the returned, stamp-stripped blob).
                    haves.push(Value::Bin(full_hash(bin).to_vec()));
                    count += 1;
                }
            }
            if !haves.is_empty() {
                // `/get [None, haves]` → node deletes the messages we received.
                sync_send_get(shared, trng, link_id, Value::Array(vec![Value::Nil, Value::Array(haves)]));
            }
            if count > 0 {
                // One buzz for the whole synced batch (deliver_lxmf didn't per-msg).
                shared.llio.vibe(llio::VibePattern::Long).ok();
            }
            sync_finish(shared, chat_cid, &format!("synced {count} message(s)"));
        }
        _ => {}
    }
}

/// Decrypt a synced message blob (`dest_hash(16) || encrypt_to_us(...)`) and route
/// it through the normal inbound path.
fn deliver_synced_message(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, trng: &Trng, blob: &[u8]) {
    if blob.len() <= TRUNCATED_HASHLENGTH {
        return;
    }
    let plaintext = { shared.transport.lock().unwrap().identity().decrypt(&blob[TRUNCATED_HASHLENGTH..], &[]) };
    let plaintext = match plaintext {
        Ok(p) => p,
        Err(e) => {
            log::warn!("synced message decrypt failed: {e}");
            return;
        }
    };
    let mut full = blob[..TRUNCATED_HASHLENGTH].to_vec();
    full.extend_from_slice(&plaintext);
    deliver_lxmf(shared, chat_cid, pddb, trng, &full, false); // synced: batch-buzz instead
}

/// End the current sync (success or failure) and reset the state machine. The
/// link to the node is dropped either way — sync links are one-shot (mirrors the
/// reference client): on failure the link is suspect (a timeout usually MEANS
/// it's dead), and we send no keepalives, so a kept link would quietly die and
/// hang the next sync. Establishment is cheap relative to a 2-minute hang.
fn sync_finish(shared: &Arc<Shared>, chat_cid: CID, msg: &str) {
    let link = {
        let mut s = shared.sync.lock().unwrap();
        s.phase = SyncPhase::Idle;
        s.receiver = None;
        s.requested = false;
        s.route_tries = 0;
        s.link_id.take()
    };
    if let Some(lid) = link {
        shared.transport.lock().unwrap().drop_out_link(&lid);
    }
    let line = format!("sync: {msg}");
    // Persist the result as idle text (so it stays after the transient paint) AND
    // force an immediate repaint, since the normal status redraw is throttled.
    chat::cf_set_status_idle_text(chat_cid, &line);
    chat::cf_set_status_text_forced(chat_cid, &line);
}

/// Parse an RNS response payload `[request_id, response]`, returning `response`.
fn parse_rns_response(payload: &[u8]) -> Option<Value> {
    let v = msgpack::decode(payload).ok()?;
    let arr = v.as_array()?;
    if arr.len() < 2 {
        return None;
    }
    Some(arr[1].clone())
}

fn post_to_chat(shared: &Arc<Shared>, chat_cid: CID, author: &str, timestamp: u64, text: &str) {
    let post = Post {
        dialogue_id: shared.dialogue_id.clone(),
        author: author.to_string(),
        timestamp,
        text: text.to_string(),
        attach_url: None,
    };
    if let Ok(buf) = Buffer::into_buf(post) {
        buf.send(chat_cid, ChatOp::PostAdd as u32).ok();
    }
    xous::send_message(chat_cid, xous::Message::new_scalar(ChatOp::DialogueSave as usize, 0, 0, 0, 0)).ok();
}

/// Find a post by (author, timestamp) in the chat server's *currently active*
/// Persist the active dialogue (after an atomic bubble update).
fn dialogue_save(chat_cid: CID) {
    xous::send_message(chat_cid, xous::Message::new_scalar(ChatOp::DialogueSave as usize, 0, 0, 0, 0)).ok();
}

// ---- Outbound delivery engine -------------------------------------------------

/// Queue a sent message for delivery tracking and kick the pump so the first
/// attempt (or link request) goes out immediately. The caller has already echoed
/// the bubble at `display_ts` with [`MARK_PENDING`].
pub fn enqueue_outbound(
    shared: &Arc<Shared>,
    chat_cid: CID,
    pddb: &Pddb,
    trng: &Trng,
    peer: [u8; TRUNCATED_HASHLENGTH],
    display_ts: u64,
    text: String,
    packed: Vec<u8>,
) {
    shared.outbox.lock().unwrap().push(OutboundMsg {
        peer,
        display_ts,
        text,
        packed,
        via_pn: false,
        tried_pn: false,
        in_flight: None,
        attempts: 0,
        route_tries: 0,
        pn_blob: None,
        next_action: 0,
        created: now_secs(),
        deadline: now_secs() + DIRECT_DEADLINE,
    });
    // Do NOT send here: enqueue_outbound runs on the MAIN (UI) thread (via post()),
    // and pump_outbox does blocking hub writes — a stalled write would freeze the
    // UI and the message bubble would never render. The pump thread picks the
    // message up on its next tick (≤2s) and sends it; the bubble already shows ○.
    let _ = (chat_cid, pddb, trng);
}

/// Background thread: re-drives the outbox every couple of seconds so timeouts,
/// link establishment, and propagation fallback make progress without a network
/// event. One instance for the app's lifetime.
pub fn outbox_pump_thread(shared: Arc<Shared>, chat_cid: CID) {
    let pddb = Pddb::new();
    let trng = match XousNames::new().ok().and_then(|xns| Trng::new(&xns).ok()) {
        Some(t) => t,
        None => {
            log::error!("outbox pump: TRNG init failed");
            return;
        }
    };
    loop {
        std::thread::sleep(std::time::Duration::from_secs(2));
        shared.beat_pump.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        if !shared.outbox.lock().unwrap().is_empty() {
            // Mine any pending propagation stamp first (slow, lock-free), so the
            // blob is ready when pump_outbox reaches the PN-send step. Doing it
            // here keeps the multi-second PoW off the net read loop.
            compute_pending_pn_blob(&shared, chat_cid, &trng);
            pump_outbox(&shared, chat_cid, &pddb, &trng);
        }
    }
}

/// Dedicated propagation-node sync driver, on its OWN thread so a slow outbox op
/// (stalled write / PoW mining) on the pump thread can't delay a sync request, and
/// so a slow sync can't delay message sending. Consumes the manual-sync flag and
/// times out a stalled sync.
pub fn sync_thread(shared: Arc<Shared>, chat_cid: CID) {
    let trng = match XousNames::new().ok().and_then(|xns| Trng::new(&xns).ok()) {
        Some(t) => t,
        None => {
            // Without this thread nothing ever consumes a sync request — make
            // that loudly visible instead of "sync requested…" forever.
            log::error!("sync thread: TRNG init failed");
            chat::cf_set_status_idle_text(chat_cid, "sync unavailable (init failed — restart app)");
            chat::cf_set_status_text_forced(chat_cid, "sync unavailable (init failed — restart app)");
            return;
        }
    };
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        shared.beat_sync.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        maybe_auto_sync(&shared, chat_cid, &trng);
    }
}

// Sync-path progress markers for the `[gN]` diagnostic (see Shared.sync_stage).
// Each is stored just BEFORE the statement it names, so a frozen value points at
// the exact blocking statement:
//  1 maybe_auto_sync entered (about to take the sync lock for the watchdog)
//  2 watchdog done (about to take the sync lock for the linking check)
//  3 linking check done (about to take the sync lock to consume the request)
// 10 request consumed (about to call start_sync)
// 11 start_sync entered (about to take the sync lock for the phase check)
// 12 phase check done (about to read the connected flag)
// 13 connected (about to take the TRANSPORT lock for known/path)
// 14 known/path read (about to take the sync lock to init Linking state)
// 15 Linking state set (about to take the TRANSPORT lock for outbound_link_for)
// 16 no reusable link (about to build + write the LINKREQUEST)
// 17 LINKREQUEST write returned
fn stage(shared: &Arc<Shared>, s: u32) {
    shared.sync_stage.store(s, core::sync::atomic::Ordering::SeqCst);
}

/// Kick off a one-time sync once the propagation node's route is known (after the
/// connect-time path request resolves), and time out a stalled sync. Called on the
/// pump thread's tick so it doesn't block the net read loop.
fn maybe_auto_sync(shared: &Arc<Shared>, chat_cid: CID, trng: &Trng) {
    let pn = match crate::propagation_node() {
        Some(p) => p,
        None => {
            // Still consume a manual request so the user gets an answer instead
            // of "sync requested…" sitting there forever.
            let requested = {
                let mut s = shared.sync.lock().unwrap();
                core::mem::replace(&mut s.requested, false)
            };
            if requested {
                chat::cf_set_status_text_forced(chat_cid, "no propagation node configured");
            }
            return;
        }
    };
    let now = now_secs();
    stage(shared, 1);
    // Time out a stuck sync.
    let stalled = {
        let s = shared.sync.lock().unwrap();
        s.phase != SyncPhase::Idle && now > s.deadline
    };
    if stalled {
        sync_finish(shared, chat_cid, "timed out");
        return;
    }
    stage(shared, 2);
    // Mid-sync, still waiting for the link: if the LINKREQUEST was lost (its
    // pending entry expired with no proof), send a fresh one — otherwise a single
    // lost request used to mean nothing more ever went out and the sync just sat
    // until the watchdog. `send_pn_link_request` no-ops while one is still pending.
    let linking = { shared.sync.lock().unwrap().phase == SyncPhase::Linking };
    if linking {
        let known = { shared.transport.lock().unwrap().known(&pn).cloned() };
        if let Some(k) = known {
            match send_pn_link_request(shared, trng, &pn, &k.identity, now) {
                LinkReqOutcome::Sent => {
                    // Show the retry on the status line: a counter that advances
                    // means the sync thread is alive and writes complete — if the
                    // node still sees nothing, the requests die on the network.
                    let tries = {
                        let mut s = shared.sync.lock().unwrap();
                        s.link_tries = s.link_tries.saturating_add(1);
                        s.link_tries
                    };
                    chat::cf_set_status_text_forced(
                        chat_cid,
                        &format!("sync: contacting node (try {tries})…"),
                    );
                }
                LinkReqOutcome::WriteFailed => {
                    sync_finish(shared, chat_cid, "hub write failed — try again");
                }
                LinkReqOutcome::Pending => {}
            }
        }
        return;
    }
    // A manual sync request (from the menu) is executed HERE — on the sync thread
    // — never on the main thread, so a blocking hub write can't freeze the UI.
    // `next_attempt` is the backoff while the node's route is being resolved.
    stage(shared, 3);
    let requested = {
        let mut s = shared.sync.lock().unwrap();
        if s.requested && now >= s.next_attempt {
            s.requested = false;
            true
        } else {
            false
        }
    };
    if requested {
        stage(shared, 10);
        start_sync(shared, chat_cid, trng); // handles not-ready / already-running itself
        return;
    }
    // Auto-sync on connect is disabled for now (sync is manual via the menu).
    // Flip AUTO_SYNC_ON_CONNECT to re-enable: sync once per app run when the node
    // becomes reachable.
    if AUTO_SYNC_ON_CONNECT {
        let go = {
            let s = shared.sync.lock().unwrap();
            !s.auto_done && s.phase == SyncPhase::Idle
        };
        let ready = go && {
            let tp = shared.transport.lock().unwrap();
            tp.known(&pn).is_some() && tp.has_path(&pn)
        };
        if ready {
            shared.sync.lock().unwrap().auto_done = true;
            start_sync(shared, chat_cid, trng);
        }
    }
}

/// Request a propagation-node sync from the main thread (the menu): just sets a
/// flag the pump thread picks up. Does NO hub I/O, so it can never block the UI.
pub fn request_sync(shared: &Arc<Shared>) {
    shared.sync.lock().unwrap().requested = true;
}

/// Compute, **lock-free**, the propagation blob for at most one outbox message
/// that has escalated to the propagation node and doesn't have one yet. The blob
/// is the message re-encrypted to the recipient plus a proof-of-work *stamp* that
/// the node demands (mining it takes several seconds on the Precursor), so this
/// must run off the outbox lock and off the net read loop — hence its own pass,
/// invoked only from [`outbox_pump_thread`]. Snapshots the inputs under the lock,
/// releases, mines, then stores the result by re-finding the entry (it may have
/// been delivered/removed meanwhile). Returns true if it produced a blob.
fn compute_pending_pn_blob(shared: &Arc<Shared>, chat_cid: CID, trng: &Trng) -> bool {
    // One message that's on the PN path and still needs a stamp.
    let job = {
        let outbox = shared.outbox.lock().unwrap();
        outbox
            .iter()
            .find(|m| m.via_pn && m.pn_blob.is_none())
            .map(|m| (m.peer, m.display_ts, m.packed.clone()))
    };
    let (peer, display_ts, packed) = match job {
        Some(j) => j,
        None => return false,
    };
    // We encrypt the stored copy *to the recipient*, so we need their key. If we
    // don't have it yet, pump_outbox is already requesting it — try again later.
    let known = { shared.transport.lock().unwrap().known(&peer).cloned() };
    let known = match known {
        Some(k) => k,
        None => return false,
    };

    let label = peer_label(shared, &peer);
    chat::cf_set_status_text(chat_cid, &format!("{label}: computing propagation stamp…"));

    let mut eph = [0u8; KEY_HALF];
    let mut iv = [0u8; IV_LENGTH];
    crate::fill_random(trng, &mut eph);
    crate::fill_random(trng, &mut iv);

    // Slow: builds the ~256 KB workblock and mines the PoW stamp. Lock-free.
    let blob = lxmf::message::pack_propagation(
        &known.identity,
        &peer,
        &packed[TRUNCATED_HASHLENGTH..],
        known.ratchet.as_ref(),
        &eph,
        &iv,
        now_secs() as f64,
        crate::propagation_cost(),
    );

    // Store it back by re-finding the entry; it may have been removed/delivered.
    let mut outbox = shared.outbox.lock().unwrap();
    if let Some(m) = outbox.iter_mut().find(|m| m.peer == peer && m.display_ts == display_ts) {
        m.pn_blob = Some(blob);
    }
    true
}

/// Advance every outbound message: (re)establish the link to its target (the peer,
/// or the propagation node once direct delivery has timed out), send it, and on
/// proof timeout escalate direct→propagation→failed. Idempotent and cheap to call
/// often (on a timer, on link-up, and right after enqueue).
fn pump_outbox(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, trng: &Trng) {
    let pn = crate::propagation_node();
    let now = now_secs();
    // Each failure carries a short reason so the user can see *why* a message
    // ended at ✗ (the intermediate statuses flash by) — routing vs no ack vs PN.
    let mut failures: Vec<([u8; TRUNCATED_HASHLENGTH], u64, String, &'static str)> = Vec::new();

    {
        let mut outbox = shared.outbox.lock().unwrap();
        let mut i = 0;
        while i < outbox.len() {
            // 0. The current phase's independent time budget is up.
            if now > outbox[i].deadline {
                let m = outbox.remove(i);
                let why = if m.via_pn {
                    "propagation node unconfirmed"
                } else if m.attempts == 0 && !m.tried_pn {
                    "no route found"
                } else {
                    "no acknowledgement"
                };
                failures.push((m.peer, m.display_ts, m.text, why));
                continue;
            }

            // 1. Awaiting a delivery proof?
            if outbox[i].in_flight.is_some() {
                if now < outbox[i].next_action {
                    i += 1;
                    continue;
                }
                outbox[i].in_flight = None; // proof timed out
                let label = peer_label(shared, &outbox[i].peer);
                if !outbox[i].via_pn {
                    if outbox[i].attempts < MAX_ATTEMPTS {
                        // retry opportunistically (falls through to the send below)
                    } else if !outbox[i].tried_pn && pn.is_some() {
                        // Escalate to the propagation node with its OWN fresh time
                        // budget — the direct phase's spent time doesn't count
                        // against it (mirrors LXMF's per-method attempt budgets).
                        outbox[i].via_pn = true;
                        outbox[i].deadline = now + PROP_DEADLINE;
                        chat::cf_set_status_text(chat_cid, &format!("{label}: no confirmation — trying propagation node…"));
                    } else {
                        // Reached the network (we sent it) but never got a proof:
                        // recipient dropped it (e.g. stamp rejected) or the proof
                        // was lost. No PN configured / already tried.
                        let m = outbox.remove(i);
                        failures.push((m.peer, m.display_ts, m.text, "no acknowledgement"));
                        continue;
                    }
                } else {
                    // A propagation send went unproven: retry within the propagation
                    // budget (re-send / re-establish the link via the via_pn block
                    // below) rather than giving up on the first timeout — the PROP
                    // deadline check above fails it once that budget is exhausted.
                    chat::cf_set_status_text(chat_cid, &format!("{label}: retrying propagation node…"));
                }
            } else if now < outbox[i].next_action {
                i += 1;
                continue; // backing off after a key/path request
            }

            if outbox[i].via_pn {
                // ---- Propagation fallback: store the message at the node, sent
                // over a link to it (the node returns a proof → ⇪). ----
                let target = pn.unwrap();
                let (known, have_path) = {
                    let tp = shared.transport.lock().unwrap();
                    (tp.known(&target).cloned(), tp.has_path(&target))
                };
                let known = match known {
                    Some(k) => k,
                    None => {
                        request_peer_key(shared, trng, &target);
                        outbox[i].next_action = now + KEY_RETRY;
                        i += 1;
                        continue;
                    }
                };
                // Need a route to the node before opening the link (the link
                // request is addressed to the node's destination, which may be
                // multiple hops away — see the opportunistic branch).
                if !have_path {
                    request_peer_key(shared, trng, &target);
                    outbox[i].next_action = now + KEY_RETRY;
                    i += 1;
                    continue;
                }
                let link = { shared.transport.lock().unwrap().outbound_link_for(&target, now) };
                let link = match link {
                    Some(l) => l,
                    None => {
                        send_pn_link_request(shared, trng, &target, &known.identity, now);
                        let label = peer_label(shared, &outbox[i].peer);
                        chat::cf_set_status_text(chat_cid, &format!("{label}: contacting propagation node…"));
                        outbox[i].next_action = now + LINK_RETRY;
                        i += 1;
                        continue;
                    }
                };
                // The propagation blob (encrypted message + PoW stamp) is computed
                // lock-free by `compute_pending_pn_blob` (the stamp takes seconds);
                // wait a tick if it isn't ready yet.
                let blob = match &outbox[i].pn_blob {
                    Some(b) => b.clone(),
                    None => {
                        outbox[i].next_action = now + 1;
                        i += 1;
                        continue;
                    }
                };
                let mut div = [0u8; IV_LENGTH];
                crate::fill_random(trng, &mut div);
                let sent = { shared.transport.lock().unwrap().make_link_data(&link, &blob, &div) };
                match sent {
                    Some((raw, packet_hash)) => {
                        write_to_hub(shared, &raw);
                        outbox[i].in_flight = Some(packet_hash);
                        outbox[i].tried_pn = true;
                        outbox[i].next_action = now + PROOF_TIMEOUT;
                        let label = peer_label(shared, &outbox[i].peer);
                        chat::cf_set_status_text(chat_cid, &format!("{label}: sending to propagation node…"));
                    }
                    None => outbox[i].next_action = now + 2,
                }
            } else {
                // ---- Primary: opportunistic delivery, acknowledged by the
                // recipient's returned proof (this is how LXMF/NomadNet confirms
                // delivery — the receiver proves every delivered packet). ----
                let (known, have_path) = {
                    let tp = shared.transport.lock().unwrap();
                    (tp.known(&outbox[i].peer).cloned(), tp.has_path(&outbox[i].peer))
                };
                let known = match known {
                    Some(k) => k,
                    None => {
                        request_peer_key(shared, trng, &outbox[i].peer);
                        outbox[i].next_action = now + KEY_RETRY;
                        i += 1;
                        continue;
                    }
                };
                // Even with the peer's key, we need a current route: a transport
                // node will not forward a packet to a destination >1 hop away
                // unless it is addressed via that node (HEADER_2). Request a path
                // (re-announce) and wait — mirrors RNS requesting a path before
                // sending. The announce response teaches us the next hop.
                if !have_path {
                    let label = peer_label(shared, &outbox[i].peer);
                    // If the route never resolves (peer offline / unannounced), fall
                    // back to the propagation node rather than spinning until the
                    // deadline — the PN can still store-and-forward for an offline
                    // peer (LXMF does the same after its pathless tries).
                    if outbox[i].route_tries >= MAX_ROUTE_TRIES && !outbox[i].tried_pn && pn.is_some() {
                        outbox[i].via_pn = true;
                        outbox[i].deadline = now + PROP_DEADLINE; // fresh, independent budget
                        outbox[i].next_action = now; // act on the PN path immediately
                        chat::cf_set_status_text(chat_cid, &format!("{label}: no route — trying propagation node…"));
                        continue; // re-enter the loop on this same message via the PN branch
                    }
                    request_peer_key(shared, trng, &outbox[i].peer);
                    outbox[i].route_tries += 1;
                    chat::cf_set_status_text(chat_cid, &format!("{label}: finding a route…"));
                    outbox[i].next_action = now + KEY_RETRY;
                    i += 1;
                    continue;
                }
                let mut eph = [0u8; KEY_HALF];
                let mut iv = [0u8; IV_LENGTH];
                crate::fill_random(trng, &mut eph);
                crate::fill_random(trng, &mut iv);
                let peer = outbox[i].peer;
                let (raw, full_hash) = {
                    let mut tp = shared.transport.lock().unwrap();
                    tp.make_opportunistic_tracked(
                        &peer, &known.identity, known.ratchet.as_ref(), &outbox[i].packed[TRUNCATED_HASHLENGTH..], &eph, &iv,
                    )
                };
                write_to_hub(shared, &raw);
                outbox[i].in_flight = Some(full_hash);
                outbox[i].attempts += 1;
                outbox[i].next_action = now + DELIVERY_RETRY;
                let label = peer_label(shared, &outbox[i].peer);
                chat::cf_set_status_text(chat_cid, &format!("{label}: sent, awaiting confirmation…"));
            }
            i += 1;
        }
    }

    for (peer, ts, text, why) in failures {
        let label = peer_label(shared, &peer);
        chat::cf_set_status_idle_text(chat_cid, &format!("\u{00d7} {label}: {why}"));
        update_mark(shared, chat_cid, pddb, &peer, ts, &text, STATUS_FAILED);
    }
}

/// A packet proof arrived: find the matching outbound message and mark it
/// delivered (✓) or stored-at-node (⇪), depending on how it was sent.
fn mark_delivered(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, packet_hash: &[u8; 32]) {
    let done = {
        let mut outbox = shared.outbox.lock().unwrap();
        outbox.iter().position(|m| m.in_flight == Some(*packet_hash)).map(|pos| {
            let m = outbox.remove(pos);
            let status = if m.via_pn { STATUS_QUEUED } else { STATUS_DELIVERED };
            (m.peer, m.display_ts, m.text, status)
        })
    };
    if let Some((peer, ts, text, status)) = done {
        let label = peer_label(shared, &peer);
        let note = if status == STATUS_QUEUED {
            format!("⇪ stored at propagation node for {label}")
        } else {
            format!("✓ delivered to {label}")
        };
        chat::cf_set_status_text(chat_cid, &note);
        update_mark(shared, chat_cid, pddb, &peer, ts, &text, status);
    }
}

/// Swap a sent message's bubble to show its new delivery mark. Uses a single
/// atomic find-and-replace (by author + timestamp), so concurrent posts from
/// other messages can't cause the wrong bubble to be edited. If the message's
/// thread isn't the active dialogue, the update is held (persisted) and applied
/// when the user opens that thread.
fn update_mark(
    shared: &Arc<Shared>,
    chat_cid: CID,
    pddb: &Pddb,
    peer: &[u8; TRUNCATED_HASHLENGTH],
    display_ts: u64,
    text: &str,
    status: u8,
) {
    let new_text = bubble_text(text, status_mark(status));
    if chat::cf_post_update(chat_cid, chat::SELF_AUTHOR, display_ts, &new_text) {
        dialogue_save(chat_cid); // updated in the active dialogue; persist it
        return;
    }
    // Not the active thread: defer + persist (mirrors the inbound pending queue).
    let mut map = shared.delivery_updates.lock().unwrap();
    let list = map.entry(*peer).or_default();
    list.push(DeliveryUpdate { display_ts, text: text.to_string(), status });
    crate::persist_delivery_updates(pddb, peer, list);
}

/// Apply any held delivery-mark updates for `peer` to the now-active dialogue
/// (called from `activate_peer` after the dialogue is switched). Clears them.
pub fn apply_delivery_updates(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, peer: &[u8; TRUNCATED_HASHLENGTH]) {
    let updates = shared.delivery_updates.lock().unwrap().remove(peer);
    if let Some(updates) = updates {
        for u in &updates {
            chat::cf_post_update(chat_cid, chat::SELF_AUTHOR, u.display_ts, &bubble_text(&u.text, status_mark(u.status)));
        }
        dialogue_save(chat_cid);
        crate::delete_delivery_updates(pddb, peer);
    }
}
