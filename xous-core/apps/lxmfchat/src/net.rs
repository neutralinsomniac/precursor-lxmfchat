//! Background network thread: reads HDLC frames off the hub TCP socket, drives
//! the sans-IO [`Transport`], learns/persists contacts from announces, answers
//! inbound link requests, and posts inbound LXMF messages into the chat UI.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use chat::{ChatOp, Post};
use pddb::Pddb;
use reticulum_core::constants::{IV_LENGTH, KEY_HALF, TRUNCATED_HASHLENGTH};
use reticulum_core::hdlc::{Deframer, frame};
use reticulum_core::transport::{Event, Transport};
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

/// State shared between the app's main thread and the network RX thread.
pub struct Shared {
    pub transport: Mutex<Transport>,
    /// The write half of the hub connection (None until connected).
    pub writer: Mutex<Option<TcpStream>>,
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
                match stream.try_clone() {
                    Ok(reader) => {
                        *shared.writer.lock().unwrap() = Some(stream);
                        backoff = 2;
                        chat::cf_set_status_text(chat_cid, &format!("connected to {hub}"));
                        send_announce(&shared, &trng);
                        // Proactively learn the propagation node's route now, so a
                        // later store-and-forward fallback doesn't have to discover
                        // it mid-escalation (which burns the retry deadline).
                        request_propagation_path(&shared, &trng);
                        read_until_closed(&shared, chat_cid, &pddb, &trng, reader);
                        *shared.writer.lock().unwrap() = None;
                        chat::cf_set_status_text(chat_cid, "hub connection lost — reconnecting…");
                    }
                    Err(e) => {
                        *shared.writer.lock().unwrap() = None;
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
            deliver_lxmf(shared, chat_cid, pddb, trng, &lxmf_bytes);
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
            deliver_lxmf(shared, chat_cid, pddb, trng, &plaintext);
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
            pump_outbox(shared, chat_cid, pddb, trng);
        }
        // A packet proof confirmed one of our sent messages reached its target.
        Event::Delivered { packet_hash } => {
            mark_delivered(shared, chat_cid, pddb, &packet_hash);
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
fn deliver_lxmf(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, trng: &Trng, lxmf_bytes: &[u8]) {
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
pub fn keepalive_thread(shared: Arc<Shared>) {
    const KEEPALIVE_SECS: u64 = 60;
    let empty = frame(&[]);
    // Runs for the app's lifetime (one instance). Sends a keepalive whenever a
    // connection exists; stays quiet while the manager is reconnecting. Write
    // errors are ignored — the read loop/manager detects the drop and reconnects.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(KEEPALIVE_SECS));
        if let Some(s) = shared.writer.lock().unwrap().as_mut() {
            let _ = s.write_all(&empty).and_then(|_| s.flush());
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

fn write_to_hub(shared: &Arc<Shared>, raw: &[u8]) {
    let framed = frame(raw);
    if let Some(w) = shared.writer.lock().unwrap().as_mut() {
        let _ = w.write_all(&framed).and_then(|_| w.flush());
    }
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
    pump_outbox(shared, chat_cid, pddb, trng);
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
        if !shared.outbox.lock().unwrap().is_empty() {
            // Mine any pending propagation stamp first (slow, lock-free), so the
            // blob is ready when pump_outbox reaches the PN-send step. Doing it
            // here keeps the multi-second PoW off the net read loop.
            compute_pending_pn_blob(&shared, chat_cid, &trng);
            pump_outbox(&shared, chat_cid, &pddb, &trng);
        }
    }
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
                let link = { shared.transport.lock().unwrap().outbound_link_for(&target) };
                let link = match link {
                    Some(l) => l,
                    None => {
                        let raw = {
                            let mut tp = shared.transport.lock().unwrap();
                            if tp.pending_link_to(&target) {
                                None
                            } else {
                                let mut ex = [0u8; KEY_HALF];
                                let mut ed = [0u8; KEY_HALF];
                                crate::fill_random(trng, &mut ex);
                                crate::fill_random(trng, &mut ed);
                                Some(tp.make_link_request(&target, &known.identity, &ex, &ed).0)
                            }
                        };
                        if let Some(raw) = raw {
                            write_to_hub(shared, &raw);
                            let label = peer_label(shared, &outbox[i].peer);
                            chat::cf_set_status_text(chat_cid, &format!("{label}: contacting propagation node…"));
                        }
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
