//! Background network thread: reads HDLC frames off the hub TCP socket, drives
//! the sans-IO [`Transport`], learns/persists contacts from announces, answers
//! inbound link requests, and posts inbound LXMF messages into the chat UI.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use chat::{ChatOp, Post};
use pddb::Pddb;
use reticulum_core::constants::{
    CONTEXT_REQUEST, CONTEXT_RESOURCE, CONTEXT_RESOURCE_ADV, CONTEXT_RESOURCE_HMU,
    CONTEXT_RESOURCE_REQ, CONTEXT_RESPONSE, IV_LENGTH, KEY_HALF, SIG_LENGTH, TRUNCATED_HASHLENGTH,
};
use reticulum_core::crypto::{full_hash, truncated_hash};
use reticulum_core::hdlc::{Deframer, frame};
use reticulum_core::resource::ResourceReceiver;
use reticulum_core::transport::{Event, PathIface, Transport};
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
pub const MARK_SYNCED: &str = "»"; // received via the propagation node (downloaded by sync)
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
const MAX_LINK_TRIES: u8 = 3; // link requests (each gets its ~20 s answer window) before the PN
/// Whether to sync from the propagation node automatically on first connect.
/// Runs once per app run, as soon as the node's route resolves; the "Sync
/// messages" menu remains for manual re-syncs.
const AUTO_SYNC_ON_CONNECT: bool = true;
/// Cap on concurrent inbound Resource downloads (peers sending large direct
/// messages). One per link; oldest evicted.
const MAX_IN_RESOURCES: usize = 4;
/// Cap on remembered shared addresses awaiting "Import contact" (oldest dropped).
const MAX_FOUND_ADDRS: usize = 16;
/// Largest `packed` LXMF that fits a single link DATA packet (the RNS link
/// MDU bounds the per-packet plaintext at 431 bytes; LXMF's 319-byte content
/// limit is that minus its 112 bytes of overhead). Bigger messages would need
/// an outbound Resource sender (not implemented) — they go store-and-forward
/// via the propagation node instead.
const LINK_PACKED_MAX: usize = 431;
/// A backchannel idle past this is not used for replies (the initiator
/// keepalives every 360 s and LXMF closes idle links at 600 s; our keepalive
/// echoes refresh the clock, so an alive link stays usable indefinitely).
const BACKCHANNEL_MAX_IDLE: u64 = 540;
/// Proof wait for a message sent as a Resource (multiple request/part round
/// trips before the receiver can prove it) — longer than the single-packet
/// DELIVERY_RETRY. On timeout the send is retried as a fresh resource.
const RESOURCE_RETRY: u64 = 45;

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
    /// Some(cost) while the recipient's required proof-of-work delivery stamp
    /// is still unmined. The pump thread mines it (see
    /// [`compute_pending_delivery_stamp`]) and appends it to `packed`; nothing
    /// is sent until then. None = ready (no cost, ticket-stamped, or mined).
    pub needs_stamp: Option<u32>,
    /// `packed` already carries a (ticket) stamp. Distinct from `needs_stamp`
    /// being None — the recipient's stamp cost may be UNKNOWN at enqueue time
    /// (key not learned yet); when their announce later reveals a cost, an
    /// unstamped, not-yet-sent message gets `needs_stamp` set, but a
    /// ticket-stamped one must not be double-stamped.
    pub stamped: bool,
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
    /// LINKREQUESTs actually sent while establishing our own link to the peer.
    /// Deliberately separate from `route_tries`: a send right after a hub
    /// reconnect legitimately spends route tries first (paths are session
    /// state), and when both phases shared one counter the link phase arrived
    /// with its budget already spent — escalating to the propagation node two
    /// seconds after the first "establishing link…".
    pub link_tries: u8,
    /// What the last pump pass found missing: true = the peer's identity key
    /// itself, false = just a fresh route. Only used to phrase the "…— sending"
    /// status honestly when the awaited announce arrives ("key" vs "route" —
    /// a route refresh is normal once per peer per session and shouldn't read
    /// like a missing key).
    pub awaiting_key: bool,
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
    /// One-shot guard so we auto-sync only once per app run.
    auto_done: bool,
    /// Earliest time to (re)probe for the propagation node's route while the
    /// auto-sync is still pending. The hub connect path requests it too, but a
    /// local-only session has no connect event — the sync thread probes over
    /// whatever interface is up.
    pn_probe_at: u64,
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
            pn_probe_at: 0,
            requested: false,
            next_attempt: 0,
            route_tries: 0,
            link_tries: 0,
        }
    }
}

/// A fully-specified page location: node, path, and URL variables.
pub type PageAddr = ([u8; TRUNCATED_HASHLENGTH], String, Vec<(String, String)>);

/// Stage of a NomadNet page fetch (the node browser). One at a time.
#[derive(Clone, Copy, PartialEq)]
enum BrowserPhase {
    Idle,
    /// Waiting for the link to the node to come up.
    Linking,
    /// Request sent; awaiting the RESPONSE packet or response Resource.
    Fetching,
}

/// State of the node page browser: the in-flight fetch (mirrors [`SyncState`]'s
/// proven lifecycle) plus the navigation state of the shown page.
pub struct BrowserState {
    phase: BrowserPhase,
    /// The node the in-flight fetch targets.
    node: Option<[u8; TRUNCATED_HASHLENGTH]>,
    /// The page path being fetched (e.g. "/page/index.mu").
    path: String,
    /// URL variables of the in-flight fetch (sent as `{"var_<k>": v}` request
    /// data, like NomadNet).
    vars: Vec<(String, String)>,
    /// The established outbound link id to the node.
    link_id: Option<[u8; TRUNCATED_HASHLENGTH]>,
    /// In-progress Resource download of a large page.
    receiver: Option<ResourceReceiver>,
    /// Wall-clock deadline; the fetch aborts if it stalls past this.
    deadline: u64,
    /// Set by [`request_page`] (the menu / a key, on the main thread) and
    /// consumed by the browser thread — no hub I/O ever runs on the UI thread.
    requested: Option<PageAddr>,
    /// Earliest time the browser thread should act on `requested` (the retry
    /// backoff while the node's key/route resolves).
    next_attempt: u64,
    /// Times a requested fetch was deferred for want of the node's key/route.
    route_tries: u8,
    /// LINKREQUESTs sent for this fetch.
    link_tries: u8,
    /// The page currently displayed, for relative links and the back stack.
    current: Option<PageAddr>,
    /// Whether the in-flight fetch should push the current page onto the back
    /// stack when it renders (true for following a link, false for back).
    pending_push: bool,
    /// Whether the in-flight fetch is a back-navigation: its target is the TOP
    /// back-stack entry, removed only when the page renders. Popping up front
    /// lost the entry whenever the fetch failed (e.g. hub connection down).
    pending_pop: bool,
    /// Pages to return to with the back key (newest last). Vars ride along so
    /// returning to e.g. a `g=mirrors` group page re-requests the same view.
    back: Vec<PageAddr>,
    /// Links of the displayed page, indexed by the DocLine link id.
    pub links: Vec<micron::Link>,
    /// The displayed page's title (its first heading), for bookmark labels.
    current_title: Option<String>,
    /// Whether the document view is currently shown (the app's key handling
    /// switches to browser bindings while true).
    pub viewing: bool,
}

impl BrowserState {
    pub fn new() -> BrowserState {
        BrowserState {
            phase: BrowserPhase::Idle,
            node: None,
            path: String::new(),
            vars: Vec::new(),
            link_id: None,
            receiver: None,
            deadline: 0,
            requested: None,
            next_attempt: 0,
            route_tries: 0,
            link_tries: 0,
            current: None,
            pending_push: false,
            pending_pop: false,
            back: Vec::new(),
            links: Vec::new(),
            current_title: None,
            viewing: false,
        }
    }
}

/// State shared between the app's main thread and the network RX thread.
pub struct Shared {
    pub transport: Mutex<Transport>,
    /// The write half of the hub connection (None until connected).
    ///
    /// LOCK DISCIPLINE: only [`hub_write`] (with a BOUNDED try_lock wait) and
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
    /// Unix seconds (truncated to u32) when we last read ANY bytes from the
    /// hub. A socket that died while the device slept never errors out on its
    /// own — writes keep buffering into the net stack and the blocked read
    /// never returns — so inbound silence is the only death signal we get. The
    /// keepalive thread probes a stale connection (path request for our own
    /// destination, which the hub must answer) and forces a reconnect when the
    /// probes go unanswered.
    pub last_inbound: core::sync::atomic::AtomicU32,
    /// WHY the current/last connection went down — "closed by hub", "read
    /// failed: …", "woke from sleep", … . First cause wins (a forced reconnect
    /// also makes the read loop exit; the trigger is the interesting part, not
    /// the fallout), recorded via [`note_disconnect`], consumed and shown by the
    /// connection manager after the read loop exits, cleared on connect. This is
    /// what tells a user WHICH LAYER is losing the connection.
    pub disconnect_reason: Mutex<Option<String>>,
    /// The hub to (re)connect to, as `host:port`. Read by the connection manager
    /// each cycle so a "Set hub" takes effect on the next (re)connect.
    pub hub: Mutex<String>,
    /// When false the connection manager neither dials nor redials (local-only
    /// operation); the toggle that clears it also tears down the live socket.
    pub hub_enabled: core::sync::atomic::AtomicBool,
    /// Our own lxmf.delivery destination hash.
    pub our_dh: [u8; TRUNCATED_HASHLENGTH],
    /// The display name we announce (announce app_data, legacy raw-utf8 form).
    /// User-settable from the menu; persisted under `KEY_NAME`.
    pub display_name: Mutex<String>,
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
    /// The conversation we were in before the current one — F2 jumps back to
    /// it (and `activate_peer` records the swap, so F2 toggles between two).
    pub prev_peer: Mutex<Option<[u8; TRUNCATED_HASHLENGTH]>>,
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
    /// Open backchannels: peers who established a link TO us and identified
    /// themselves on it (LINKIDENTIFY) — replies to them can ride that link
    /// with no reverse handshake (the LXMF backchannel). dest hash →
    /// (inbound link id, last-activity secs). Entries idle past
    /// [`BACKCHANNEL_MAX_IDLE`] are dropped at use; cleared on reconnect.
    pub backchannels: Mutex<BTreeMap<[u8; TRUNCATED_HASHLENGTH], ([u8; TRUNCATED_HASHLENGTH], u64)>>,
    /// LXMF addresses spotted in inbound message text (32-hex tokens), newest
    /// last — so a contact can be shared by simply messaging us their address
    /// ("here's Bob: <hex>") and imported from the menu, with no announce and
    /// no manual hex entry. Each entry: (address, label of who sent it, when).
    /// Bounded; persisted (PDDB `found_addrs`) so an address received before a
    /// reboot is still importable after it.
    pub found_addrs: Mutex<Vec<([u8; TRUNCATED_HASHLENGTH], String, u64)>>,
    /// Delivery stamp costs peers have announced (msgpack element 1 of an
    /// lxmf.delivery announce). A message to one of these peers must carry a
    /// stamp: a ticket-derived one if they trusted us, else mined
    /// proof-of-work. In-memory: the route resolution before any send brings
    /// us their announce (path response), so the cost is known by send time.
    pub stamp_costs: Mutex<BTreeMap<[u8; TRUNCATED_HASHLENGTH], u32>>,
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
    /// Live directory of NomadNet node announces seen this session:
    /// node dest hash -> (node name, last-seen unix seconds). In-memory only.
    pub nodes_seen: Mutex<BTreeMap<[u8; TRUNCATED_HASHLENGTH], (String, u64)>>,
    /// Nodes the user has browsed: dest hash -> name. Persisted (lxmf.nodes).
    pub saved_nodes: Mutex<BTreeMap<[u8; TRUNCATED_HASHLENGTH], String>>,
    /// Node page browser state machine (fetch + navigation).
    pub browser: Mutex<BrowserState>,
    /// In-progress inbound Resource downloads — direct messages too large for a
    /// single link packet, arriving on links peers opened to us — keyed by link
    /// id. Bounded by [`MAX_IN_RESOURCES`]; cleared on reconnect (the links die
    /// with the hub connection).
    pub in_resources: Mutex<BTreeMap<[u8; TRUNCATED_HASHLENGTH], ResourceReceiver>>,
    /// Low-level I/O handle, used to buzz the vibration motor on a new inbound
    /// message. `vibe` is a fire-and-forget scalar, safe to call from any thread.
    pub llio: llio::Llio,
    /// AutoInterface (local-network peering) state.
    pub auto: Mutex<crate::autoiface::AutoState>,
    /// Atomic so the outbound hot path checks it without a lock.
    pub auto_enabled: core::sync::atomic::AtomicBool,
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
        .or_else(|| plock(&shared.seen).get(peer).map(|(n, _)| n.clone()))
        .unwrap_or_else(|| hex(&peer[..4]))
}

/// The next conversation to catch up on: the unread chat whose oldest held
/// message arrived earliest, so repeated F1 presses walk the unread chats in
/// the order the messages came in. Returns its address and unread count.
pub fn first_unread(shared: &Arc<Shared>) -> Option<([u8; TRUNCATED_HASHLENGTH], u32)> {
    // Snapshot, then consult `pending` — never hold both locks at once.
    let unread: Vec<_> =
        plock(&shared.unread).iter().filter(|(_, n)| **n > 0).map(|(h, n)| (*h, *n)).collect();
    let pending = plock(&shared.pending);
    unread.into_iter().min_by_key(|(h, _)| {
        pending.get(h).and_then(|l| l.first()).map(|(_, ts, _)| *ts).unwrap_or(u64::MAX)
    })
}

/// A peer name short enough for an F-key helper slot (a quarter screen wide,
/// ~11 narrow glyphs); `max` leaves room for whatever shares the slot.
fn slot_label(shared: &Arc<Shared>, peer: &[u8; TRUNCATED_HASHLENGTH], max: usize) -> String {
    peer_label(shared, peer).chars().take(max).collect()
}

/// Recompose the persistent status line ("◉ <who you're talking to>") and the
/// F-key helper tray: F1 shows the next unread chat and its count ("✉bob 2"),
/// F2 the conversation it jumps back to ("↩alice"); blank when idle. Call
/// whenever any of that changes (peer switch, message held, unread flushed).
pub fn refresh_idle_status(shared: &Arc<Shared>, chat_cid: CID) {
    // While the page browser is on screen the tray belongs to it (back/open/
    // exit) and the idle status shows the page — a message arriving mid-browse
    // must not clobber them. browser_suspend re-calls this to catch up.
    if plock(&shared.browser).viewing {
        return;
    }
    let current = *plock(&shared.current_peer);
    let line = match current {
        Some(p) => format!("\u{25c9} {}", peer_label(shared, &p)),
        None => String::new(),
    };
    chat::cf_set_status_idle_text(chat_cid, &line);
    let f1 = match first_unread(shared) {
        Some((peer, n)) => format!("\u{2709}{} {n}", slot_label(shared, &peer, 8)),
        None => String::new(),
    };
    chat::cf_icontray_set(chat_cid, 0, &f1);
    let f2 = match *plock(&shared.prev_peer) {
        Some(p) if current != Some(p) => format!("\u{21a9}{}", slot_label(shared, &p, 10)),
        _ => String::new(),
    };
    chat::cf_icontray_set(chat_cid, 1, &f2);
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Block until libstd's wall-clock time server (the well-known
/// "timeserverpublic", registered by the dns service during boot) exists. The
/// kernel parks a connect to a not-yet-existing server and retries it
/// internally, so this is simply a blocking connect — it returns as soon as
/// the server is up. Belt-and-suspenders for threads that use wall-clock time
/// from the first instant of boot (we're the boot app). Hosted mode uses the
/// host clock directly; nothing to wait for there.
///
/// NOTE the panic "failed to request utc time in ms: the requested server
/// could not be found" is NOT a boot race: it means the process's (deduped,
/// shared!) connection to the time server was DISCONNECTED — e.g. by dropping
/// a temporary `llio::LocalTime`, whose refcounted Drop severs the very
/// connection libstd caches for `SystemTime::now()`. Never let the last
/// `LocalTime` in a process drop.
pub(crate) fn wait_for_time_server() {
    #[cfg(target_os = "xous")]
    {
        let _ = xous::connect(xous::SID::from_bytes(b"timeserverpublic").unwrap());
    }
}

/// Connection manager: keeps a live connection to `shared.hub`, automatically
/// reconnecting (with capped backoff) whenever it drops. Runs for the lifetime
/// of the app — one instance, started on the first `connect()`. On each
/// successful connect it announces our destination and runs the read loop until
/// the socket closes, then loops to reconnect.
pub fn connection_manager(shared: Arc<Shared>, chat_cid: CID) {
    wait_for_time_server();
    let pddb = Pddb::new();
    let trng = match XousNames::new().ok().and_then(|xns| Trng::new(&xns).ok()) {
        Some(t) => t,
        None => {
            log::error!("lxmf connection manager: TRNG init failed");
            return;
        }
    };
    // On hardware, the wifi link takes a while to associate + DHCP after boot;
    // the net service reports an IPv4 config only once that's done. Hosted mode
    // rides the host OS's network (no DHCP event ever arrives there), so the
    // readiness check is hardware-only.
    #[cfg(target_os = "xous")]
    let netmgr = net::NetManager::new();
    let mut backoff = 2u64;
    // The previous drop's cause + uptime, echoed in the next "connected" status:
    // the "link lost" line alone only shows for the backoff seconds, too brief
    // to diagnose from; this keeps the answer on screen until the next event.
    let mut last_drop: Option<String> = None;
    loop {
        if !shared.hub_enabled.load(core::sync::atomic::Ordering::SeqCst) {
            backoff = 2;
            std::thread::sleep(std::time::Duration::from_secs(3));
            continue;
        }
        let hub = plock(&shared.hub).clone();
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

        // Don't dial until the network is actually up — connecting into a down
        // interface just burns long connect timeouts and clutters the status bar
        // with failures that aren't the hub's fault.
        #[cfg(target_os = "xous")]
        {
            let mut waited = false;
            while netmgr.get_ipv4_config().is_none() {
                if !waited {
                    chat::cf_set_status_text(chat_cid, "waiting for wifi…");
                    waited = true;
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            if waited {
                backoff = 2; // network just came up: connect promptly
            }
        }

        chat::cf_set_status_text(chat_cid, &format!("connecting to {hub}…"));
        // Resolve, then dial with an EXPLICIT timeout. A plain connect() carries
        // no deadline into the net service, and a connection stuck in SynSent
        // with no expiry waits there forever — a SYN blackholed right after a
        // wake (wifi still re-associating) would stall the manager for good.
        let dialed = (host.as_str(), port).to_socket_addrs().map_err(|e| e.to_string()).and_then(
            |mut addrs| match addrs.next() {
                Some(addr) => TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(15))
                    .map_err(|e| e.to_string()),
                None => Err("no address".to_string()),
            },
        );
        match dialed {
            Ok(stream) => {
                stream.set_nodelay(true).ok();
                // Bound hub writes so a stalled socket (e.g. during a resource
                // transfer) can't block a writer forever and wedge the threads
                // that share it (no-op if the Xous TcpStream ignores it).
                stream.set_write_timeout(Some(std::time::Duration::from_secs(10))).ok();
                let clones = stream.try_clone().and_then(|r| stream.try_clone().map(|c| (r, c)));
                match clones {
                    Ok((reader, ctl)) => {
                        *plock(&shared.writer) = Some(stream);
                        *plock(&shared.ctl) = Some(ctl);
                        shared
                            .last_inbound
                            .store(now_secs() as u32, core::sync::atomic::Ordering::SeqCst);
                        shared.connected.store(true, core::sync::atomic::Ordering::SeqCst);
                        // A reason noted while we were already down (e.g. a menu
                        // reconnect during backoff) must not be blamed for this
                        // fresh connection's eventual drop.
                        plock(&shared.disconnect_reason).take();
                        let connected_at = now_secs();
                        backoff = 2;
                        match last_drop.take() {
                            Some(d) => chat::cf_set_status_text(
                                chat_cid,
                                &format!("connected — last drop: {d}"),
                            ),
                            None => chat::cf_set_status_text(chat_cid, &format!("connected to {hub}")),
                        }
                        send_announce(&shared, &trng);
                        // Proactively learn the propagation node's route now, so a
                        // later store-and-forward fallback doesn't have to discover
                        // it mid-escalation (which burns the retry deadline).
                        request_propagation_path(&shared, &trng);
                        read_until_closed(&shared, chat_cid, &pddb, &trng, reader);
                        shared.connected.store(false, core::sync::atomic::Ordering::SeqCst);
                        plock(&shared.ctl).take();
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
                        plock(&shared.transport).connection_reset();
                        plock(&shared.in_resources).clear();
                        plock(&shared.backchannels).clear();
                        let sync_active = { plock(&shared.sync).phase != SyncPhase::Idle };
                        if sync_active {
                            sync_finish(&shared, chat_cid, "connection lost — try again");
                        }
                        let browse_active = { plock(&shared.browser).phase != BrowserPhase::Idle };
                        if browse_active {
                            browser_finish(&shared, chat_cid, "connection lost — try again");
                        } else {
                            // Any kept page link died with the session.
                            plock(&shared.browser).link_id = None;
                        }
                        // Say WHY and after how long, so the failing layer is
                        // identifiable from the status bar alone: a forced
                        // reconnect names its trigger (suspend/watchdog/menu);
                        // an unprompted read-loop exit means the socket itself
                        // died (hub closed it / TCP reset / wifi).
                        let why = plock(&shared.disconnect_reason)
                            .take()
                            .unwrap_or_else(|| "connection dropped".to_string());
                        let up = fmt_duration(now_secs().saturating_sub(connected_at));
                        #[cfg(target_os = "xous")]
                        let wifi = if netmgr.get_ipv4_config().is_some() { "" } else { ", wifi down" };
                        #[cfg(not(target_os = "xous"))]
                        let wifi = "";
                        log::warn!("hub link lost after {up}: {why}{wifi}");
                        chat::cf_set_status_text(
                            chat_cid,
                            &format!("link lost after {up} — {why}{wifi}"),
                        );
                        last_drop = Some(format!("{why} after {up}{wifi}"));
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
    // Read with a timeout so the loop NEVER depends on a shutdown() aborting the
    // blocked read to terminate. On the device, shutting down a socket that died
    // across a suspend demonstrably did NOT unblock the read (menu→Connect sat
    // at "reconnecting…" forever) — so every reconnect path (force_reconnect,
    // write-error, menu) clears `connected`, and the timeout tick notices that
    // and exits the loop on its own.
    stream.set_read_timeout(Some(std::time::Duration::from_secs(15))).ok();
    loop {
        // Checked on EVERY iteration, not just the timeout tick: a hub that
        // floods continuously (a full interface's announce stream) keeps every
        // read returning data, so the timeout branch alone never runs — a
        // forced reconnect would never be noticed and the manager could never
        // dial the new hub (it sat at "reconnecting…" burning CPU on announces).
        if !shared.connected.load(core::sync::atomic::Ordering::SeqCst) {
            log::info!("reconnect requested — leaving the read loop");
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => {
                log::info!("hub connection closed");
                note_disconnect(shared, "closed by hub (EOF)".to_string());
                break;
            }
            Ok(n) => {
                // Any inbound bytes prove the connection is alive — feed the
                // keepalive thread's liveness watchdog.
                shared.last_inbound.store(now_secs() as u32, core::sync::atomic::Ordering::SeqCst);
                for frame in deframer.push(&buf[..n]) {
                    handle_frame(shared, chat_cid, pddb, trng, &frame, PathIface::Hub);
                }
            }
            // Timeout tick: nothing to do — the top-of-loop check decides
            // whether to keep reading.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => {
                log::warn!("hub read error: {e}");
                note_disconnect(shared, format!("read failed: {:?}", e.kind()));
                break;
            }
        }
    }
}

/// Record WHY the hub connection is going down, for the connection manager's
/// "link lost after X — why" status. First cause wins: a forced reconnect also
/// makes the read loop exit (and may error the socket out), and the trigger is
/// the diagnosis — not the fallout.
fn note_disconnect(shared: &Arc<Shared>, reason: String) {
    let mut slot = plock(&shared.disconnect_reason);
    if slot.is_none() {
        *slot = Some(reason);
    }
}

/// `93s` → "1m33s": compact connection-uptime label for the status bar.
fn fmt_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Announce our lxmf.delivery destination on the current connection.
/// Build a raw (unframed) announce for our lxmf.delivery destination.
pub(crate) fn build_announce(shared: &Arc<Shared>, trng: &Trng) -> Vec<u8> {
    let mut r5 = [0u8; 5];
    crate::fill_random(trng, &mut r5);
    let name = plock(&shared.display_name).clone();
    let tp = plock(&shared.transport);
    tp.make_announce_with("lxmf", &["delivery"], name.as_bytes(), &r5, now_secs())
}

fn send_announce(shared: &Arc<Shared>, trng: &Trng) {
    let raw = build_announce(shared, trng);
    broadcast_out(shared, &raw);
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

pub(crate) fn handle_frame(
    shared: &Arc<Shared>,
    chat_cid: CID,
    pddb: &Pddb,
    trng: &Trng,
    frame_bytes: &[u8],
    iface: PathIface,
) {
    // Fresh per-link ephemeral X25519 key material for answering a link request.
    // Drawn from the TRNG *before* taking the transport lock: a TRNG IPC is a
    // blocking service call, and blocking while holding the transport mutex
    // wedges every other thread in the app (sync, sends, …). At most one link
    // request per frame, so one pregenerated value is enough.
    let mut eph = [0u8; KEY_HALF];
    crate::fill_random(trng, &mut eph);
    let mut gen_ephemeral = || eph;
    let event = {
        let mut tp = plock(&shared.transport);
        tp.handle_frame(frame_bytes, &mut gen_ephemeral, iface)
    };

    match event {
        Event::Announce { destination_hash, info } => {
            // Our own announce coming back — the path response to a liveness
            // probe. Reading it already proved the link alive; we're not a peer.
            if destination_hash == shared.our_dh {
                log::info!("hub liveness probe answered");
                return;
            }
            // NomadNet nodes go in their own directory for the page browser
            // (app_data is the node name as raw utf-8) — never the peer lists,
            // and none of the LXMF contact/stamp/ticket handling below applies.
            if info.name_hash == crate::nomad_node_name_hash() {
                let name = String::from_utf8_lossy(&info.app_data).trim().to_string();
                let name = if name.is_empty() { hex(&destination_hash) } else { name };
                plock(&shared.nodes_seen).insert(destination_hash, (name, now_secs()));
                return;
            }
            // Only list LXMF *delivery* destinations — skip propagation-node and
            // other-app announces, whose app_data isn't a messageable peer name.
            if info.name_hash != crate::lxmf_delivery_name_hash() {
                return;
            }
            // Announces populate the live directory only; they are NOT saved as
            // contacts until you actually message them (or they message you).
            let name = crate::lxmf_display_name(&info.app_data).unwrap_or_else(|| hex(&destination_hash));
            plock(&shared.seen).insert(destination_hash, (name.clone(), now_secs()));
            // Track the peer's announced delivery stamp cost: our replies must
            // carry a (ticket or proof-of-work) stamp or they'll be dropped.
            match crate::lxmf_stamp_cost(&info.app_data) {
                Some(c) => {
                    plock(&shared.stamp_costs).insert(destination_hash, c);
                }
                None => {
                    plock(&shared.stamp_costs).remove(&destination_hash);
                }
            }
            // If this is already a saved contact (e.g. someone who messaged us
            // before we had their key — common on an access_point interface),
            // refresh their record now that we have the key. The display name
            // is only upgraded if the saved one is a placeholder (the bare
            // address) — a real name, e.g. a manual rename, is sticky.
            let existing = plock(&shared.contacts).get(&destination_hash).cloned();
            if let Some(existing) = existing {
                let addr_hex = hex(&destination_hash);
                let is_placeholder =
                    existing == addr_hex || existing == format!("{}…", &addr_hex[..8]);
                let keep = if is_placeholder { name.clone() } else { existing };
                crate::save_contact(shared, pddb, &destination_hash, &keep);
            }
            // Now that we have this peer's key, recover a ticket from any earlier
            // message we couldn't verify at the time (access-point interface).
            let cached = plock(&shared.ticket_pending).remove(&destination_hash);
            if let Some(bytes) = cached {
                verify_and_store_ticket(shared, chat_cid, pddb, &destination_hash, &info.identity, &bytes);
            }
            // A queued message may have been waiting for exactly this key. Two
            // things: (a) the announce just revealed the peer's stamp cost — a
            // not-yet-sent unstamped message must mine a stamp first or the
            // recipient drops it; (b) send now instead of waiting out the pump
            // tick, and say so (the wait was otherwise silent-ish).
            let cost = plock(&shared.stamp_costs).get(&destination_hash).copied();
            let (waiting, was_keyless) = {
                let mut outbox = plock(&shared.outbox);
                let mut waiting = false;
                let mut was_keyless = false;
                for m in outbox.iter_mut().filter(|m| m.peer == destination_hash) {
                    if m.attempts == 0 && m.in_flight.is_none() {
                        waiting = true;
                        was_keyless |= m.awaiting_key;
                        if let Some(c) = cost {
                            if !m.stamped && m.needs_stamp.is_none() {
                                m.needs_stamp = Some(c);
                            }
                        }
                        m.next_action = 0; // act immediately
                    }
                }
                (waiting, was_keyless)
            };
            if waiting {
                let label = peer_label(shared, &destination_hash);
                // A missing KEY and a stale ROUTE both park a message here, and
                // the same announce answers both — but a route refresh is the
                // normal once-per-session case for a saved contact, so don't
                // make it read like we'd lost their key.
                let got = if was_keyless { "key received" } else { "route found" };
                chat::cf_set_status_text(chat_cid, &format!("{label}: {got} — sending…"));
                pump_outbox(shared, chat_cid, pddb, trng);
            }
        }
        // Opportunistic delivery: the destination hash is stripped on the wire, so
        // prepend ours to reconstruct the full LXMF blob. Send the delivery proof
        // back FIRST — it's how the sender gets its ✓ instead of retrying and
        // falling back to its propagation node (sent per packet, including
        // retransmits, before any dedup — mirrors LXMRouter.delivery_packet).
        Event::Data { destination_hash, plaintext, proof } => {
            broadcast_out(shared, &proof);
            let mut lxmf_bytes = destination_hash.to_vec();
            lxmf_bytes.extend_from_slice(&plaintext);
            deliver_lxmf(shared, chat_cid, pddb, trng, &lxmf_bytes, true);
        }
        // We accepted an inbound link request: send the proof so the initiator
        // starts transmitting the message over the link.
        Event::LinkEstablished { link_id, proof } => {
            log::info!("accepted inbound link {}", hex(&link_id));
            broadcast_out(shared, &proof);
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
        Event::LinkData { link_id, plaintext, proof } => {
            broadcast_out(shared, &proof);
            {
                // traffic on the link = the backchannel (if any) is alive
                let mut b = plock(&shared.backchannels);
                for (_, (lid, seen)) in b.iter_mut() {
                    if *lid == link_id {
                        *seen = now_secs();
                    }
                }
            }
            deliver_lxmf(shared, chat_cid, pddb, trng, &plaintext, true);
        }
        // A direct message too large for one link packet arrives as an RNS
        // Resource on the inbound link: advertisement → we request the parts →
        // parts → we prove receipt (the sender's delivery ack) and deliver.
        Event::InLinkData { link_id, context, plaintext } => {
            inbound_resource(shared, chat_cid, pddb, trng, link_id, context, plaintext);
        }
        // The peer identified itself on its link to us: open a backchannel —
        // replies to them now ride this link, no reverse handshake. Also a
        // free key-learning moment (like an announce without app_data), which
        // makes the peer replyable even if we never see them announce.
        Event::LinkIdentified { link_id, identity } => {
            let dest = reticulum_core::destination::single_destination_hash(
                "lxmf",
                &["delivery"],
                &identity.hash,
            );
            log::info!("backchannel open: {} via link {}", hex(&dest), hex(&link_id));
            {
                let mut tp = plock(&shared.transport);
                if tp.known(&dest).is_none() {
                    tp.remember(
                        dest,
                        reticulum_core::transport::KnownDest {
                            identity,
                            name_hash: crate::lxmf_delivery_name_hash(),
                            ratchet: None,
                            app_data: Vec::new(),
                        },
                    );
                }
            }
            plock(&shared.backchannels).insert(dest, (link_id, now_secs()));
            // A queued reply may have been waiting for exactly this.
            pump_outbox(shared, chat_cid, pddb, trng);
        }
        // Echo the initiator's keepalive so it doesn't stale the link out —
        // and note the link (hence backchannel) is alive.
        Event::LinkKeepalive { link_id, reply } => {
            broadcast_out(shared, &reply);
            let mut b = plock(&shared.backchannels);
            for (_, (lid, seen)) in b.iter_mut() {
                if *lid == link_id {
                    *seen = now_secs();
                }
            }
        }
        // The initiator closed its link: any backchannel over it is dead.
        Event::InLinkClosed { link_id } => {
            plock(&shared.backchannels).retain(|_, (lid, _)| *lid != link_id);
            plock(&shared.in_resources).remove(&link_id);
        }
        // A link we initiated is up. Real RNS responders only activate the link —
        // and start accepting data — once they receive an RTT packet, so send it
        // before any data (or the data is silently dropped). Then send queued msgs.
        Event::OutboundLinkUp { link_id, target } => {
            log::info!("outbound link {} up to {}", hex(&link_id), hex(&target));
            let mut iv = [0u8; IV_LENGTH];
            crate::fill_random(trng, &mut iv);
            let rtt = { plock(&shared.transport).make_link_rtt(&link_id, &iv) };
            if let Some(rtt) = rtt {
                broadcast_out(shared, &rtt);
            }
            // Identify ourselves on links to PEERS (the PN flow identifies
            // during sync) so their replies can ride this link back — the
            // provider half of the LXMF backchannel. NEVER on a link the page
            // browser opened: node pages are served ALLOW_ALL and browsing
            // stays anonymous.
            if crate::propagation_node() != Some(target) && !browser_targets(shared, &target) {
                let mut iiv = [0u8; IV_LENGTH];
                crate::fill_random(trng, &mut iiv);
                let idp = { plock(&shared.transport).make_out_link_identify(&link_id, &iiv) };
                if let Some(idp) = idp {
                    broadcast_out(shared, &idp);
                }
            }
            sync_on_link_up(shared, chat_cid, trng, link_id, target);
            browser_on_link_up(shared, chat_cid, trng, link_id, target);
            pump_outbox(shared, chat_cid, pddb, trng);
        }
        // A packet proof confirmed one of our sent messages reached its target.
        Event::Delivered { packet_hash } => {
            mark_delivered(shared, chat_cid, pddb, &packet_hash);
        }
        // Data on a link we opened. A RESOURCE_REQ here is a receiver
        // downloading a Resource WE are sending (a large direct message, or a
        // large transfer to the propagation node) — serve it. Everything else
        // drives the propagation-node sync state machine (sync never receives
        // requests: we're the requester there).
        Event::OutLinkData { link_id, context, plaintext } => {
            if context == CONTEXT_RESOURCE_REQ {
                let mut iv = [0u8; IV_LENGTH];
                crate::fill_random(trng, &mut iv);
                // Bind first: never hold the transport guard across hub writes.
                let packets = { plock(&shared.transport).serve_link_resource(&link_id, &plaintext, &iv) };
                if !packets.is_empty() {
                    for p in packets {
                        broadcast_out(shared, &p);
                    }
                    return;
                }
            }
            // Sync traffic goes to the sync state machine and page traffic to
            // the browser's (BEFORE the resource fallback, or a page Resource
            // would be fed to deliver_lxmf); anything else on a link WE opened
            // is the peer using the backchannel — including a LARGE reply
            // arriving as a Resource on our own link.
            let is_sync_link = { plock(&shared.sync).link_id == Some(link_id) };
            let is_browser_link = { plock(&shared.browser).link_id == Some(link_id) };
            if is_sync_link {
                sync_on_outlink_data(shared, chat_cid, pddb, trng, link_id, context, plaintext);
            } else if is_browser_link {
                browser_on_outlink_data(shared, chat_cid, pddb, trng, link_id, context, plaintext);
            } else {
                outlink_resource(shared, chat_cid, pddb, trng, link_id, context, plaintext);
            }
        }
        // The responder closed a link we initiated (transport already forgot it).
        // If a sync was mid-flight on it, abort now and let the user retry over a
        // fresh link instead of waiting out the 2-minute watchdog.
        Event::OutLinkClosed { link_id } => {
            log::info!("outbound link {} closed by responder", hex(&link_id));
            let sync_was_on_it = {
                let s = plock(&shared.sync);
                s.phase != SyncPhase::Idle && s.link_id == Some(link_id)
            };
            if sync_was_on_it {
                sync_finish(shared, chat_cid, "node closed the link — try again");
            }
            let browse_was_on_it = {
                let b = plock(&shared.browser);
                b.link_id == Some(link_id)
            };
            if browse_was_on_it {
                let mid_fetch = { plock(&shared.browser).phase != BrowserPhase::Idle };
                if mid_fetch {
                    browser_finish(shared, chat_cid, "node closed the link — try again");
                } else {
                    // Idle on a kept link: just forget it; the next fetch
                    // establishes a fresh one.
                    plock(&shared.browser).link_id = None;
                }
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
        Event::Dropped(why) => {
            log::debug!("dropped frame: {}", why);
        }
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
    let keep = plock(&shared.tickets).get(src_hash).map_or(true, |(exp, _)| t.expires >= *exp);
    if !keep {
        return;
    }
    plock(&shared.tickets).insert(*src_hash, (t.expires, t.ticket));
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

/// Drive an inbound Resource transfer — a direct message too large for a single
/// link packet (~319 bytes of content), sent over a link the peer opened to us.
/// Accept the advertisement, request every part, reassemble + decrypt + verify,
/// send the `RESOURCE_PRF` proof (which is the sender's delivery confirmation),
/// and deliver the recovered LXMF blob like any other direct message. Failures
/// are log-only — the sender re-advertises or falls back to the propagation
/// node, and a persisted error post per attempt would flood the dialogue.
fn inbound_resource(
    shared: &Arc<Shared>,
    chat_cid: CID,
    pddb: &Pddb,
    trng: &Trng,
    link_id: [u8; TRUNCATED_HASHLENGTH],
    context: u8,
    plaintext: Vec<u8>,
) {
    match context {
        CONTEXT_RESOURCE_ADV => match ResourceReceiver::accept(&plaintext) {
            Ok(mut rx) => {
                let req = rx.next_request();
                {
                    // One transfer per link; a fresh advertisement on the same
                    // link replaces (restarts) it, oldest evicted past the cap.
                    let mut map = plock(&shared.in_resources);
                    while map.len() >= MAX_IN_RESOURCES && !map.contains_key(&link_id) {
                        map.pop_first();
                    }
                    map.insert(link_id, rx);
                }
                if let Some(req) = req {
                    send_in_link_request(shared, trng, &link_id, &req);
                }
                chat::cf_set_status_text(chat_cid, "incoming message — receiving…");
            }
            Err(e) => {
                // Oversized / multi-segment / malformed: don't request it; the
                // sender times out and falls back to the propagation node.
                log::warn!("inbound resource on link {} rejected: {e}", hex(&link_id));
            }
        },
        CONTEXT_RESOURCE => {
            // Ingest the part. When the current window completes, request the
            // next one; when the whole transfer completes, fall through to
            // assembly below.
            let (complete, next_req) = {
                let mut map = plock(&shared.in_resources);
                match map.get_mut(&link_id) {
                    Some(rx) => {
                        let window_done = rx.receive_part(&plaintext);
                        if rx.is_complete() {
                            (true, None)
                        } else if window_done {
                            (false, rx.next_request())
                        } else {
                            (false, None)
                        }
                    }
                    None => (false, None),
                }
            };
            if let Some(req) = next_req {
                send_in_link_request(shared, trng, &link_id, &req);
            }
            if !complete {
                return;
            }
            // Take the receiver out: from here the transfer either delivers or
            // is abandoned (the sender retries with a fresh advertisement).
            let rx = match plock(&shared.in_resources).remove(&link_id) {
                Some(rx) => rx,
                None => return,
            };
            let stream = rx.concat();
            let plain = if rx.encrypted() {
                // Bind first (match-scrutinee guards outlive the arms).
                let decrypted = { plock(&shared.transport).decrypt_in_link(&link_id, &stream) };
                match decrypted {
                    Some(p) => p,
                    None => {
                        log::warn!("inbound resource on link {}: stream decrypt failed", hex(&link_id));
                        return;
                    }
                }
            } else {
                stream
            };
            match rx.finish(&plain) {
                Ok((payload, proof)) => {
                    // Bind first: don't hold the transport guard across the write.
                    let raw = { plock(&shared.transport).make_in_link_resource_proof(&link_id, &proof) };
                    if let Some(raw) = raw {
                        broadcast_out(shared, &raw);
                    }
                    deliver_lxmf(shared, chat_cid, pddb, trng, &payload, true);
                }
                Err(e) => log::warn!("inbound resource on link {} invalid: {e}", hex(&link_id)),
            }
        }
        // A hashmap-update page: the transfer is bigger than the advertisement
        // could describe; learn the next page of part hashes and keep going.
        CONTEXT_RESOURCE_HMU => {
            let next_req = {
                let mut map = plock(&shared.in_resources);
                match map.get_mut(&link_id) {
                    Some(rx) => match rx.receive_hashmap_update(&plaintext) {
                        Ok(()) => rx.next_request(),
                        Err(e) => {
                            log::warn!("inbound resource on link {}: bad hashmap update: {e}", hex(&link_id));
                            None
                        }
                    },
                    None => None,
                }
            };
            if let Some(req) = next_req {
                send_in_link_request(shared, trng, &link_id, &req);
            }
        }
        // The initiator downloading a Resource WE are sending over the
        // backchannel asks for parts: serve them.
        CONTEXT_RESOURCE_REQ => {
            let mut iv = [0u8; IV_LENGTH];
            crate::fill_random(trng, &mut iv);
            // Bind first: never hold the transport guard across hub writes.
            let packets = { plock(&shared.transport).serve_link_resource(&link_id, &plaintext, &iv) };
            for p in packets {
                broadcast_out(shared, &p);
            }
        }
        _ => log::debug!("inbound link {} resource ctx=0x{context:02x} ignored", hex(&link_id)),
    }
}

/// Start a Resource transfer of `data` on an established outbound link and
/// transmit its advertisement; returns the resource hash (the in_flight
/// receipt key — the receiver's RESOURCE_PRF surfaces Event::Delivered with
/// it). Bind-then-write: never hold the transport guard across the hub write.
fn make_resource_on_link(
    shared: &Arc<Shared>,
    trng: &Trng,
    link_id: &[u8; TRUNCATED_HASHLENGTH],
    data: &[u8],
) -> Option<[u8; 32]> {
    let mut r = [0u8; 4];
    let mut prefix = [0u8; 4];
    let mut iv = [0u8; IV_LENGTH];
    let mut adv_iv = [0u8; IV_LENGTH];
    crate::fill_random(trng, &mut r);
    crate::fill_random(trng, &mut prefix);
    crate::fill_random(trng, &mut iv);
    crate::fill_random(trng, &mut adv_iv);
    let made =
        { plock(&shared.transport).make_link_resource(link_id, data, r, prefix, &iv, &adv_iv) };
    let (adv, hash) = made?;
    broadcast_out(shared, &adv);
    Some(hash)
}

/// Drive a Resource arriving on a link WE opened, outside a sync — a peer's
/// LARGE backchannel reply. Mirror of [`inbound_resource`] with the out-link
/// crypto ops; shares the receiver map (link ids are unique across tables).
fn outlink_resource(
    shared: &Arc<Shared>,
    chat_cid: CID,
    pddb: &Pddb,
    trng: &Trng,
    link_id: [u8; TRUNCATED_HASHLENGTH],
    context: u8,
    plaintext: Vec<u8>,
) {
    match context {
        CONTEXT_RESOURCE_ADV => match ResourceReceiver::accept(&plaintext) {
            Ok(mut rx) => {
                let req = rx.next_request();
                {
                    let mut map = plock(&shared.in_resources);
                    while map.len() >= MAX_IN_RESOURCES && !map.contains_key(&link_id) {
                        map.pop_first();
                    }
                    map.insert(link_id, rx);
                }
                if let Some(req) = req {
                    send_out_link_request(shared, trng, &link_id, &req);
                }
                chat::cf_set_status_text(chat_cid, "incoming message — receiving…");
            }
            Err(e) => {
                log::warn!("backchannel resource on link {} rejected: {e}", hex(&link_id));
            }
        },
        CONTEXT_RESOURCE => {
            let (complete, next_req) = {
                let mut map = plock(&shared.in_resources);
                match map.get_mut(&link_id) {
                    Some(rx) => {
                        let window_done = rx.receive_part(&plaintext);
                        if rx.is_complete() {
                            (true, None)
                        } else if window_done {
                            (false, rx.next_request())
                        } else {
                            (false, None)
                        }
                    }
                    None => (false, None),
                }
            };
            if let Some(req) = next_req {
                send_out_link_request(shared, trng, &link_id, &req);
            }
            if !complete {
                return;
            }
            let rx = match plock(&shared.in_resources).remove(&link_id) {
                Some(rx) => rx,
                None => return,
            };
            let stream = rx.concat();
            let plain = if rx.encrypted() {
                // Bind first (match-scrutinee guards outlive the arms).
                let decrypted = { plock(&shared.transport).decrypt_out_link(&link_id, &stream) };
                match decrypted {
                    Some(p) => p,
                    None => {
                        log::warn!("backchannel resource on link {}: stream decrypt failed", hex(&link_id));
                        return;
                    }
                }
            } else {
                stream
            };
            match rx.finish(&plain) {
                Ok((payload, proof)) => {
                    let raw = { plock(&shared.transport).make_out_link_resource_proof(&link_id, &proof) };
                    if let Some(raw) = raw {
                        broadcast_out(shared, &raw);
                    }
                    deliver_lxmf(shared, chat_cid, pddb, trng, &payload, true);
                }
                Err(e) => log::warn!("backchannel resource on link {} invalid: {e}", hex(&link_id)),
            }
        }
        CONTEXT_RESOURCE_HMU => {
            let next_req = {
                let mut map = plock(&shared.in_resources);
                match map.get_mut(&link_id) {
                    Some(rx) => match rx.receive_hashmap_update(&plaintext) {
                        Ok(()) => rx.next_request(),
                        Err(e) => {
                            log::warn!("backchannel resource on link {}: bad hashmap update: {e}", hex(&link_id));
                            None
                        }
                    },
                    None => None,
                }
            };
            if let Some(req) = next_req {
                send_out_link_request(shared, trng, &link_id, &req);
            }
        }
        _ => log::debug!("out-link {} non-sync ctx=0x{context:02x} ignored", hex(&link_id)),
    }
}

/// Send a `RESOURCE_REQ` on an inbound link. Bind-then-write: never hold the
/// transport guard across the hub write.
fn send_in_link_request(shared: &Arc<Shared>, trng: &Trng, link_id: &[u8; TRUNCATED_HASHLENGTH], req: &[u8]) {
    let mut iv = [0u8; IV_LENGTH];
    crate::fill_random(trng, &mut iv);
    let raw = { plock(&shared.transport).make_in_link_context(link_id, CONTEXT_RESOURCE_REQ, req, &iv) };
    if let Some(raw) = raw {
        broadcast_out(shared, &raw);
    }
}

/// Send a `RESOURCE_REQ` on a link we initiated (the sync link). Bind-then-write.
fn send_out_link_request(shared: &Arc<Shared>, trng: &Trng, link_id: &[u8; TRUNCATED_HASHLENGTH], req: &[u8]) {
    let mut iv = [0u8; IV_LENGTH];
    crate::fill_random(trng, &mut iv);
    let raw = { plock(&shared.transport).make_out_link_context(link_id, CONTEXT_RESOURCE_REQ, req, &iv) };
    if let Some(raw) = raw {
        broadcast_out(shared, &raw);
    }
}

/// Candidate LXMF destination addresses in message text: maximal runs of hex
/// digits that are EXACTLY 32 chars. Longer runs are skipped — a 64-hex
/// identity key is not an address, and grabbing half of one would import
/// garbage.
fn extract_addresses(text: &str) -> Vec<[u8; TRUNCATED_HASHLENGTH]> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i - start == 2 * TRUNCATED_HASHLENGTH {
                if let Some(a) = crate::parse_addr(&text[start..i]) {
                    out.push(a);
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Parse a full LXMF blob (`dest||source||sig||payload`), verify, de-duplicate,
/// route into the sender's thread, and post it.
/// `notify`: buzz the vibration motor for this message (live receipt). The sync
/// path passes false and buzzes once for the whole batch instead.
/// `live` distinguishes a message received over the link right now from one
/// downloaded by a propagation-node sync: a live message buzzes the motor
/// (sync buzzes once per batch) and a synced one gets the `»` mark.
fn deliver_lxmf(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, trng: &Trng, lxmf_bytes: &[u8], live: bool) {
    if lxmf_bytes.len() < 2 * TRUNCATED_HASHLENGTH {
        return;
    }
    let mut src_hash = [0u8; TRUNCATED_HASHLENGTH];
    src_hash.copy_from_slice(&lxmf_bytes[TRUNCATED_HASHLENGTH..2 * TRUNCATED_HASHLENGTH]);

    let src_id = { plock(&shared.transport).known(&src_hash).map(|k| k.identity.clone()) };
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
        let mut ids = plock(&shared.recent_msg_ids);
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
        .or_else(|| plock(&shared.seen).get(&src_hash).map(|(n, _)| n.clone()))
        .unwrap_or_else(|| hex(&src_hash));
    let mut text = m.content_string();
    if !m.signature_validated {
        text.push_str("  ⚠(unverified)");
    }
    if !live {
        // Downloaded from the propagation node rather than received live —
        // mirror the outgoing » so both directions show store-and-forward hops.
        text = bubble_text(&text, MARK_SYNCED);
    }

    crate::save_contact(shared, pddb, &src_hash, &author);

    // A shared contact: any 32-hex token in the text is a candidate LXMF
    // address — remember it so "Import contact" can add it without an
    // announce or manual hex entry.
    {
        let ours = shared.our_dh;
        let mut fresh = Vec::new();
        // When every address gets filtered, say WHY — otherwise the import
        // appears to silently swallow it ("no addresses received" while the
        // hex sits right there in the thread).
        let mut filtered: Option<String> = None;
        for a in extract_addresses(&text) {
            log::info!("address in message text: {}", hex(&a));
            if a == ours {
                filtered = Some("that address is this device's own".to_string());
            } else if a == src_hash {
                filtered = Some(format!("that's {author}'s address (already a contact)"));
            } else if let Some(n) = plock(&shared.contacts).get(&a).cloned() {
                filtered = Some(format!("address already saved as {n}"));
            } else {
                fresh.push(a);
            }
        }
        if fresh.is_empty() {
            if let Some(why) = filtered {
                chat::cf_set_status_text(chat_cid, &why);
            }
        } else {
            let mut found = plock(&shared.found_addrs);
            for a in fresh {
                if !found.iter().any(|(fa, _, _)| *fa == a) {
                    found.push((a, author.clone(), now_secs()));
                }
            }
            while found.len() > MAX_FOUND_ADDRS {
                found.remove(0);
            }
            // Persist: an address received before a reboot stays importable
            // after it (restored scrollback never re-runs this scan).
            crate::persist_found_addrs(pddb, &found);
            drop(found);
            chat::cf_set_status_text(chat_cid, "address received — menu \u{2192} Import contact");
        }
    }

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
        plock(&shared.ticket_pending).insert(src_hash, lxmf_bytes.to_vec());
        log::info!("cached unverified ticket message from {} pending key", hex(&src_hash));
    }

    let ts = m.timestamp as u64;
    let active = *plock(&shared.current_peer);
    if active == Some(src_hash) {
        // The conversation we're currently viewing: show it immediately.
        {
            let mut lt = plock(&shared.last_ts);
            *lt = (*lt).max(ts);
        }
        refresh_idle_status(shared, chat_cid);
        post_to_chat(shared, chat_cid, &author, ts, &text);
    } else {
        // A different contact: do NOT disturb the active conversation. Hold the
        // message and bump that contact's unread badge; it'll be flushed into the
        // thread when the user opens it (see `activate_peer`).
        {
            let mut p = plock(&shared.pending);
            let list = p.entry(src_hash).or_default();
            list.push((author.clone(), ts, text));
            // Persist so held messages + the unread badge survive an app restart.
            crate::persist_pending(pddb, &src_hash, list);
        }
        *plock(&shared.unread).entry(src_hash).or_default() += 1;
        // The persistent line picks up the F1 jump hint; the transient one
        // announces the arrival.
        refresh_idle_status(shared, chat_cid);
        chat::cf_set_status_text(chat_cid, &format!("\u{2709} new message from {author}"));
    }

    // Buzz the vibration motor as a notification — LAST, once the bubble (or the
    // unread status line) is on screen. The PDDB writes between decrypt and draw
    // are slow enough that an early buzz leaves the user staring at an unchanged
    // screen. Live receipt only; the sync path buzzes once per batch.
    if live {
        shared.llio.vibe(llio::VibePattern::Long).ok();
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
    wait_for_time_server();
    use core::sync::atomic::Ordering;
    const TICK_SECS: u64 = 5;
    // Empty frame every 10 s. The hub (RNS TCPServerInterface) arms its client
    // sockets with SO_KEEPALIVE probing 5 s after the last segment it received
    // and TCP_USER_TIMEOUT=24 s — it ABORTS the connection ~29 s after it last
    // heard from us. The old 30 s cadence was slower than that deadline, so any
    // delayed/dropped probe ACK (wifi power-save naps) lost the race and showed
    // up as "closed by hub after ~45s". 10 s = three chances per kill window,
    // and the regular transmit keeps the radio from napping deeply at all.
    const KEEPALIVE_TICKS: u64 = 2;
    /// A wall-clock jump this far past a 5 s tick means the device was
    /// suspended: ticktimer sleeps don't count suspended time, but SystemTime
    /// is resynced from the hardware RTC on resume.
    const SUSPEND_GAP_SECS: u64 = 60;
    /// Probe the hub once nothing has been read for this long…
    const PROBE_AFTER_SECS: u32 = 180;
    /// …re-probing at most this often…
    const PROBE_MIN_INTERVAL_SECS: u32 = 20;
    /// …and declare the connection dead (reconnect) after this much silence.
    const DEAD_AFTER_SECS: u32 = 240;
    // Runs for the app's lifetime (one instance). Four jobs:
    // 1. SUSPEND DETECTOR (every tick): wifi drops during sleep but the net
    //    stack never aborts existing TCP sockets, so after a wake the hub
    //    socket is a zombie — writes buffer forever without erroring and the
    //    blocked read never returns. Detect the wake by the wall-clock jump
    //    and reconnect immediately.
    // 2. STUCK-WRITE WATCHDOG (every tick): a hub write that's been in flight
    //    past WRITE_STUCK_SECS has hung the writer mutex (the socket write
    //    timeout demonstrably doesn't always fire on hardware) — shut the socket
    //    down via the control clone, which errors the blocked write out, releases
    //    the mutex, ends the read loop, and lets the manager reconnect. Without
    //    this, ONE stuck write silently wedged sync + sends + reconnect forever.
    // 3. LIVENESS WATCHDOG: an access-point hub is normally silent toward us, so
    //    inbound silence alone can't distinguish quiet from dead. After
    //    PROBE_AFTER_SECS without inbound bytes, send a path request for our OWN
    //    destination — the hub knows us (we announce on connect) and must answer
    //    with our announce, producing inbound bytes on a live link. Still
    //    nothing by DEAD_AFTER_SECS → the socket is dead (e.g. wifi bounced
    //    without a suspend): reconnect. Catches every silent-blackhole cause.
    // 4. KEEPALIVE (every 2nd tick): send an empty HDLC frame (a protocol-safe
    //    no-op RNS discards) so NAT/hub idle timers don't drop a quiet link.
    let trng = XousNames::new().ok().and_then(|xns| Trng::new(&xns).ok());
    if trng.is_none() {
        // Without randomness we can't build probe tags; leave the liveness
        // watchdog off rather than reconnect-loop on a healthy quiet hub.
        log::error!("keepalive: TRNG init failed — liveness probing disabled");
    }
    let mut ticks: u64 = 0;
    let mut last_wall = now_secs();
    let mut last_probe: u32 = 0;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(TICK_SECS));
        ticks += 1;
        let now = now_secs();
        let gap = now.saturating_sub(last_wall);
        last_wall = now;
        if gap > SUSPEND_GAP_SECS && shared.connected.load(Ordering::SeqCst) {
            log::warn!("woke from suspend (clock jumped {gap}s) — reconnecting to the hub");
            force_reconnect(&shared, chat_cid, "woke from sleep — reconnecting…", "woke from sleep");
            continue;
        }
        let started = shared.write_started.load(Ordering::SeqCst);
        if started != 0 && (now as u32).saturating_sub(started) > WRITE_STUCK_SECS {
            log::warn!("hub write stuck >{WRITE_STUCK_SECS}s — shutting the socket down to unwedge it");
            force_reconnect(
                &shared,
                chat_cid,
                "hub write stalled — resetting connection…",
                "write stalled >20s",
            );
            continue;
        }
        if shared.connected.load(Ordering::SeqCst) {
            if let Some(trng) = trng.as_ref() {
                let silent = (now as u32).saturating_sub(shared.last_inbound.load(Ordering::SeqCst));
                if silent > DEAD_AFTER_SECS {
                    log::warn!("nothing read from the hub in {silent}s despite probes — reconnecting");
                    force_reconnect(
                        &shared,
                        chat_cid,
                        "hub unresponsive — reconnecting…",
                        &format!("no inbound for {silent}s, probes unanswered"),
                    );
                    continue;
                }
                if silent > PROBE_AFTER_SECS
                    && (now as u32).saturating_sub(last_probe) >= PROBE_MIN_INTERVAL_SECS
                {
                    last_probe = now as u32;
                    log::info!("quiet for {silent}s — probing the hub (path request for ourselves)");
                    request_peer_key(&shared, trng, &shared.our_dh);
                }
            }
            if ticks % KEEPALIVE_TICKS == 0 {
                broadcast_out(&shared, &[]);
            }
        }
    }
}

/// Tear the hub connection down from outside the manager so it dials fresh.
/// Belt and suspenders: clearing `connected` makes the read loop exit on its
/// own at its next timeout tick (≤15 s), and the shutdown() errors out any
/// blocked read/write immediately when the net service honors the abort (it
/// demonstrably may not for a socket that died across a suspend).
pub(crate) fn force_reconnect(shared: &Arc<Shared>, chat_cid: CID, status: &str, reason: &str) {
    use core::sync::atomic::Ordering;
    note_disconnect(shared, reason.to_string());
    chat::cf_set_status_text(chat_cid, status);
    shared.write_started.store(0, Ordering::SeqCst);
    shared.connected.store(false, Ordering::SeqCst);
    if let Some(c) = plock(&shared.ctl).take() {
        c.shutdown(std::net::Shutdown::Both).ok();
    }
}

/// Ask the network to (re-)announce `target` so we learn its public key. Used
/// when we receive from, or want to message, a peer we have no key for — the
/// normal case on an access_point interface where announces aren't flooded to us.
pub fn request_peer_key(shared: &Arc<Shared>, trng: &Trng, target: &[u8; TRUNCATED_HASHLENGTH]) -> bool {
    let mut tag = [0u8; TRUNCATED_HASHLENGTH];
    crate::fill_random(trng, &mut tag);
    let raw = { plock(&shared.transport).make_path_request(target, &tag) };
    let ok = broadcast_out(shared, &raw);
    if ok {
        log::info!("sent path request for {}", hex(target));
    } else {
        log::warn!("path request for {} not sent (no hub connection)", hex(target));
    }
    ok
}

/// Acquire a mutex by polling `try_lock` instead of `lock()`.
///
/// On the Precursor, a thread that PARKS on a contended `Mutex::lock()` was
/// observed (liveness brackets, Jun-10) to sleep forever even after the mutex
/// was free — the sync thread sat 3+ minutes blocked acquiring a transport
/// lock that no other thread held, microseconds after acquiring the same lock
/// twice itself. Parking goes through the ticktimer server and the wakeup
/// evidently can be lost (suspected interaction with suspend/idle; upstream
/// report pending). `try_lock` is a pure atomic and never parks; `sleep`
/// demonstrably always wakes. So: poll. 5 ms granularity is invisible at our
/// message rates and converts a forever-hang into bounded latency.
pub(crate) fn plock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    loop {
        match m.try_lock() {
            Ok(g) => return g,
            Err(std::sync::TryLockError::WouldBlock) => {
                std::thread::sleep(std::time::Duration::from_millis(5))
            }
            Err(std::sync::TryLockError::Poisoned(e)) => {
                panic!("poisoned mutex: {e}")
            }
        }
    }
}

/// A hub write counts as stuck after this long; the keepalive thread's watchdog
/// then shuts the socket down out from under it, erroring the write out.
const WRITE_STUCK_SECS: u32 = 20;

/// Send a raw RNS packet out every interface: HDLC-framed to the hub, one UDP
/// datagram per AutoInterface peer. The single outbound choke point, so
/// replies a local peer waits for (e.g. our LRPROOF) reach it hub or no hub;
/// receivers de-duplicate by packet hash, so dual-path copies are fine. True
/// if any interface accepted the bytes. An empty `raw` is the hub TCP
/// keepalive — meaningless as a datagram, so it skips UDP.
pub(crate) fn broadcast_out(shared: &Arc<Shared>, raw: &[u8]) -> bool {
    let hub_ok = hub_write(shared, raw);
    let auto_ok = crate::autoiface::send_to_peers(shared, raw);
    hub_ok || auto_ok
}

/// Whether anything we send can currently go anywhere: the hub connection is
/// up, or AutoInterface has live peers (a local transport node routes links
/// and path requests just like the hub does). Atomics only — must never block
/// behind a stuck write.
pub(crate) fn any_interface_up(shared: &Arc<Shared>) -> bool {
    shared.connected.load(core::sync::atomic::Ordering::SeqCst)
        || (crate::autoiface::enabled(shared) && !plock(&shared.auto).peers.is_empty())
}

/// Frame and write `raw` to the hub. Returns true only if the bytes were fully
/// written; false if there is no connection, the writer was busy too long, or
/// the write failed (callers that need delivery — like the sync state machine —
/// surface that instead of silently doing nothing).
///
/// Never blocks unboundedly: the writer mutex is acquired with a ~2 s bounded
/// wait (a healthy write completes in milliseconds; a longer hold means a wedged
/// write that the watchdog will kill), and the write itself is marked in
/// `write_started` so the watchdog can detect and break a hang.
pub(crate) fn hub_write(shared: &Arc<Shared>, raw: &[u8]) -> bool {
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
            if let Err(e) = &res {
                // A failed/timed-out write means the connection is dead OR the HDLC
                // stream is now half-written and desynced. Don't keep limping along
                // (that silently drops every later message): shut the socket so the
                // read loop returns and the connection manager reconnects cleanly.
                note_disconnect(shared, format!("write failed: {:?}", e.kind()));
                w.shutdown(std::net::Shutdown::Both).ok();
                *guard = None;
                shared.connected.store(false, Ordering::SeqCst);
                plock(&shared.ctl).take();
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
/// Per-transfer message size limit we advertise (KB). LXMF's default is 1000;
/// our Resource receiver handles windowed transfers with hashmap updates up to
/// its [`reticulum_core::resource::MAX_TRANSFER_BYTES`] device-memory budget
/// (256 KB). Advertise half of that so the batch plus its envelope stays well
/// inside the budget — anything left over comes on the next sync.
const SYNC_DELIVERY_LIMIT: i64 = 128;
/// Abort a sync that stalls past this many seconds.
const SYNC_DEADLINE_SECS: u64 = 120;
/// Retry cadence and bound while a requested sync waits for the propagation
/// node's key/route (a path request is in flight): every 3 s, up to 20 tries
/// (~1 min), then fail visibly.
const SYNC_ROUTE_RETRY_SECS: u64 = 3;
const SYNC_ROUTE_TRIES: u8 = 20;
/// Cadence for the pending-auto-sync route probe (see `SyncState::pn_probe_at`).
const PN_PROBE_RETRY_SECS: u64 = 30;

/// Begin a propagation-node sync (from the menu or auto on first connect). Ensures
/// the node's key + route, (re)uses or opens the link, and kicks the exchange.
pub fn start_sync(shared: &Arc<Shared>, chat_cid: CID, trng: &Trng) {
    let pn = match crate::propagation_node() {
        Some(p) => p,
        None => {
            chat::cf_set_status_text_forced(chat_cid, "no propagation node configured");
            return;
        }
    };
    if plock(&shared.sync).phase != SyncPhase::Idle {
        chat::cf_set_status_text_forced(chat_cid, "sync already in progress");
        return;
    }
    let now = now_secs();
    // No interface up: nothing we send can go anywhere. Wait for the manager
    // to reconnect / a local peer to appear (same bounded retry as the
    // no-route case below) instead of burning the request on writes that go
    // nowhere.
    if !any_interface_up(shared) {
        let (give_up, first_wait) = {
            let mut s = plock(&shared.sync);
            s.route_tries = s.route_tries.saturating_add(1);
            if s.route_tries <= SYNC_ROUTE_TRIES {
                s.requested = true;
                s.next_attempt = now + SYNC_ROUTE_RETRY_SECS;
                (false, s.route_tries == 1)
            } else {
                (true, false)
            }
        };
        if give_up {
            sync_finish(shared, chat_cid, "no connection (hub or local peers)");
        } else if first_wait {
            // Once, not every tick — see start_fetch: the connection manager's
            // statuses must stay readable while we wait for it to reconnect.
            chat::cf_set_status_text_forced(chat_cid, "sync: waiting for a connection…");
        }
        return;
    }
    let (known, have_path) = {
        let tp = plock(&shared.transport);
        (tp.known(&pn).cloned(), tp.has_path(&pn))
    };
    let known = match (known, have_path) {
        (Some(k), true) => k,
        _ => {
            // No key/route for the node yet: fire a path request and RE-ARM the
            // request flag so the sync thread retries once the response lands —
            // consuming the flag here with no retry left the status stuck at
            // "finding…" forever. Bounded so an unreachable node fails visibly.
            let give_up = {
                let mut s = plock(&shared.sync);
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
        let mut s = plock(&shared.sync);
        s.phase = SyncPhase::Linking;
        s.receiver = None;
        s.deadline = now + SYNC_DEADLINE_SECS;
        s.link_id = None;
        s.route_tries = 0;
        s.next_attempt = 0;
        s.link_tries = 0;
    }
    // BIND the lookup result before matching. A lock inside a `match` scrutinee
    // — even wrapped in braces — keeps its guard alive through EVERY ARM (Rust
    // temporary-scope rules), so the old `match { lock().outbound_link_for() }`
    // SELF-DEADLOCKED as soon as either arm touched the transport mutex again.
    // That was the root cause of "sync hangs forever on the first attempt of
    // every boot" (and it wedged sends + inbound frames behind the held mutex);
    // it never reproduced off-device because only the device runs start_sync.
    let existing_link = { plock(&shared.transport).outbound_link_for(&pn, now) };
    match existing_link {
        Some(lid) => {
            plock(&shared.sync).link_id = Some(lid);
            sync_send_identify_and_list(shared, chat_cid, trng, lid);
        }
        None => {
            // The hop count distinguishes a HEADER_1 (hops ≤ 1, direct) from a
            // HEADER_2 (routed) link request — and the try counter advancing
            // proves the sync thread is alive and writing. Status BEFORE the
            // write so it shows even if the write stalls.
            let hops = { plock(&shared.transport).path_hops(&pn) };
            let hops = hops.map(|h| h.to_string()).unwrap_or_else(|| "?".to_string());
            chat::cf_set_status_text_forced(
                chat_cid,
                &format!("sync: contacting node (try 1, hops {hops})…"),
            );
            let outcome = send_link_request(shared, trng, &pn, &known.identity, now);
            match outcome {
                LinkReqOutcome::WriteFailed => {
                    sync_finish(shared, chat_cid, "hub write failed — try again");
                }
                LinkReqOutcome::Sent | LinkReqOutcome::Pending => {
                    plock(&shared.sync).link_tries = 1;
                }
            }
        }
    }
}

/// What happened when we tried to (re)send a LINKREQUEST to the propagation node.
enum LinkReqOutcome {
    /// A fresh request was framed and fully written to the hub.
    Sent,
    /// A recent request is still pending an LRPROOF, or the link is already
    /// established — nothing sent (correct).
    Pending,
    /// No connection, or the hub write failed: nothing went out.
    WriteFailed,
}

/// Send a LINKREQUEST to `target` (a peer or the propagation node) unless one
/// is already pending and
/// recent (expired pending entries are pruned by `pending_link_to`, which is what
/// lets a lost request be retried at all) — or the link is already up. The
/// established-link check must live HERE, under the same transport lock that
/// processes the LRPROOF: the retry ticks sample their phase first and call
/// this after, so a proof landing in between used to slip past the pending
/// check (consumed by the proof) and send a duplicate LINKREQUEST — painting
/// "try 2" right after "requesting message list…" and opening a second link
/// the node keeps for nothing.
fn send_link_request(
    shared: &Arc<Shared>,
    trng: &Trng,
    pn: &[u8; TRUNCATED_HASHLENGTH],
    pn_identity: &reticulum_core::identity::PublicIdentity,
    now: u64,
) -> LinkReqOutcome {
    // Sub-stages 161-164 of the `g` diagnostic (only meaningful for the sync
    // thread; the pump only calls this while the outbox is non-empty).
    let raw = {
        let mut tp = plock(&shared.transport);
        if tp.pending_link_to(pn, now) || tp.outbound_link_for(pn, now).is_some() {
            None
        } else {
            let mut ex = [0u8; KEY_HALF];
            let mut ed = [0u8; KEY_HALF];
            crate::fill_random(trng, &mut ex);
            crate::fill_random(trng, &mut ed);
            Some(tp.make_link_request(pn, pn_identity, &ex, &ed, now))
        }
    };
    match raw {
        None => LinkReqOutcome::Pending,
        Some((raw, link_id)) => {
            if broadcast_out(shared, &raw) {
                LinkReqOutcome::Sent
            } else {
                // Nothing went out: drop the pending entry make_link_request
                // registered, or for the next ~20 s every retry would be
                // answered "Pending" on the strength of a request nobody saw.
                plock(&shared.transport).forget_pending_link(&link_id);
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
        let mut s = plock(&shared.sync);
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
    plock(&shared.sync).phase = SyncPhase::ListRequested;
    chat::cf_set_status_text_forced(chat_cid, "sync: requesting message list…");
    let mut iv = [0u8; IV_LENGTH];
    crate::fill_random(trng, &mut iv);
    // Bind before testing: in edition 2021 an `if let` scrutinee's lock guard
    // lives through the body, which would hold the transport mutex across the
    // hub write below.
    let idp = { plock(&shared.transport).make_out_link_identify(&link_id, &iv) };
    if let Some(idp) = idp {
        broadcast_out(shared, &idp);
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
    // Bind before testing (scrutinee guards outlive the body in edition 2021).
    let raw = { plock(&shared.transport).make_out_link_context(&link_id, CONTEXT_REQUEST, &packed, &iv) };
    if let Some(raw) = raw {
        broadcast_out(shared, &raw);
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
        let s = plock(&shared.sync);
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
            Ok(mut rx) => {
                let req = rx.next_request();
                plock(&shared.sync).receiver = Some(rx);
                if let Some(req) = req {
                    send_out_link_request(shared, trng, &link_id, &req);
                }
                chat::cf_set_status_text_forced(chat_cid, "sync: downloading…");
            }
            Err(e) => {
                log::warn!("sync resource advertisement rejected: {e}");
                sync_finish(shared, chat_cid, "sync failed (unsupported resource)");
            }
        },
        CONTEXT_RESOURCE_HMU => {
            // Next page of part hashes for a transfer bigger than the
            // advertisement could describe.
            let next_req = {
                let mut s = plock(&shared.sync);
                match &mut s.receiver {
                    Some(rx) => match rx.receive_hashmap_update(&plaintext) {
                        Ok(()) => rx.next_request(),
                        Err(e) => {
                            log::warn!("sync: bad hashmap update: {e}");
                            None
                        }
                    },
                    None => None,
                }
            };
            if let Some(req) = next_req {
                send_out_link_request(shared, trng, &link_id, &req);
            }
        }
        CONTEXT_RESOURCE => {
            // Ingest the part; request the next window when this one completes.
            let (complete, next_req) = {
                let mut s = plock(&shared.sync);
                match &mut s.receiver {
                    Some(rx) => {
                        let window_done = rx.receive_part(&plaintext);
                        if rx.is_complete() {
                            (true, None)
                        } else if window_done {
                            (false, rx.next_request())
                        } else {
                            (false, None)
                        }
                    }
                    None => (false, None),
                }
            };
            if let Some(req) = next_req {
                send_out_link_request(shared, trng, &link_id, &req);
            }
            if !complete {
                return;
            }
            // The receiver can vanish between these lock acquisitions (the sync
            // thread's watchdog may sync_finish a stalled sync at any moment), so
            // never unwrap it — bail out instead of panicking the read thread.
            let (stream, encrypted) = {
                let s = plock(&shared.sync);
                match s.receiver.as_ref() {
                    Some(rx) => (rx.concat(), rx.encrypted()),
                    None => return,
                }
            };
            let plain = if encrypted {
                // Bind first: the None arm calls sync_finish, which locks the
                // transport mutex to drop the link — a self-deadlock if the
                // scrutinee's guard were still held (match-arm temporary scope).
                let decrypted = { plock(&shared.transport).decrypt_out_link(&link_id, &stream) };
                match decrypted {
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
                let s = plock(&shared.sync);
                match s.receiver.as_ref() {
                    Some(rx) => rx.finish(&plain),
                    None => return,
                }
            };
            match finished {
                Ok((payload, proof)) => {
                    // Bind first: don't hold the transport guard across the write.
                    let raw = { plock(&shared.transport).make_out_link_resource_proof(&link_id, &proof) };
                    if let Some(raw) = raw {
                        broadcast_out(shared, &raw);
                    }
                    plock(&shared.sync).receiver = None;
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
    let phase = plock(&shared.sync).phase;
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
            plock(&shared.sync).phase = SyncPhase::GetRequested;
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
            sync_finish(shared, chat_cid, &format!("synced {count} message(s)"));
            if count > 0 {
                // One buzz for the whole synced batch (deliver_lxmf didn't per-msg).
                // Buzz LAST, after the status line is painted, so the user reads
                // the result before feeling the notification.
                shared.llio.vibe(llio::VibePattern::Long).ok();
            }
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
    let plaintext = { plock(&shared.transport).identity().decrypt(&blob[TRUNCATED_HASHLENGTH..], &[]) };
    let plaintext = match plaintext {
        Ok(p) => p,
        Err(e) => {
            log::warn!("synced message decrypt failed: {e}");
            return;
        }
    };
    let mut full = blob[..TRUNCATED_HASHLENGTH].to_vec();
    full.extend_from_slice(&plaintext);
    deliver_lxmf(shared, chat_cid, pddb, trng, &full, false); // synced: » mark, batch-buzz instead
}

/// End the current sync (success or failure) and reset the state machine. The
/// link to the node is dropped either way — sync links are one-shot (mirrors the
/// reference client): on failure the link is suspect (a timeout usually MEANS
/// it's dead), and we send no keepalives, so a kept link would quietly die and
/// hang the next sync. Establishment is cheap relative to a 2-minute hang.
fn sync_finish(shared: &Arc<Shared>, chat_cid: CID, msg: &str) {
    let link = {
        let mut s = plock(&shared.sync);
        s.phase = SyncPhase::Idle;
        s.receiver = None;
        s.requested = false;
        s.route_tries = 0;
        s.link_id.take()
    };
    if let Some(lid) = link {
        plock(&shared.transport).drop_out_link(&lid);
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

// ---- Node page browser ----------------------------------------------------
//
// Fetch micron pages from NomadNet nodes: link to the node's nomadnetwork.node
// destination (ANONYMOUSLY — no LINKIDENTIFY; page handlers are ALLOW_ALL),
// send an RNS request for the page path, and render the response through the
// chat lib's document mode. The fetch lifecycle is a clone of the sync state
// machine above (same route acquisition, link reuse, retry budgets, watchdog);
// wire behavior validated live against real RNS by scripts/page_test.sh.

/// The default page served by a node.
pub const PAGE_PATH_DEFAULT: &str = "/page/index.mu";
/// Abort a page fetch that stalls past this many seconds.
const PAGE_DEADLINE_SECS: u64 = 60;
/// Retry cadence/bound while a requested fetch waits for the node's key/route
/// — or for the hub connection itself. 2 minutes: a full reconnect cycle (wifi
/// re-associate + a 15 s dial timeout + up to 30 s backoff) can exceed the
/// minute the route budget alone would allow.
const BROWSER_ROUTE_RETRY_SECS: u64 = 3;
const BROWSER_ROUTE_TRIES: u8 = 40;
/// Pages you can go ← back through (oldest dropped).
const BACK_STACK_MAX: usize = 16;

/// The page currently shown in the browser, if any.
pub fn current_page(shared: &Arc<Shared>) -> Option<PageAddr> {
    plock(&shared.browser).current.clone()
}

/// The shown page's title (its first heading), if it has one.
pub fn current_page_title(shared: &Arc<Shared>) -> Option<String> {
    plock(&shared.browser).current_title.clone()
}

/// Short human label for a node (saved/announced name, else a hex prefix).
pub(crate) fn node_label(shared: &Arc<Shared>, node: &[u8; TRUNCATED_HASHLENGTH]) -> String {
    plock(&shared.saved_nodes)
        .get(node)
        .cloned()
        .or_else(|| plock(&shared.nodes_seen).get(node).map(|(n, _)| n.clone()))
        .unwrap_or_else(|| hex(&node[..4]))
}

/// True while the browser is mid-fetch to `target` (gates LINKIDENTIFY off
/// the browser's links so page requests stay anonymous).
fn browser_targets(shared: &Arc<Shared>, target: &[u8; TRUNCATED_HASHLENGTH]) -> bool {
    let b = plock(&shared.browser);
    b.phase != BrowserPhase::Idle && b.node == Some(*target)
}

/// Request a page, from the main thread (menu/keys): only flags the request —
/// the browser thread does the link + hub writes. `push_back` records the
/// currently shown page on the back stack once the new page actually renders.
/// Returns false if a fetch was already in flight (request not taken).
pub fn request_page(
    shared: &Arc<Shared>,
    chat_cid: CID,
    node: [u8; TRUNCATED_HASHLENGTH],
    path: &str,
    vars: Vec<(String, String)>,
    push_back: bool,
) -> bool {
    {
        let mut b = plock(&shared.browser);
        if b.phase != BrowserPhase::Idle {
            drop(b);
            chat::cf_set_status_text(chat_cid, "page fetch already in progress…");
            return false;
        }
        b.requested = Some((node, path.to_string(), vars));
        b.pending_push = push_back;
        b.pending_pop = false;
        b.next_attempt = 0;
        b.route_tries = 0;
    }
    chat::cf_set_status_text(chat_cid, &format!("page: fetching {}…", node_label(shared, &node)));
    true
}

/// One lifetime thread driving the page browser (mirrors [`sync_thread`]):
/// watchdog, link retries, and consuming requests off the UI thread.
pub fn browser_thread(shared: Arc<Shared>, chat_cid: CID) {
    wait_for_time_server();
    let trng = match XousNames::new().ok().and_then(|xns| Trng::new(&xns).ok()) {
        Some(t) => t,
        None => {
            log::error!("browser thread: TRNG init failed");
            chat::cf_set_status_text_forced(chat_cid, "browser unavailable (init failed — restart app)");
            return;
        }
    };
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        browser_tick(&shared, chat_cid, &trng);
    }
}

fn browser_tick(shared: &Arc<Shared>, chat_cid: CID, trng: &Trng) {
    let now = now_secs();
    // Time out a stuck fetch.
    let (stalled, never_linked_node) = {
        let b = plock(&shared.browser);
        let stalled = b.phase != BrowserPhase::Idle && now > b.deadline;
        (stalled, if b.phase == BrowserPhase::Linking { b.node } else { None })
    };
    if stalled {
        // Stalled before the link ever came up: expire the node's unresponsive
        // route so the next fetch re-discovers one (RNS expire_path on a failed
        // link). Past Linking the link was up and the route is fine.
        if let Some(node) = never_linked_node {
            plock(&shared.transport).expire_path(&node);
        }
        browser_finish(shared, chat_cid, "timed out");
        return;
    }
    // Mid-fetch, still waiting for the link: re-send a lost LINKREQUEST
    // (no-ops while one is still pending or the link is already up — same
    // recovery, and same phase-sample race, as the sync path).
    let linking = {
        let b = plock(&shared.browser);
        if b.phase == BrowserPhase::Linking { b.node } else { None }
    };
    if let Some(node) = linking {
        let known = { plock(&shared.transport).known(&node).cloned() };
        if let Some(k) = known {
            match send_link_request(shared, trng, &node, &k.identity, now) {
                LinkReqOutcome::Sent => {
                    let tries = {
                        let mut b = plock(&shared.browser);
                        b.link_tries = b.link_tries.saturating_add(1);
                        b.link_tries
                    };
                    chat::cf_set_status_text_forced(
                        chat_cid,
                        &format!("page: contacting node (try {tries})…"),
                    );
                }
                LinkReqOutcome::WriteFailed => {
                    browser_finish(shared, chat_cid, "hub write failed — try again");
                }
                LinkReqOutcome::Pending => {}
            }
        }
        return;
    }
    // A requested fetch (from the menu / a key) executes HERE.
    let job = {
        let mut b = plock(&shared.browser);
        if b.phase == BrowserPhase::Idle && b.requested.is_some() && now >= b.next_attempt {
            b.requested.take()
        } else {
            None
        }
    };
    if let Some((node, path, vars)) = job {
        start_fetch(shared, chat_cid, trng, node, path, vars);
    }
}

/// Begin a page fetch: ensure connection + the node's key/route (bounded
/// retries via the request flag), then reuse or open the link and send the
/// request. Structure mirrors [`start_sync`] — including its lock discipline.
fn start_fetch(
    shared: &Arc<Shared>,
    chat_cid: CID,
    trng: &Trng,
    node: [u8; TRUNCATED_HASHLENGTH],
    path: String,
    vars: Vec<(String, String)>,
) {
    let now = now_secs();
    // Re-arm the request (bounded) while there is no connection or no route —
    // mirrors start_sync's wait-for-resources loop.
    let rearm = |b: &mut BrowserState| -> bool {
        b.route_tries = b.route_tries.saturating_add(1);
        if b.route_tries <= BROWSER_ROUTE_TRIES {
            b.requested = Some((node, path.clone(), vars.clone()));
            b.next_attempt = now + BROWSER_ROUTE_RETRY_SECS;
            true
        } else {
            false
        }
    };
    if !any_interface_up(shared) {
        let (retrying, first_wait) = {
            let mut b = plock(&shared.browser);
            let ok = rearm(&mut b);
            (ok, b.route_tries == 1)
        };
        if !retrying {
            browser_finish(shared, chat_cid, "no connection (hub or local peers)");
        } else if first_wait {
            // Say it ONCE. Repeating this every retry tick papered over the
            // connection manager's own statuses (connecting…/connect failed…/
            // link lost — why), which are exactly what diagnoses a reconnect
            // that isn't completing. The fetch resumes by itself once the
            // manager gets the connection back.
            chat::cf_set_status_text_forced(chat_cid, "page: waiting for a connection…");
        }
        return;
    }
    let (known, have_path) = {
        let tp = plock(&shared.transport);
        (tp.known(&node).cloned(), tp.has_path(&node))
    };
    let known = match (known, have_path) {
        (Some(k), true) => k,
        _ => {
            let retrying = { rearm(&mut plock(&shared.browser)) };
            if !retrying {
                browser_finish(shared, chat_cid, "no route to the node");
                return;
            }
            chat::cf_set_status_text_forced(chat_cid, "page: finding the node…");
            request_peer_key(shared, trng, &node);
            return;
        }
    };
    // Patience scales with distance: link establishment alone is allowed
    // ~6 s/hop by the reference, and a 7-hop mesh node can take most of a
    // minute before the first byte of the page even starts back.
    let hops = { plock(&shared.transport).path_hops(&node).unwrap_or(1).max(1) as u64 };
    {
        let mut b = plock(&shared.browser);
        b.phase = BrowserPhase::Linking;
        b.node = Some(node);
        b.path = path;
        b.vars = vars;
        b.receiver = None;
        b.deadline = now + PAGE_DEADLINE_SECS + 12 * hops;
        b.link_id = None;
        b.route_tries = 0;
        b.next_attempt = 0;
        b.link_tries = 0;
    }
    // Bind before matching — a guard in a match scrutinee outlives the arms
    // (the sync self-deadlock lesson; see start_sync).
    let existing_link = { plock(&shared.transport).outbound_link_for(&node, now) };
    match existing_link {
        Some(lid) => {
            plock(&shared.browser).link_id = Some(lid);
            browser_send_request(shared, chat_cid, trng, lid);
        }
        None => {
            chat::cf_set_status_text_forced(
                chat_cid,
                &format!("page: contacting node (try 1, hops {hops})…"),
            );
            match send_link_request(shared, trng, &node, &known.identity, now) {
                LinkReqOutcome::WriteFailed => {
                    browser_finish(shared, chat_cid, "hub write failed — try again");
                }
                LinkReqOutcome::Sent | LinkReqOutcome::Pending => {
                    plock(&shared.browser).link_tries = 1;
                }
            }
        }
    }
}

/// Continue a pending fetch once the link to the node comes up. No-op unless
/// the browser is mid-Linking to this node.
fn browser_on_link_up(
    shared: &Arc<Shared>,
    chat_cid: CID,
    trng: &Trng,
    link_id: [u8; TRUNCATED_HASHLENGTH],
    target: [u8; TRUNCATED_HASHLENGTH],
) {
    let go = {
        let mut b = plock(&shared.browser);
        if b.phase == BrowserPhase::Linking && b.node == Some(target) {
            b.link_id = Some(link_id);
            true
        } else {
            false
        }
    };
    if go {
        browser_send_request(shared, chat_cid, trng, link_id);
    }
}

/// Send the page request on the established link: an anonymous RNS request,
/// msgpack `[now, truncated_hash(path), Nil]` with context REQUEST.
fn browser_send_request(
    shared: &Arc<Shared>,
    chat_cid: CID,
    trng: &Trng,
    link_id: [u8; TRUNCATED_HASHLENGTH],
) {
    let (path, vars) = {
        let mut b = plock(&shared.browser);
        b.phase = BrowserPhase::Fetching;
        (b.path.clone(), b.vars.clone())
    };
    chat::cf_set_status_text_forced(chat_cid, &format!("page: requesting {path}…"));
    let path_hash = truncated_hash(path.as_bytes());
    // URL variables travel as a request-data dict like NomadNet sends them:
    // `[label`url`g=mirrors] → {"var_g": "mirrors"}; no vars → Nil.
    let data = if vars.is_empty() {
        Value::Nil
    } else {
        Value::StrMap(
            vars.into_iter().map(|(k, v)| (format!("var_{k}"), Value::Str(v))).collect(),
        )
    };
    let req =
        Value::Array(vec![Value::F64(now_secs() as f64), Value::Bin(path_hash.to_vec()), data]);
    let packed = msgpack::encode(&req);
    let mut iv = [0u8; IV_LENGTH];
    crate::fill_random(trng, &mut iv);
    // Bind before testing (scrutinee guards outlive the body).
    let raw = { plock(&shared.transport).make_out_link_context(&link_id, CONTEXT_REQUEST, &packed, &iv) };
    match raw {
        Some(raw) => {
            if !broadcast_out(shared, &raw) {
                browser_finish(shared, chat_cid, "hub write failed — try again");
            }
        }
        // The link vanished between establishment and the request.
        None => browser_finish(shared, chat_cid, "link lost — try again"),
    }
}

/// Dispatch decrypted out-link data for the active fetch (RESPONSE packet, or
/// a RESOURCE advertisement / parts carrying a large page). Structural clone
/// of [`sync_on_outlink_data`] over the browser's receiver.
fn browser_on_outlink_data(
    shared: &Arc<Shared>,
    chat_cid: CID,
    pddb: &Pddb,
    trng: &Trng,
    link_id: [u8; TRUNCATED_HASHLENGTH],
    context: u8,
    plaintext: Vec<u8>,
) {
    {
        let b = plock(&shared.browser);
        if b.link_id != Some(link_id) || b.phase != BrowserPhase::Fetching {
            return;
        }
    }
    // Any data on the active fetch link is forward progress, so push the
    // deadline out: it's a stall timeout, not a fixed budget. A large page
    // arrives as a multi-part Resource fetched in growing windows — each window
    // a round-trip plus on-device decryption — which legitimately runs past the
    // initial budget over a slow link. Without this, big (typically dynamic,
    // param-bearing) pages get killed mid-download while small single-packet
    // pages return inside the budget and never trip it.
    plock(&shared.browser).deadline = now_secs() + PAGE_DEADLINE_SECS;
    match context {
        CONTEXT_RESPONSE => {
            if let Some(resp) = parse_rns_response(&plaintext) {
                page_received(shared, chat_cid, pddb, resp);
            }
        }
        CONTEXT_RESOURCE_ADV => match ResourceReceiver::accept(&plaintext) {
            Ok(mut rx) => {
                let req = rx.next_request();
                plock(&shared.browser).receiver = Some(rx);
                if let Some(req) = req {
                    send_out_link_request(shared, trng, &link_id, &req);
                }
                chat::cf_set_status_text_forced(chat_cid, "page: downloading…");
            }
            Err(e) => {
                log::warn!("page resource advertisement rejected: {e}");
                browser_finish(shared, chat_cid, "page too large / unsupported");
            }
        },
        CONTEXT_RESOURCE_HMU => {
            let next_req = {
                let mut b = plock(&shared.browser);
                match &mut b.receiver {
                    Some(rx) => match rx.receive_hashmap_update(&plaintext) {
                        Ok(()) => rx.next_request(),
                        Err(e) => {
                            log::warn!("page: bad hashmap update: {e}");
                            None
                        }
                    },
                    None => None,
                }
            };
            if let Some(req) = next_req {
                send_out_link_request(shared, trng, &link_id, &req);
            }
        }
        CONTEXT_RESOURCE => {
            let (complete, next_req) = {
                let mut b = plock(&shared.browser);
                match &mut b.receiver {
                    Some(rx) => {
                        let window_done = rx.receive_part(&plaintext);
                        if rx.is_complete() {
                            (true, None)
                        } else if window_done {
                            (false, rx.next_request())
                        } else {
                            (false, None)
                        }
                    }
                    None => (false, None),
                }
            };
            if let Some(req) = next_req {
                send_out_link_request(shared, trng, &link_id, &req);
            }
            if !complete {
                return;
            }
            // The receiver can vanish under the watchdog — never unwrap it.
            let (stream, encrypted) = {
                let b = plock(&shared.browser);
                match b.receiver.as_ref() {
                    Some(rx) => (rx.concat(), rx.encrypted()),
                    None => return,
                }
            };
            let plain = if encrypted {
                // Bind first: the None arm re-locks the transport (browser_finish).
                let decrypted = { plock(&shared.transport).decrypt_out_link(&link_id, &stream) };
                match decrypted {
                    Some(p) => p,
                    None => {
                        browser_finish(shared, chat_cid, "page failed (decrypt)");
                        return;
                    }
                }
            } else {
                stream
            };
            let finished = {
                let b = plock(&shared.browser);
                match b.receiver.as_ref() {
                    Some(rx) => rx.finish(&plain),
                    None => return,
                }
            };
            match finished {
                Ok((payload, proof)) => {
                    let raw = { plock(&shared.transport).make_out_link_resource_proof(&link_id, &proof) };
                    if let Some(raw) = raw {
                        broadcast_out(shared, &raw);
                    }
                    plock(&shared.browser).receiver = None;
                    if let Some(resp) = parse_rns_response(&payload) {
                        page_received(shared, chat_cid, pddb, resp);
                    }
                }
                Err(e) => {
                    log::warn!("page resource invalid: {e}");
                    browser_finish(shared, chat_cid, "page failed (resource)");
                }
            }
        }
        _ => {}
    }
}

/// A page response arrived: parse the micron source, hand the styled lines to
/// the chat lib's document view, and update the navigation state. The link is
/// KEPT for follow-up fetches (page browsing is bursty; `outbound_link_for`
/// reuses it, and stale links self-heal via LINKCLOSE / connection resets).
fn page_received(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, resp: Value) {
    let bytes: Vec<u8> = match &resp {
        Value::Int(code) => {
            let why = match *code {
                240 => "node needs identification",
                241 => "node denied access",
                _ => "node error",
            };
            browser_finish(shared, chat_cid, why);
            return;
        }
        Value::Bin(b) => b.clone(),
        Value::Str(s) => s.as_bytes().to_vec(),
        _ => {
            browser_finish(shared, chat_cid, "unexpected response");
            return;
        }
    };
    let src = String::from_utf8_lossy(&bytes);
    let doc = micron::parse(&src);

    // Map parser output onto chat-lib document lines.
    let mut lines: Vec<chat::DocLine> = Vec::with_capacity(doc.lines.len());
    for l in &doc.lines {
        let style = match l.style {
            micron::Style::Heading(1) => chat::DOC_STYLE_LARGE,
            micron::Style::Heading(_) | micron::Style::Bold => chat::DOC_STYLE_BOLD,
            micron::Style::Mono => chat::DOC_STYLE_MONO,
            micron::Style::Regular => chat::DOC_STYLE_REGULAR,
        };
        let align = match l.align {
            micron::Align::Center => chat::DOC_ALIGN_CENTER,
            micron::Align::Right => chat::DOC_ALIGN_RIGHT,
            micron::Align::Left => chat::DOC_ALIGN_LEFT,
        };
        let (kind, link_id) = match l.kind {
            micron::Kind::Divider => (chat::DOC_KIND_DIVIDER, 0),
            micron::Kind::Link(id) => (chat::DOC_KIND_LINK, id),
            micron::Kind::Text => (chat::DOC_KIND_TEXT, 0),
        };
        lines.push(chat::DocLine { text: l.text.clone(), style, align, kind, link_id });
    }

    // Update the navigation state and pull out what the render needs.
    let page_title = doc.title.clone();
    let (node, path, entering) = {
        let mut b = plock(&shared.browser);
        let node = match b.node {
            Some(n) => n,
            None => return, // finished/aborted concurrently
        };
        let path = core::mem::take(&mut b.path);
        let vars = core::mem::take(&mut b.vars);
        if b.pending_push {
            if let Some(prev) = b.current.take() {
                b.back.push(prev);
                if b.back.len() > BACK_STACK_MAX {
                    b.back.remove(0);
                }
            }
            b.pending_push = false;
        }
        if b.pending_pop {
            // A back-navigation rendered: NOW its entry leaves the stack.
            b.back.pop();
            b.pending_pop = false;
        }
        b.current = Some((node, path.clone(), vars));
        b.links = doc.links;
        b.current_title = page_title.clone();
        b.phase = BrowserPhase::Idle;
        b.node = None;
        b.receiver = None;
        let entering = !b.viewing;
        b.viewing = true;
        (node, path, entering)
    };

    // An index page's title is the node's de-facto name: upgrade a PLACEHOLDER
    // (bare-hex) saved-node entry with it, so address-browsed nodes that never
    // announce where we can hear them still get real names in the pickers and
    // labels. Announced / manually-meaningful names are sticky (same policy as
    // contact names).
    if let Some(t) = page_title.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        if path == PAGE_PATH_DEFAULT {
            let addr_hex = hex(&node);
            let placeholder = {
                let nodes = plock(&shared.saved_nodes);
                match nodes.get(&node) {
                    Some(name) => *name == addr_hex || *name == format!("{}…", &addr_hex[..8]),
                    None => false,
                }
            };
            if placeholder {
                let mut t = t.to_string();
                t.truncate(crate::DISPLAY_NAME_MAX);
                plock(&shared.saved_nodes).insert(node, t.clone());
                crate::persist_node(pddb, &node, &t);
            }
        }
    }

    let label = node_label(shared, &node);
    let title = format!("{label}{path}");
    chat::cf_document_begin(chat_cid, &title);
    chat::cf_document_lines(chat_cid, &lines);
    chat::cf_document_show(chat_cid);
    if entering {
        browser_fkey_hints(chat_cid);
    }
    let line = format!("\u{25a3} {title}");
    chat::cf_set_status_idle_text(chat_cid, &line);
    chat::cf_set_status_text_forced(chat_cid, &line);
}

/// End a FAILED fetch and reset the fetch machine (the displayed page, back
/// stack and viewing state are untouched — only the in-flight fetch dies).
/// The link is dropped: a fetch failure usually means it's suspect.
fn browser_finish(shared: &Arc<Shared>, chat_cid: CID, msg: &str) {
    let link = {
        let mut b = plock(&shared.browser);
        b.phase = BrowserPhase::Idle;
        b.node = None;
        b.receiver = None;
        b.requested = None;
        b.pending_push = false;
        b.pending_pop = false;
        b.route_tries = 0;
        b.link_id.take()
    };
    if let Some(lid) = link {
        plock(&shared.transport).drop_out_link(&lid);
    }
    let line = format!("page: {msg}");
    chat::cf_set_status_idle_text(chat_cid, &line);
    chat::cf_set_status_text_forced(chat_cid, &line);
}

/// The browser's F-key tray labels (←/→ are back/follow, undisplayable here).
/// Set when a page first shows and re-asserted after any modal.
pub fn browser_fkey_hints(chat_cid: CID) {
    chat::cf_icontray_set(chat_cid, 0, "menu");
    chat::cf_icontray_set(chat_cid, 1, "pg up");
    chat::cf_icontray_set(chat_cid, 2, "pg dn");
    chat::cf_icontray_set(chat_cid, 3, "exit");
}

/// Follow the link under the document cursor (→ while browsing).
pub fn follow_selected_link(shared: &Arc<Shared>, chat_cid: CID) {
    let id = match chat::cf_document_selected(chat_cid) {
        Some(id) => id as usize,
        None => {
            chat::cf_set_status_text(chat_cid, "move the cursor onto a link first (↑/↓)");
            return;
        }
    };
    let (url, vars, current) = {
        let b = plock(&shared.browser);
        match b.links.get(id) {
            Some(l) => (l.url.clone(), l.fields.clone(), b.current.clone()),
            None => return,
        }
    };
    match micron::resolve_link(&url) {
        micron::LinkTarget::SameNode(path) => {
            if let Some((node, _, _)) = current {
                request_page(shared, chat_cid, node, &path, vars, true);
            }
        }
        micron::LinkTarget::OtherNode(node, path) => {
            request_page(shared, chat_cid, node, &path, vars, true);
        }
        micron::LinkTarget::NodeIndex(node) => {
            request_page(shared, chat_cid, node, PAGE_PATH_DEFAULT, vars, true);
        }
        micron::LinkTarget::Lxmf(_) => {
            chat::cf_set_status_text(chat_cid, "messaging links not supported yet");
        }
        micron::LinkTarget::Anchor | micron::LinkTarget::Unsupported => {
            chat::cf_set_status_text(chat_cid, "link not supported");
        }
    }
}

/// Go back one page (F1 while browsing). Returns false when there was
/// nothing to go back to (the caller tells the user; F3 is the exit).
pub fn browser_back(shared: &Arc<Shared>, chat_cid: CID) -> bool {
    // PEEK, don't pop: the entry comes off the stack only when the page
    // renders (page_received). A pop here was lost for good when the fetch
    // failed — e.g. hub connection down — silently eating history.
    let prev = { plock(&shared.browser).back.last().cloned() };
    match prev {
        Some((node, path, vars)) => {
            if request_page(shared, chat_cid, node, &path, vars, false) {
                plock(&shared.browser).pending_pop = true;
            }
            true
        }
        None => false,
    }
}

/// Leave the browser view, KEEPING its session: the current page, back stack,
/// link table and title stay in [`BrowserState`], and the rendered document
/// (scroll + cursor included) is parked in the chat lib — [`browser_resume`]
/// brings it all back exactly as it was. Any in-flight fetch is aborted and
/// the page link dropped (navigation re-links on demand; a kept link wouldn't
/// survive a reconnect anyway). The status bar goes back to the conversation.
pub fn browser_suspend(shared: &Arc<Shared>, chat_cid: CID) {
    let link = {
        let mut b = plock(&shared.browser);
        b.phase = BrowserPhase::Idle;
        b.node = None;
        b.receiver = None;
        b.requested = None;
        b.pending_push = false;
        b.pending_pop = false;
        b.route_tries = 0;
        b.viewing = false;
        // current, back, links, current_title survive for browser_resume.
        b.link_id.take()
    };
    if let Some(lid) = link {
        plock(&shared.transport).drop_out_link(&lid);
    }
    chat::cf_document_suspend(chat_cid);
    chat::cf_icontray_set(chat_cid, 2, "sync");
    chat::cf_icontray_set(chat_cid, 3, ""); // F4 is unbound outside the browser
    refresh_idle_status(shared, chat_cid);
    // refresh_idle_status only recomposes the *idle* text — the visible status
    // line would keep showing the page title. Bring the conversation back.
    let line = match *plock(&shared.current_peer) {
        Some(p) => format!("\u{25c9} {}", peer_label(shared, &p)),
        None => String::new(),
    };
    chat::cf_set_status_text(chat_cid, &line);
}

/// Bring a suspended browser session back on screen (main menu → Browser).
/// Returns false when there is nothing to resume.
pub fn browser_resume(shared: &Arc<Shared>, chat_cid: CID) -> bool {
    let (node, path) = match { plock(&shared.browser).current.clone() } {
        Some((node, path, _)) => (node, path),
        None => return false,
    };
    if !chat::cf_document_resume(chat_cid) {
        // The chat lib has no parked page (shouldn't happen — both halves are
        // session state) — drop our stale mirror so the menu path is taken.
        let mut b = plock(&shared.browser);
        b.current = None;
        b.back.clear();
        b.links.clear();
        b.current_title = None;
        return false;
    }
    plock(&shared.browser).viewing = true;
    browser_fkey_hints(chat_cid);
    // Restore the page's title line (same composition as page_received).
    let line = format!("\u{25a3} {}{}", node_label(shared, &node), path);
    chat::cf_set_status_idle_text(chat_cid, &line);
    chat::cf_set_status_text(chat_cid, &line);
    true
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
    needs_stamp: Option<u32>,
    stamped: bool,
) {
    plock(&shared.outbox).push(OutboundMsg {
        peer,
        display_ts,
        text,
        packed,
        needs_stamp,
        stamped,
        via_pn: false,
        tried_pn: false,
        in_flight: None,
        attempts: 0,
        route_tries: 0,
        link_tries: 0,
        awaiting_key: false,
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
    wait_for_time_server();
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
        if !plock(&shared.outbox).is_empty() {
            // Mine any pending proof-of-work first (slow, lock-free), so the
            // message/blob is ready when pump_outbox reaches its send step.
            // Doing it here keeps the multi-second PoW off the net read loop.
            compute_pending_delivery_stamp(&shared, chat_cid, &pddb);
            compute_pending_pn_blob(&shared, chat_cid, &trng);
            pump_outbox(&shared, chat_cid, &pddb, &trng);
        }
    }
}

/// Upper bound on a peer's announced delivery stamp cost we're willing to
/// mine. Expected attempts double per bit — 20 bits is ~1M single-block
/// compressions (about a minute on the device, a few at unlucky variance);
/// past that, treat the announce as hostile and fail the message visibly
/// instead of pinning the pump thread for an hour. Real-world costs are 8–16.
const MAX_DELIVERY_STAMP_COST: u32 = 20;

/// Mine, **lock-free**, the proof-of-work delivery stamp for at most one
/// outbox message whose recipient enforces a stamp cost (and has sent us no
/// ticket). Mirrors [`compute_pending_pn_blob`]: snapshot the inputs under the
/// outbox lock, release it, mine (seconds to minutes, depending on cost), then
/// store the result by re-finding the entry. The stamp is appended to the
/// packed message as the 5th payload element — the message id and signature
/// cover only the 4-tuple, so they are unchanged. Runs only on the pump
/// thread. Returns true if it stamped a message.
fn compute_pending_delivery_stamp(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb) -> bool {
    let job = {
        let outbox = plock(&shared.outbox);
        outbox.iter().find(|m| m.needs_stamp.is_some()).map(|m| {
            (m.peer, m.display_ts, m.text.clone(), m.packed.clone(), m.needs_stamp.unwrap_or(0))
        })
    };
    let (peer, display_ts, text, packed, cost) = match job {
        Some(j) => j,
        None => return false,
    };
    let label = peer_label(shared, &peer);

    let fail = |why: String| {
        plock(&shared.outbox).retain(|m| !(m.peer == peer && m.display_ts == display_ts));
        update_mark(shared, chat_cid, pddb, &peer, display_ts, &text, STATUS_FAILED);
        chat::cf_set_status_idle_text(chat_cid, &why);
        chat::cf_set_status_text(chat_cid, &why);
    };
    if cost > MAX_DELIVERY_STAMP_COST {
        fail(format!("× {label}: stamp cost {cost} is too high"));
        return false;
    }

    chat::cf_set_status_text(chat_cid, &format!("computing stamp for {label} (cost {cost})…"));
    // message_id = full_hash(dest || source || payload): the packed message
    // minus its signature.
    let mut hashed = Vec::with_capacity(packed.len() - SIG_LENGTH);
    hashed.extend_from_slice(&packed[..2 * TRUNCATED_HASHLENGTH]);
    hashed.extend_from_slice(&packed[2 * TRUNCATED_HASHLENGTH + SIG_LENGTH..]);
    let message_id = full_hash(&hashed);
    let stamp =
        lxmf::stamp::generate_stamp(&message_id, cost, lxmf::stamp::WORKBLOCK_EXPAND_ROUNDS_DELIVERY);
    let stamped = match lxmf::message::append_stamp(&packed, &stamp) {
        Some(s) => s,
        None => {
            // Can't happen for our own pack() output; fail loudly if it does.
            fail(format!("× {label}: could not stamp message"));
            return false;
        }
    };

    // Re-find the entry (it may have been cleared meanwhile) and arm it. The
    // delivery clock starts NOW: mining time doesn't count against the
    // delivery budget.
    let mut outbox = plock(&shared.outbox);
    match outbox.iter_mut().find(|m| m.peer == peer && m.display_ts == display_ts) {
        Some(m) => {
            m.packed = stamped;
            m.needs_stamp = None;
            m.created = now_secs();
            m.deadline = now_secs() + DIRECT_DEADLINE;
            drop(outbox);
            chat::cf_set_status_text(chat_cid, &format!("stamp ready — sending to {label}…"));
            true
        }
        None => false,
    }
}

/// Dedicated propagation-node sync driver, on its OWN thread so a slow outbox op
/// (stalled write / PoW mining) on the pump thread can't delay a sync request, and
/// so a slow sync can't delay message sending. Consumes the manual-sync flag and
/// times out a stalled sync.
pub fn sync_thread(shared: Arc<Shared>, chat_cid: CID) {
    wait_for_time_server();
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
        maybe_auto_sync(&shared, chat_cid, &trng);
    }
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
                let mut s = plock(&shared.sync);
                core::mem::replace(&mut s.requested, false)
            };
            if requested {
                chat::cf_set_status_text_forced(chat_cid, "no propagation node configured");
            }
            return;
        }
    };
    let now = now_secs();
    // Time out a stuck sync.
    let (stalled, never_linked) = {
        let s = plock(&shared.sync);
        (s.phase != SyncPhase::Idle && now > s.deadline, s.phase == SyncPhase::Linking)
    };
    if stalled {
        // Stalled before the link ever came up: the node's cached route is
        // unresponsive, so expire it (RNS expire_path on a failed link) — the
        // next sync re-discovers a working route instead of reusing the dead
        // one. Past Linking the link was up and the route is fine.
        if never_linked {
            plock(&shared.transport).expire_path(&pn);
        }
        sync_finish(shared, chat_cid, "timed out");
        return;
    }
    // Mid-sync, still waiting for the link: if the LINKREQUEST was lost (its
    // pending entry expired with no proof), send a fresh one — otherwise a single
    // lost request used to mean nothing more ever went out and the sync just sat
    // until the watchdog. `send_link_request` no-ops while one is still pending
    // AND when the link is already up — the proof can land between this phase
    // sample and the send, and the duplicate request would clobber the status
    // with a phantom "try N".
    let linking = { plock(&shared.sync).phase == SyncPhase::Linking };
    if linking {
        let known = { plock(&shared.transport).known(&pn).cloned() };
        if let Some(k) = known {
            match send_link_request(shared, trng, &pn, &k.identity, now) {
                LinkReqOutcome::Sent => {
                    // Show the retry on the status line: a counter that advances
                    // means the sync thread is alive and writes complete — if the
                    // node still sees nothing, the requests die on the network.
                    let tries = {
                        let mut s = plock(&shared.sync);
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
    let requested = {
        let mut s = plock(&shared.sync);
        if s.requested && now >= s.next_attempt {
            s.requested = false;
            true
        } else {
            false
        }
    };
    if requested {
        start_sync(shared, chat_cid, trng); // handles not-ready / already-running itself
        return;
    }
    // Auto-sync once per app run, as soon as the node becomes reachable over
    // ANY interface.
    if AUTO_SYNC_ON_CONNECT {
        let go = {
            let s = plock(&shared.sync);
            !s.auto_done && s.phase == SyncPhase::Idle
        };
        if !go {
            return;
        }
        let ready = {
            let tp = plock(&shared.transport);
            tp.known(&pn).is_some() && tp.has_path(&pn)
        };
        if ready {
            plock(&shared.sync).auto_done = true;
            start_sync(shared, chat_cid, trng);
        } else if any_interface_up(shared) {
            let probe = {
                let mut s = plock(&shared.sync);
                if now >= s.pn_probe_at {
                    s.pn_probe_at = now + PN_PROBE_RETRY_SECS;
                    true
                } else {
                    false
                }
            };
            if probe {
                request_peer_key(shared, trng, &pn);
            }
        }
    }
}

/// Request a propagation-node sync from the main thread (the menu): just sets a
/// flag the pump thread picks up. Does NO hub I/O, so it can never block the UI.
pub fn request_sync(shared: &Arc<Shared>) {
    plock(&shared.sync).requested = true;
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
        let outbox = plock(&shared.outbox);
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
    let known = { plock(&shared.transport).known(&peer).cloned() };
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
    let mut outbox = plock(&shared.outbox);
    if let Some(m) = outbox.iter_mut().find(|m| m.peer == peer && m.display_ts == display_ts) {
        m.pn_blob = Some(blob);
    }
    true
}

/// Advance every outbound message: (re)establish the link to its target (the peer,
/// or the propagation node once direct delivery has timed out), send it, and on
/// proof timeout escalate direct→propagation→failed. Idempotent and cheap to call
/// often (on a timer, on link-up, and right after enqueue).
/// Status line for a direct link send. Every send paints one — a silent send
/// looks hung from the bubble's ○ — and retries carry the attempt count so a
/// stalled delivery shows visible progress instead of nothing for 50 seconds.
fn send_status(label: &str, attempt: u8) -> String {
    if attempt > 1 {
        format!("{label}: sent over link, awaiting confirmation… (try {attempt}/{MAX_ATTEMPTS})")
    } else {
        format!("{label}: sent over link, awaiting confirmation…")
    }
}

fn pump_outbox(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, trng: &Trng) {
    let pn = crate::propagation_node();
    let now = now_secs();
    // Each failure carries a short reason so the user can see *why* a message
    // ended at ✗ (the intermediate statuses flash by) — routing vs no ack vs PN.
    let mut failures: Vec<([u8; TRUNCATED_HASHLENGTH], u64, String, &'static str)> = Vec::new();

    {
        let mut outbox = plock(&shared.outbox);
        let mut i = 0;
        while i < outbox.len() {
            // 0a. Still waiting for its proof-of-work delivery stamp (mined on
            // this same pump thread, just before pump_outbox runs). Nothing —
            // including the deadline — applies until the stamp is on; the cost
            // cap in compute_pending_delivery_stamp bounds how long that takes.
            if outbox[i].needs_stamp.is_some() {
                i += 1;
                continue;
            }
            // 0b. The current phase's independent time budget is up.
            if now > outbox[i].deadline {
                // Backstop: if the direct phase ran out of time before its
                // per-stage escalations fired — a distant peer whose link
                // windows (6 s/hop) outlast the 90 s direct budget, common when
                // a local transport node routes onto a multi-hop backbone — fall
                // back to the propagation node rather than giving up outright.
                if !outbox[i].via_pn && !outbox[i].tried_pn && pn.is_some() {
                    let label = peer_label(shared, &outbox[i].peer);
                    outbox[i].via_pn = true;
                    outbox[i].deadline = now + PROP_DEADLINE;
                    outbox[i].next_action = now;
                    chat::cf_set_status_text(
                        chat_cid,
                        &format!("{label}: direct delivery timed out — trying propagation node…"),
                    );
                    i += 1;
                    continue;
                }
                let m = outbox.remove(i);
                let why = if m.via_pn {
                    // Escalated to the node but never managed a send over a link
                    // to it (tried_pn is set only after a PN send): its route is
                    // unresponsive, so expire it (RNS expire_path on a failed
                    // link) — sync and later sends then re-discover it.
                    if !m.tried_pn {
                        if let Some(node) = pn {
                            plock(&shared.transport).expire_path(&node);
                        }
                    }
                    "propagation node unconfirmed"
                } else if m.attempts == 0 && !m.tried_pn {
                    // Nothing was ever sent. Two distinct stories: we never got
                    // a route at all, or the route was fine but our link
                    // requests went unanswered (peer offline at the other end
                    // of a working path).
                    if plock(&shared.transport).has_path(&m.peer) {
                        "link could not be established"
                    } else {
                        "no route found"
                    }
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
                        // Re-send (falls through to the send below) — but not
                        // down the same link: no proof inside the window
                        // usually means the link is dead (a TCP drop on the
                        // peer's side sends no LINKCLOSE), so forget both
                        // directions and let the re-send establish fresh.
                        let peer = outbox[i].peer;
                        plock(&shared.backchannels).remove(&peer);
                        {
                            let mut tp = plock(&shared.transport);
                            if let Some(lid) = tp.outbound_link_for(&peer, now) {
                                tp.drop_out_link(&lid);
                            }
                        }
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
                    // The unproven link is as suspect as in the direct case: forget
                    // it (unless a sync is mid-flight on it) so the retry
                    // establishes a fresh one.
                    if let Some(target) = pn {
                        let sync_lid = { plock(&shared.sync).link_id };
                        let mut tp = plock(&shared.transport);
                        if let Some(lid) = tp.outbound_link_for(&target, now) {
                            if sync_lid != Some(lid) {
                                tp.drop_out_link(&lid);
                            }
                        }
                    }
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
                    let tp = plock(&shared.transport);
                    (tp.known(&target).cloned(), tp.has_path(&target))
                };
                let known = match known {
                    Some(k) => k,
                    None => {
                        request_peer_key(shared, trng, &target);
                        outbox[i].awaiting_key = true;
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
                    outbox[i].awaiting_key = false;
                    outbox[i].next_action = now + KEY_RETRY;
                    i += 1;
                    continue;
                }
                let link = { plock(&shared.transport).outbound_link_for(&target, now) };
                let link = match link {
                    Some(l) => l,
                    None => {
                        send_link_request(shared, trng, &target, &known.identity, now);
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
                if blob.len() > LINK_PACKED_MAX {
                    // Too big for one link packet: transfer it as a Resource
                    // (LXMF does the same for large PROPAGATED messages).
                    let sent = make_resource_on_link(shared, trng, &link, &blob);
                    match sent {
                        Some(res_hash) => {
                            outbox[i].in_flight = Some(res_hash);
                            outbox[i].tried_pn = true;
                            outbox[i].next_action = now + RESOURCE_RETRY;
                            let label = peer_label(shared, &outbox[i].peer);
                            chat::cf_set_status_text(
                                chat_cid,
                                &format!("{label}: transferring to propagation node…"),
                            );
                        }
                        None => outbox[i].next_action = now + 2,
                    }
                    i += 1;
                    continue;
                }
                let mut div = [0u8; IV_LENGTH];
                crate::fill_random(trng, &mut div);
                let sent = { plock(&shared.transport).make_link_data(&link, &blob, &div) };
                match sent {
                    Some((raw, packet_hash)) => {
                        broadcast_out(shared, &raw);
                        outbox[i].in_flight = Some(packet_hash);
                        outbox[i].tried_pn = true;
                        outbox[i].next_action = now + PROOF_TIMEOUT;
                        let label = peer_label(shared, &outbox[i].peer);
                        chat::cf_set_status_text(chat_cid, &format!("{label}: sending to propagation node…"));
                    }
                    None => outbox[i].next_action = now + 2,
                }
            } else {
                // ---- Primary: DIRECT delivery over a link (the reference
                // default): a link we established, else the peer's link to us
                // (the backchannel). A live link in either direction needs no
                // key lookup and no route — its packets are addressed to the
                // link id, which every hop forwards from its link table. Only
                // establishing a FRESH link gates on key + route, mirroring
                // LXMRouter.process_outbound (direct_links → backchannel_links
                // → has_path/request_path). ----
                let peer = outbox[i].peer;
                let label = peer_label(shared, &peer);
                let link = { plock(&shared.transport).outbound_link_for(&peer, now) };
                match link {
                    Some(lid) if outbox[i].packed.len() > LINK_PACKED_MAX => {
                        // Too big for one link packet: send it as a Resource
                        // over the link, exactly as LXMF does for large DIRECT
                        // messages. The receiver's RESOURCE_PRF is the proof.
                        match make_resource_on_link(shared, trng, &lid, &outbox[i].packed) {
                            Some(res_hash) => {
                                outbox[i].in_flight = Some(res_hash);
                                outbox[i].attempts += 1;
                                outbox[i].next_action = now + RESOURCE_RETRY;
                                chat::cf_set_status_text(
                                    chat_cid,
                                    &format!("{label}: transferring (large message)…"),
                                );
                            }
                            None => outbox[i].next_action = now + 1,
                        }
                    }
                    Some(lid) => {
                        let mut iv = [0u8; IV_LENGTH];
                        crate::fill_random(trng, &mut iv);
                        // Bind first: never hold the transport guard across a hub write.
                        let made = { plock(&shared.transport).make_link_data(&lid, &outbox[i].packed, &iv) };
                        match made {
                            Some((raw, packet_hash)) => {
                                broadcast_out(shared, &raw);
                                outbox[i].in_flight = Some(packet_hash);
                                outbox[i].attempts += 1;
                                outbox[i].next_action = now + DELIVERY_RETRY;
                                chat::cf_set_status_text(chat_cid, &send_status(&label, outbox[i].attempts));
                            }
                            None => {
                                // The link vanished between the two lock takes
                                // (expired / connection reset): retry next tick,
                                // which re-establishes.
                                outbox[i].next_action = now + 1;
                            }
                        }
                    }
                    None => {
                        // A peer who messaged us and identified leaves a
                        // backchannel: reply over THEIR link, no handshake —
                        // as a single link packet, or as a Resource when too
                        // big for one.
                        {
                            let bc = {
                                let mut b = plock(&shared.backchannels);
                                match b.get(&peer) {
                                    Some((lid, seen))
                                        if now.saturating_sub(*seen) <= BACKCHANNEL_MAX_IDLE =>
                                    {
                                        Some(*lid)
                                    }
                                    Some(_) => {
                                        b.remove(&peer); // stale: don't reuse
                                        None
                                    }
                                    None => None,
                                }
                            };
                            if let Some(lid) = bc {
                                if outbox[i].packed.len() > LINK_PACKED_MAX {
                                    // Large reply: a Resource on their link.
                                    match make_resource_on_link(shared, trng, &lid, &outbox[i].packed) {
                                        Some(res_hash) => {
                                            outbox[i].in_flight = Some(res_hash);
                                            outbox[i].attempts += 1;
                                            outbox[i].next_action = now + RESOURCE_RETRY;
                                            chat::cf_set_status_text(
                                                chat_cid,
                                                &format!("{label}: transferring over their link…"),
                                            );
                                            i += 1;
                                            continue;
                                        }
                                        None => {
                                            plock(&shared.backchannels).remove(&peer);
                                        }
                                    }
                                } else {
                                    let mut iv = [0u8; IV_LENGTH];
                                    crate::fill_random(trng, &mut iv);
                                    let made = {
                                        plock(&shared.transport)
                                            .make_in_link_data(&lid, &outbox[i].packed, &iv)
                                    };
                                    if let Some((raw, packet_hash)) = made {
                                        broadcast_out(shared, &raw);
                                        outbox[i].in_flight = Some(packet_hash);
                                        outbox[i].attempts += 1;
                                        outbox[i].next_action = now + DELIVERY_RETRY;
                                        chat::cf_set_status_text(chat_cid, &send_status(&label, outbox[i].attempts));
                                        log::info!("reply to {label} sent over their link {}", hex(&lid));
                                        i += 1;
                                        continue;
                                    }
                                    // link vanished under us: drop, establish our own
                                    plock(&shared.backchannels).remove(&peer);
                                }
                            }
                        }
                        // Neither direction has a live link, so establish our
                        // own — only THIS needs the peer's identity key (NOT
                        // for encryption — the link key is ephemeral-ephemeral
                        // ECDH — but to validate their identity-signed LRPROOF,
                        // or anyone could answer the request) and a current
                        // route: a transport node will not forward a packet to
                        // a destination >1 hop away unless it is addressed via
                        // that node (HEADER_2). Mirrors RNS requesting a path
                        // before opening a link.
                        let (known, have_path) = {
                            let tp = plock(&shared.transport);
                            (tp.known(&peer).cloned(), tp.has_path(&peer))
                        };
                        let known = match known {
                            Some(k) => k,
                            None => {
                                // No key yet (e.g. the contact was imported from
                                // an address, never announced to us): keep asking.
                                // The Announce handler fires the send the moment
                                // the key lands; the deadline turns this into
                                // "no route found".
                                chat::cf_set_status_text(chat_cid, &format!("{label}: requesting key…"));
                                request_peer_key(shared, trng, &peer);
                                outbox[i].awaiting_key = true;
                                outbox[i].next_action = now + KEY_RETRY;
                                i += 1;
                                continue;
                            }
                        };
                        if !have_path {
                            // If the route never resolves (peer offline /
                            // unannounced), fall back to the propagation node
                            // rather than spinning until the deadline — the PN
                            // can still store-and-forward for an offline peer
                            // (LXMF does the same after its pathless tries).
                            if outbox[i].route_tries >= MAX_ROUTE_TRIES && !outbox[i].tried_pn && pn.is_some() {
                                outbox[i].via_pn = true;
                                outbox[i].deadline = now + PROP_DEADLINE; // fresh, independent budget
                                outbox[i].next_action = now; // act on the PN path immediately
                                chat::cf_set_status_text(chat_cid, &format!("{label}: no route — trying propagation node…"));
                                continue; // re-enter the loop on this same message via the PN branch
                            }
                            // A try only counts if the path request actually
                            // left the device — right after a reconnect the
                            // first writes can land on a dead socket, and those
                            // must not burn the route budget.
                            if request_peer_key(shared, trng, &peer) {
                                outbox[i].route_tries += 1;
                            }
                            outbox[i].awaiting_key = false;
                            chat::cf_set_status_text(chat_cid, &format!("{label}: finding a route…"));
                            outbox[i].next_action = now + KEY_RETRY;
                            i += 1;
                            continue;
                        }
                        // No live link: establish one (a pending recent request
                        // is left alone). The OutboundLinkUp event pumps the
                        // outbox the moment the LRPROOF arrives, so the message
                        // goes out without waiting for the next tick.
                        //
                        // If the link never establishes (peer offline, stale
                        // path), `attempts` stays 0 and nothing else escalates —
                        // count establishment requests (`link_tries`, NOT the
                        // route counter: route tries spent getting here must
                        // not eat the link budget) and fall back to the
                        // propagation node like the no-route path does, instead
                        // of spinning until the deadline ✗'s the message.
                        // Escalate only once the LAST request's answer window
                        // (~20 s, PENDING_LINK_EXPIRY) has also expired — three
                        // full windows ≈ a minute of honest trying, and a slow
                        // LRPROOF (this hub's RTT runs seconds) isn't cut off
                        // at the next 2 s tick.
                        let pending = { plock(&shared.transport).pending_link_to(&peer, now) };
                        if !pending && outbox[i].link_tries >= MAX_LINK_TRIES {
                            // The link won't establish: the cached route leads to
                            // a next-hop that isn't relaying our LINKREQUEST (or
                            // the LRPROOF back). Treat it as unresponsive and drop
                            // it (RNS expire_path on a failed link) so a fresh path
                            // request can find a working next-hop — e.g. via a
                            // different interface after a topology change.
                            plock(&shared.transport).expire_path(&peer);
                            if !outbox[i].tried_pn && pn.is_some() {
                                outbox[i].via_pn = true;
                                outbox[i].deadline = now + PROP_DEADLINE; // fresh budget
                                outbox[i].next_action = now;
                                chat::cf_set_status_text(
                                    chat_cid,
                                    &format!("{label}: link won't establish — trying propagation node…"),
                                );
                                continue;
                            }
                            // No propagation node to fall back on: give direct
                            // delivery a fresh start on a re-discovered route
                            // (link_tries reset) rather than hammering the dead
                            // one until the deadline.
                            outbox[i].link_tries = 0;
                            outbox[i].next_action = now + 1;
                            i += 1;
                            continue;
                        }
                        match send_link_request(shared, trng, &peer, &known.identity, now) {
                            LinkReqOutcome::Sent => {
                                outbox[i].link_tries += 1;
                                chat::cf_set_status_text(chat_cid, &format!("{label}: establishing link…"));
                            }
                            // Pending: the window is still open, keep waiting.
                            // WriteFailed: the hub socket is down/reconnecting;
                            // nothing went out (and no pending entry remains),
                            // so the same try repeats once the hub is back.
                            LinkReqOutcome::Pending | LinkReqOutcome::WriteFailed => {}
                        }
                        outbox[i].next_action = now + 2;
                    }
                }
            }
            i += 1;
        }
    }

    for (peer, ts, text, why) in failures {
        let label = peer_label(shared, &peer);
        let note = format!("\u{00d7} {label}: {why}");
        // Both lines: transient so the failure is announced NOW (delivery ✓/⇪
        // does the same), idle so it's still readable after the banner expires.
        chat::cf_set_status_text(chat_cid, &note);
        chat::cf_set_status_idle_text(chat_cid, &note);
        update_mark(shared, chat_cid, pddb, &peer, ts, &text, STATUS_FAILED);
    }
}

/// A packet proof arrived: find the matching outbound message and mark it
/// delivered (✓) or stored-at-node (⇪), depending on how it was sent.
fn mark_delivered(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, packet_hash: &[u8; 32]) {
    let done = {
        let mut outbox = plock(&shared.outbox);
        outbox.iter().position(|m| m.in_flight == Some(*packet_hash)).map(|pos| {
            let m = outbox.remove(pos);
            let status = if m.via_pn { STATUS_QUEUED } else { STATUS_DELIVERED };
            (m.peer, m.display_ts, m.text, status)
        })
    };
    if let Some((peer, ts, text, status)) = done {
        let label = peer_label(shared, &peer);
        // Use the bubble-mark consts: they're checked against the device fonts
        // (a literal ⇪ here once rendered as tofu — see the MARK_* notes).
        let note = if status == STATUS_QUEUED {
            format!("{MARK_QUEUED} stored at propagation node for {label}")
        } else {
            format!("{MARK_DELIVERED} delivered to {label}")
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
    let mut map = plock(&shared.delivery_updates);
    let list = map.entry(*peer).or_default();
    list.push(DeliveryUpdate { display_ts, text: text.to_string(), status });
    crate::persist_delivery_updates(pddb, peer, list);
}

/// Apply any held delivery-mark updates for `peer` to the now-active dialogue
/// (called from `activate_peer` after the dialogue is switched). Clears them.
pub fn apply_delivery_updates(shared: &Arc<Shared>, chat_cid: CID, pddb: &Pddb, peer: &[u8; TRUNCATED_HASHLENGTH]) {
    let updates = plock(&shared.delivery_updates).remove(peer);
    if let Some(updates) = updates {
        for u in &updates {
            chat::cf_post_update(chat_cid, chat::SELF_AUTHOR, u.display_ts, &bubble_text(&u.text, status_mark(u.status)));
        }
        dialogue_save(chat_cid);
        crate::delete_delivery_updates(pddb, peer);
    }
}
