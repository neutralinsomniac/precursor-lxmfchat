//! Reticulum AutoInterface: zero-configuration peering with other Reticulum
//! instances on the local network — no hub required.
//!
//! Mirrors RNS `Interfaces/AutoInterface.py`:
//! - every peer multicasts a discovery token — `SHA-256(group_id ‖ its own
//!   link-local IPv6 address as a string)` — to a group address derived from
//!   `SHA-256(group_id)` (default group "reticulum" → `ff12:0:eca6:…`), port
//!   29716, every 1.6 s;
//! - a receiver validates the token against the datagram's source address and
//!   adds the sender as a peer (token mismatch = different group, ignore);
//! - peers also send the same token directly to each other's unicast discovery
//!   port (29717, "reverse peering") so one-way multicast still converges;
//! - data is raw RNS packets, one per UDP datagram (no HDLC framing), unicast
//!   to each peer's data port (42671);
//! - a peer not heard from (on either discovery port) for 22 s is dropped.
//!
//! On Xous the IPv6 link-local address is the EUI-64 of the wifi MAC — the
//! same derivation the net service uses to configure the interface — and the
//! multicast group is joined via a net-service call (libstd's
//! `join_multicast_v6` is a stub there). Hosted mode reads the host's
//! interface tables and uses the real libstd socket options, so it interops
//! with a Python RNS on the same machine's LAN.

use std::collections::BTreeMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use reticulum_core::autointerface::{discovery_token, group_discovery_address};
use xous::CID;

use crate::net::{Shared, plock};

/// Discovery group name. Peers only see each other within the same group.
const GROUP_ID: &[u8] = b"reticulum";
/// Multicast destination port for discovery tokens.
const DISCOVERY_PORT: u16 = 29716;
/// Unicast destination port for reverse-peering tokens (DISCOVERY_PORT + 1).
const UNICAST_DISCOVERY_PORT: u16 = 29717;
/// Destination port for data (raw RNS packets).
const DATA_PORT: u16 = 42671;
/// How often we multicast our discovery token. The reference beacons every
/// 1.6 s, but that's a discovery-latency choice for mains-powered nodes, not
/// a protocol requirement — the contract is only that peers hear *some* token
/// from us inside their 22 s peering timeout, and after first contact the
/// unicast reverse-peering tokens (5.2 s) carry that duty. 10 s keeps us
/// inside every window with a retry to spare (2 beacons per 22 s), matches
/// the hub keepalive cadence (no extra radio wakeups), and only costs a new
/// peer up to ~10 s to notice us.
const ANNOUNCE_INTERVAL_MS: u64 = 10_000;
/// How often we send reverse-peering tokens to each known peer
/// (reference: ANNOUNCE_INTERVAL × 3.25 = 5.2 s — kept at the reference value
/// since it, not our slower beacon, is what keeps established peers alive).
const REVERSE_INTERVAL_MS: u64 = 5200;
/// Housekeeping cadence (peer expiry, reverse-peering checks). A thread
/// wakeup with no TX is cheap; this just bounds how stale the checks can be.
const TICK_MS: u64 = 2600;
/// A peer silent this long is dropped.
const PEERING_TIMEOUT_SECS: u64 = 22;
/// Upper bound on tracked peers (a LAN party, not the open internet).
const MAX_PEERS: usize = 16;
/// AutoInterface HW MTU; datagrams larger than this aren't RNS packets.
const HW_MTU: usize = 1196;

/// Live AutoInterface state, inside `Shared.auto`. The `enabled` toggle lives
/// beside it as `Shared.auto_enabled` (an atomic, so the outbound hot path can
/// check it without a lock).
pub struct AutoState {
    /// Threads + sockets are up (started once, run for the app's lifetime;
    /// disabling just idles them).
    pub started: bool,
    /// Our link-local address — the string peers hash to validate our token.
    pub our_ll: Option<Ipv6Addr>,
    /// IPv6 scope id for binds/sends — the OS interface index on hosted
    /// (link-local sends require it there), 0 on Xous (single interface).
    pub scope: u32,
    /// Send half of the data socket (cloned for each send).
    pub tx: Option<UdpSocket>,
    /// peer link-local address → (last heard secs, last token sent to it secs).
    pub peers: BTreeMap<Ipv6Addr, (u64, u64)>,
}

impl AutoState {
    pub fn new() -> Self {
        AutoState { started: false, our_ll: None, scope: 0, tx: None, peers: BTreeMap::new() }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Our link-local IPv6 address + scope id.
///
/// On Xous: the EUI-64 of the wifi MAC (fe80::mac[0]^02:…ff:fe…), matching
/// what the net service configures on the interface; known once wifi has a
/// config. Scope is 0 (one interface; the stack needs no disambiguation).
#[cfg(target_os = "xous")]
fn local_link_local() -> Option<(Ipv6Addr, u32)> {
    let conf = net::NetManager::new().get_ipv4_config()?;
    let m = conf.mac;
    let mut b = [0u8; 16];
    b[0] = 0xfe;
    b[1] = 0x80;
    b[8] = m[0] ^ 0x02;
    b[9] = m[1];
    b[10] = m[2];
    b[11] = 0xff;
    b[12] = 0xfe;
    b[13] = m[3];
    b[14] = m[4];
    b[15] = m[5];
    Some((Ipv6Addr::from(b), 0))
}

/// On hosted: the first fe80:: address of a non-loopback interface, from
/// /proc/net/if_inet6 ("addr32hex ifindex prefix scope flags ifname"; link
/// scope is 0x20). Scope id = the interface index.
#[cfg(not(target_os = "xous"))]
fn local_link_local() -> Option<(Ipv6Addr, u32)> {
    let table = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    for line in table.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || !f[0].starts_with("fe80") || f[5] == "lo" {
            continue;
        }
        let mut b = [0u8; 16];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&f[0][i * 2..i * 2 + 2], 16).ok()?;
        }
        let scope = u32::from_str_radix(f[1], 16).ok()?;
        return Some((Ipv6Addr::from(b), scope));
    }
    None
}

/// Subscribe the network stack to the discovery multicast group.
#[cfg(target_os = "xous")]
fn join_group(_sock: &UdpSocket, group: &Ipv6Addr, _scope: u32) -> bool {
    net::NetManager::new().join_multicast_v6(*group).unwrap_or(false)
}

#[cfg(not(target_os = "xous"))]
fn join_group(sock: &UdpSocket, group: &Ipv6Addr, scope: u32) -> bool {
    sock.join_multicast_v6(group, scope).is_ok()
}

/// Start AutoInterface (idempotent): bring up the sockets and threads on first
/// call, set `auto_enabled` and report status. Returns false (with the reason
/// painted on the status bar) when there's no link-local address yet — i.e.
/// wifi isn't up.
pub fn start(shared: &Arc<Shared>, chat_cid: CID) -> bool {
    let (our_ll, scope) = match local_link_local() {
        Some(v) => v,
        None => {
            chat::cf_set_status_text(chat_cid, "local peers: no IPv6 link-local address — wifi up?");
            return false;
        }
    };
    let group = group_discovery_address(GROUP_ID);
    let already_started = {
        let mut st = plock(&shared.auto);
        st.our_ll = Some(our_ll);
        st.scope = scope;
        st.started
    };
    if already_started {
        shared.auto_enabled.store(true, Ordering::SeqCst);
        chat::cf_set_status_text(chat_cid, "local peer discovery on");
        return true;
    }

    // The data socket receives raw RNS packets and is also our send socket
    // (the source port of announces and data doesn't matter to peers — they
    // address us by source IP + the fixed ports).
    let data_sock = match UdpSocket::bind(("::", DATA_PORT)) {
        Ok(s) => s,
        Err(e) => {
            chat::cf_set_status_text(chat_cid, &format!("local peers: data port bind failed: {e}"));
            return false;
        }
    };
    let discovery_sock = match UdpSocket::bind(("::", DISCOVERY_PORT)) {
        Ok(s) => s,
        Err(e) => {
            chat::cf_set_status_text(chat_cid, &format!("local peers: discovery bind failed: {e}"));
            return false;
        }
    };
    let unicast_disc_sock = match UdpSocket::bind(("::", UNICAST_DISCOVERY_PORT)) {
        Ok(s) => s,
        Err(e) => {
            chat::cf_set_status_text(chat_cid, &format!("local peers: discovery bind failed: {e}"));
            return false;
        }
    };
    if !join_group(&discovery_sock, &group, scope) {
        // Without the group subscription we can still be discovered (our
        // multicast announces go out fine) and reverse peering still reaches
        // us — say so rather than fail.
        log::warn!("couldn't join multicast group {group}; relying on reverse peering");
        chat::cf_set_status_text(chat_cid, "local peers: multicast join failed — discovery may be one-way");
    }

    {
        let mut st = plock(&shared.auto);
        st.tx = data_sock.try_clone().ok();
        st.started = true;
    }
    shared.auto_enabled.store(true, Ordering::SeqCst);

    let s = shared.clone();
    std::thread::spawn(move || discovery_rx(s, chat_cid, discovery_sock));
    let s = shared.clone();
    std::thread::spawn(move || discovery_rx(s, chat_cid, unicast_disc_sock));
    let s = shared.clone();
    std::thread::spawn(move || data_rx(s, chat_cid, data_sock));
    let s = shared.clone();
    std::thread::spawn(move || announce_loop(s, chat_cid, group));

    log::info!("AutoInterface up: ll={our_ll} scope={scope} group={group}");
    chat::cf_set_status_text(chat_cid, "local peer discovery on — listening…");
    true
}

/// Bring AutoInterface up in the background once the network is ready: at boot
/// wifi has no address yet and [`start`] would fail loudly; this polls quietly
/// (forever — wifi may come up any time) and starts the moment a link-local
/// address exists. Used to restore a persisted "on" across an app restart;
/// gives up silently if the user toggles it off while still waiting.
pub fn start_background(shared: &Arc<Shared>, chat_cid: CID) {
    shared.auto_enabled.store(true, Ordering::SeqCst);
    let shared = shared.clone();
    std::thread::spawn(move || {
        loop {
            if !enabled(&shared) {
                return; // toggled off before the network came up
            }
            if local_link_local().is_some() {
                start(&shared, chat_cid);
                return;
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    });
}

/// Disable AutoInterface: stop announcing/accepting and forget peers. Threads
/// and sockets stay up (idle) so a re-enable is instant.
pub fn stop(shared: &Arc<Shared>, chat_cid: CID) {
    shared.auto_enabled.store(false, Ordering::SeqCst);
    plock(&shared.auto).peers.clear();
    chat::cf_set_status_text(chat_cid, "local peer discovery off");
}

pub fn enabled(shared: &Arc<Shared>) -> bool { shared.auto_enabled.load(Ordering::SeqCst) }

/// Both discovery listeners feed here: validate the token against the source
/// address, then add/refresh the peer.
fn discovery_rx(shared: Arc<Shared>, chat_cid: CID, sock: UdpSocket) {
    let mut buf = [0u8; 1024];
    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
        };
        if !enabled(&shared) {
            continue;
        }
        let src_ip = match src {
            SocketAddr::V6(a) => *a.ip(),
            _ => continue,
        };
        let our_ll = plock(&shared.auto).our_ll;
        if Some(src_ip) == our_ll {
            // Our own multicast, echoed back by the AP: proves multicast
            // works, but we are not our own peer.
            continue;
        }
        if n < 32 || buf[..32] != discovery_token(GROUP_ID, &src_ip) {
            log::debug!("discovery token mismatch from {src_ip}");
            continue;
        }
        let mut st = plock(&shared.auto);
        let now = now_secs();
        let is_new = !st.peers.contains_key(&src_ip);
        if is_new && st.peers.len() >= MAX_PEERS {
            // Evict the longest-silent peer.
            if let Some(oldest) = st.peers.iter().min_by_key(|(_, (heard, _))| *heard).map(|(a, _)| *a) {
                st.peers.remove(&oldest);
            }
        }
        st.peers.entry(src_ip).and_modify(|(heard, _)| *heard = now).or_insert((now, 0));
        let count = st.peers.len();
        drop(st);
        if is_new {
            log::info!("local peer discovered: {src_ip}");
            chat::cf_set_status_text(chat_cid, &format!("✦ local peer found ({count} nearby)"));
        }
    }
}

/// Data listener: every datagram is one raw RNS packet — straight into the
/// same transport the hub frames feed.
fn data_rx(shared: Arc<Shared>, chat_cid: CID, sock: UdpSocket) {
    crate::net::wait_for_time_server();
    let pddb = pddb::Pddb::new();
    let trng = match xous_names::XousNames::new().ok().and_then(|xns| trng::Trng::new(&xns).ok()) {
        Some(t) => t,
        None => {
            log::error!("AutoInterface data thread: TRNG init failed");
            return;
        }
    };
    let mut buf = [0u8; HW_MTU + 64];
    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
        };
        if !enabled(&shared) || n == 0 || n > HW_MTU {
            continue;
        }
        // Only peers that completed discovery are part of this interface —
        // same gate as the reference (spawned per-peer sub-interfaces).
        let src_ip = match src {
            SocketAddr::V6(a) => *a.ip(),
            _ => continue,
        };
        if !plock(&shared.auto).peers.contains_key(&src_ip) {
            log::debug!("data from undiscovered {src_ip}, ignoring");
            continue;
        }
        crate::net::handle_frame(&shared, chat_cid, &pddb, &trng, &buf[..n]);
    }
}

/// Multicast our token every [`ANNOUNCE_INTERVAL_MS`]; reverse-peer to each
/// known peer every [`REVERSE_INTERVAL_MS`]; expire peers not heard from in
/// [`PEERING_TIMEOUT_SECS`].
fn announce_loop(shared: Arc<Shared>, _chat_cid: CID, group: Ipv6Addr) {
    let mut last_beacon: u64 = 0;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(TICK_MS));
        if !enabled(&shared) {
            continue;
        }
        let (our_ll, scope, tx) = {
            let st = plock(&shared.auto);
            (st.our_ll, st.scope, st.tx.as_ref().and_then(|s| s.try_clone().ok()))
        };
        let (our_ll, tx) = match (our_ll, tx) {
            (Some(a), Some(t)) => (a, t),
            _ => continue,
        };
        let token = discovery_token(GROUP_ID, &our_ll);
        if now_secs().saturating_sub(last_beacon) * 1000 >= ANNOUNCE_INTERVAL_MS {
            last_beacon = now_secs();
            let dest = SocketAddrV6::new(group, DISCOVERY_PORT, 0, scope);
            if let Err(e) = tx.send_to(&token, dest) {
                log::warn!("multicast announce failed: {e}");
            }
        }

        let now = now_secs();
        // Snapshot under the lock; sends happen outside it.
        let (expired, reverse): (Vec<Ipv6Addr>, Vec<Ipv6Addr>) = {
            let mut st = plock(&shared.auto);
            let expired: Vec<Ipv6Addr> = st
                .peers
                .iter()
                .filter(|(_, (heard, _))| now > heard + PEERING_TIMEOUT_SECS)
                .map(|(a, _)| *a)
                .collect();
            for a in &expired {
                st.peers.remove(a);
            }
            let reverse: Vec<Ipv6Addr> = st
                .peers
                .iter_mut()
                .filter(|(_, (_, out))| now.saturating_sub(*out) * 1000 >= REVERSE_INTERVAL_MS)
                .map(|(a, (_, out))| {
                    *out = now;
                    *a
                })
                .collect();
            (expired, reverse)
        };
        for a in expired {
            log::info!("local peer timed out: {a}");
        }
        for a in reverse {
            let dest = SocketAddrV6::new(a, UNICAST_DISCOVERY_PORT, 0, scope);
            tx.send_to(&token, dest).ok();
        }
    }
}

/// Send a raw RNS packet to every live local peer. Returns true if at least
/// one send was accepted. The outbound hot path: called for every packet the
/// app emits (see `net::broadcast_out`).
pub fn send_to_peers(shared: &Arc<Shared>, raw: &[u8]) -> bool {
    if raw.is_empty() || raw.len() > HW_MTU || !enabled(shared) {
        return false;
    }
    let (scope, tx, peers) = {
        let st = plock(&shared.auto);
        if st.peers.is_empty() {
            return false;
        }
        let peers: Vec<Ipv6Addr> = st.peers.keys().copied().collect();
        (st.scope, st.tx.as_ref().and_then(|s| s.try_clone().ok()), peers)
    };
    let tx = match tx {
        Some(t) => t,
        None => return false,
    };
    let mut any = false;
    for a in peers {
        let dest = SocketAddrV6::new(a, DATA_PORT, 0, scope);
        match tx.send_to(raw, dest) {
            Ok(_) => any = true,
            Err(e) => log::debug!("send to local peer {a} failed: {e}"),
        }
    }
    any
}

