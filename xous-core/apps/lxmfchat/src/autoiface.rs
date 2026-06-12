//! Reticulum AutoInterface (see RNS `Interfaces/AutoInterface.py`): peers
//! multicast a discovery token — SHA-256(group_id ‖ own link-local address as
//! text) — validated by receivers against the datagram's source address, plus
//! unicast "reverse peering" tokens so one-way multicast still converges.
//! Data is raw RNS packets, one per UDP datagram (no HDLC framing).

use std::collections::BTreeMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use reticulum_core::autointerface::{discovery_token, group_discovery_address};
use xous::CID;

use crate::net::{Shared, plock};

const GROUP_ID: &[u8] = b"reticulum";
const DISCOVERY_PORT: u16 = 29716;
const UNICAST_DISCOVERY_PORT: u16 = 29717;
const DATA_PORT: u16 = 42671;
/// The reference beacons every 1.6 s, but the only protocol contract is that
/// peers hear *some* token of ours inside their 22 s timeout — which the
/// 5.2 s reverse-peering tokens satisfy after first contact. 10 s saves the
/// radio and only delays a brand-new peer noticing us.
const ANNOUNCE_INTERVAL_MS: u64 = 10_000;
const REVERSE_INTERVAL_MS: u64 = 5200;
const TICK_MS: u64 = 2600;
const PEERING_TIMEOUT_SECS: u64 = 22;
const MAX_PEERS: usize = 16;
const HW_MTU: usize = 1196;

pub struct AutoState {
    pub started: bool,
    pub our_ll: Option<Ipv6Addr>,
    /// Interface index on hosted (Linux requires it for link-local sends);
    /// 0 on Xous (single interface).
    pub scope: u32,
    pub tx: Option<UdpSocket>,
    /// peer address → (last heard secs, last token sent secs).
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

/// EUI-64 of the wifi MAC — must match the address the net service configures
/// on the interface, since peers hash our *source* address to validate us.
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

/// /proc/net/if_inet6 lines: "addr32hex ifindex prefix scope flags ifname".
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

/// libstd's `join_multicast_v6` is a stub on Xous; group membership lives in
/// the net service.
#[cfg(target_os = "xous")]
fn join_group(_sock: &UdpSocket, group: &Ipv6Addr, _scope: u32) -> bool {
    net::NetManager::new().join_multicast_v6(*group).unwrap_or(false)
}

#[cfg(not(target_os = "xous"))]
fn join_group(sock: &UdpSocket, group: &Ipv6Addr, scope: u32) -> bool {
    sock.join_multicast_v6(group, scope).is_ok()
}

/// Idempotent. Returns false (reason on the status bar) when there's no
/// link-local address yet, i.e. wifi isn't up.
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
        // Not fatal: our own announces still go out, and reverse peering
        // reaches us unicast — discovery is merely one-way.
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
    // The netstack must actually hold our fe80 or every v6 send is silently
    // dropped at source selection — surface that, it's invisible otherwise.
    #[cfg(target_os = "xous")]
    match net::NetManager::new().has_ipv6_addr(our_ll) {
        Ok(1) => {}
        Ok(0) => chat::cf_set_status_text(chat_cid, "local: netstack has NO IPv6 address!"),
        Ok(_) => chat::cf_set_status_text(chat_cid, "local: netstack IPv6 addr differs from ours!"),
        Err(_) => {}
    }
    true
}

/// Restore a persisted "on" across an app restart: polls quietly until wifi
/// has an address, then starts. Gives up if toggled off while waiting.
pub fn start_background(shared: &Arc<Shared>, chat_cid: CID) {
    shared.auto_enabled.store(true, Ordering::SeqCst);
    let shared = shared.clone();
    std::thread::spawn(move || {
        loop {
            if !enabled(&shared) {
                return;
            }
            if local_link_local().is_some() {
                start(&shared, chat_cid);
                return;
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    });
}

/// Threads and sockets stay up (idle) so a re-enable is instant.
pub fn stop(shared: &Arc<Shared>, chat_cid: CID) {
    shared.auto_enabled.store(false, Ordering::SeqCst);
    plock(&shared.auto).peers.clear();
    chat::cf_set_status_text(chat_cid, "local peer discovery off");
}

pub fn enabled(shared: &Arc<Shared>) -> bool { shared.auto_enabled.load(Ordering::SeqCst) }

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
            // Our own multicast, echoed back by the AP.
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

fn announce_loop(shared: Arc<Shared>, chat_cid: CID, group: Ipv6Addr) {
    let mut last_beacon: u64 = 0;
    // One status line on the first successful beacon, and on errors (throttled)
    // — a beacon that the netstack eats silently is otherwise indistinguishable
    // from a working one.
    let mut beacon_confirmed = false;
    let mut last_err_status: u64 = 0;
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
            match tx.send_to(&token, dest) {
                Ok(_) => {
                    if !beacon_confirmed {
                        beacon_confirmed = true;
                        chat::cf_set_status_text(chat_cid, &format!("local: beaconing as {our_ll}"));
                    }
                }
                Err(e) => {
                    log::warn!("multicast announce failed: {e}");
                    if now_secs().saturating_sub(last_err_status) > 30 {
                        last_err_status = now_secs();
                        chat::cf_set_status_text(chat_cid, &format!("local: beacon failed: {e}"));
                    }
                }
            }
        }

        let now = now_secs();
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

/// Send a raw RNS packet to every live local peer; true if any send was
/// accepted.
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
