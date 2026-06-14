//! Host Reticulum/LXMF client for interop testing against a real `rnsd`.
//!
//! Connects to a hub over TCP (RNS `TCPServerInterface`), announces our
//! `lxmf.delivery` destination, and either listens for inbound announces +
//! LXMF messages, or sends an opportunistic LXMF message to a destination it
//! has learned via announce.
//!
//! Usage:
//!   reticulum-host-client listen <host:port> [seconds]
//!   reticulum-host-client send   <host:port> <recipient_dest_hash_hex> <text> [seconds]
//!   reticulum-host-client fetch  <host:port> <node_dest_hash_hex> [page_path] [seconds]
//!
//! The identity is fixed (x25519=0x05*32, ed25519=0x06*32) so its address is
//! stable across runs; pass RUST_LOG=info for detail.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lxmf::message::{self, Fields};
use lxmf::msgpack::{self, Value};
use rand_core::OsRng;
use reticulum_core::constants::{
    CONTEXT_REQUEST, CONTEXT_RESOURCE, CONTEXT_RESOURCE_ADV, CONTEXT_RESOURCE_HMU,
    CONTEXT_RESOURCE_REQ, CONTEXT_RESPONSE, KEY_HALF,
};
use reticulum_core::crypto::{full_hash, truncated_hash};
use reticulum_core::destination::single_destination_hash;
use reticulum_core::hdlc::{Deframer, frame};
use reticulum_core::identity::PrivateIdentity;
use reticulum_core::resource::ResourceReceiver;
use reticulum_core::transport::{Event, PathIface, Transport};

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() }

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn main() {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <listen|send> <host:port> [...]", args[0]);
        std::process::exit(64);
    }
    let mode = args[1].as_str();
    let addr = args[2].clone();

    // Identity seed (override with HOST_SEED=<n> to run two distinct nodes).
    let seed = std::env::var("HOST_SEED").ok().and_then(|s| s.parse::<u8>().ok()).unwrap_or(0x05);
    let identity = PrivateIdentity::from_bytes(&[seed; KEY_HALF], &[seed.wrapping_add(1); KEY_HALF]);
    let our_dh = single_destination_hash("lxmf", &["delivery"], &identity.hash());
    let mut tp = Transport::new(identity);
    tp.register_destination(our_dh);
    println!("our lxmf address: {}", reticulum_core::hex(&our_dh));

    let stream = TcpStream::connect(&addr).expect("connect to hub");
    stream.set_nodelay(true).ok();
    let mut writer = stream.try_clone().expect("clone stream");

    // Reader thread: deframe HDLC and forward packets to the main loop.
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut deframer = Deframer::new();
        let mut buf = [0u8; 4096];
        let mut s = stream;
        loop {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    for f in deframer.push(&buf[..n]) {
                        if tx.send(f).is_err() {
                            return;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Announce ourselves so the hub (and peers) learn a path to us.
    let ann = tp.make_announce("lxmf", &["delivery"], b"host-client", &mut OsRng, now());
    writer.write_all(&frame(&ann)).expect("send announce");
    writer.flush().ok();
    println!("sent announce ({} bytes)", ann.len());

    let is_send = mode == "send" || mode == "send-direct";
    // `sync <host:port> <pn_propagation_dest_hex> [seconds]` downloads stored
    // messages from a propagation node (validates the Resource receiver + sync).
    // `fetch <host:port> <node_dest_hex> [path] [seconds]` requests a micron
    // page from a NomadNet node, anonymously (no identify), and dumps the
    // parsed result (validates the page-browser protocol path).
    let needs_target = is_send || mode == "sync" || mode == "fetch";
    let listen_secs: u64 = match mode {
        "listen" => args.get(3).and_then(|s| s.parse().ok()).unwrap_or(30),
        "sync" => args.get(4).and_then(|s| s.parse().ok()).unwrap_or(30),
        "fetch" => args.get(5).and_then(|s| s.parse().ok()).unwrap_or(30),
        _ if is_send => args.get(5).and_then(|s| s.parse().ok()).unwrap_or(30),
        _ => 30,
    };
    let fetch_path: String =
        args.get(4).cloned().unwrap_or_else(|| "/page/index.mu".to_string());

    let mut sync_phase: u8 = 0; // 0 idle, 1 list requested, 2 messages requested
    let mut sync_rx: Option<ResourceReceiver> = None;
    // Inbound resources: large direct messages arriving on links peers open to us.
    let mut in_rxs: std::collections::HashMap<[u8; 16], ResourceReceiver> = std::collections::HashMap::new();

    let target: Option<[u8; 16]> = if needs_target {
        let v = unhex(&args[3]);
        let mut h = [0u8; 16];
        h.copy_from_slice(&v);
        Some(h)
    } else {
        None
    };
    let text = if is_send { args[4].clone() } else { String::new() };
    let mut sent = false;
    let mut fetch_done = false;
    // listen mode: a backchannel reply waiting for the peer's LINKIDENTIFY
    // (LXMF identifies lazily — often after the first data packet).
    let mut pending_bc: Option<([u8; 16], [u8; 16])> = None; // (link_id, peer dest)

    // On an access-point hub, announces aren't relayed to us, so path-request the
    // target to learn its key (the hub answers with the target's announce). Mirrors
    // the app's `request_peer_key`.
    if let Some(t) = target {
        let mut tag = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut tag);
        let pr = tp.make_path_request(&t, &tag);
        writer.write_all(&frame(&pr)).ok();
        writer.flush().ok();
        println!("sent path request for {}", reticulum_core::hex(&t));
    }

    let deadline = Instant::now() + Duration::from_secs(listen_secs);
    while Instant::now() < deadline && !fetch_done {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(raw) => {
                let mut gen = || {
                    let mut b = [0u8; 32];
                    rand_core::RngCore::fill_bytes(&mut OsRng, &mut b);
                    b
                };
                match tp.handle_frame(&raw, &mut gen, PathIface::Hub) {
                    Event::LinkEstablished { link_id, proof } => {
                        println!("LINK ESTABLISHED {} — sending proof", reticulum_core::hex(&link_id));
                        writer.write_all(&frame(&proof)).ok();
                        writer.flush().ok();
                    }
                    Event::LinkData { link_id, plaintext, proof } => {
                        println!("LINK DATA on {} ({} bytes) — sending proof", reticulum_core::hex(&link_id), plaintext.len());
                        writer.write_all(&frame(&proof)).ok();
                        writer.flush().ok();
                        let src_id = if plaintext.len() >= 32 {
                            let mut h = [0u8; 16];
                            h.copy_from_slice(&plaintext[16..32]);
                            tp.known(&h).map(|k| k.identity.clone())
                        } else {
                            None
                        };
                        match message::parse(&plaintext, src_id.as_ref()) {
                            Ok(m) => println!(
                                ">>> LINK LXMF content={:?} sig_valid={}",
                                m.content_string(),
                                m.signature_validated
                            ),
                            Err(e) => println!("link LXMF parse failed: {:?}", e),
                        }
                        // In listen mode, exercise the backchannel: reply over the
                        // SAME inbound link and await the initiator's packet proof
                        // (it signs with its link-ephemeral Ed25519, not its
                        // identity — Event::Delivered validates that).
                        if mode == "listen" && plaintext.len() >= 32 {
                            let mut peer = [0u8; 16];
                            peer.copy_from_slice(&plaintext[16..32]);
                            if !send_backchannel_reply(&mut writer, &mut tp, &link_id, &peer, &our_dh) {
                                println!("backchannel reply queued: awaiting LINKIDENTIFY");
                                pending_bc = Some((link_id, peer));
                            }
                        }
                    }
                    Event::LinkIdentified { link_id, identity } => {
                        println!(
                            ">>> BACKCHANNEL: peer identified on link {} (identity hash {})",
                            reticulum_core::hex(&link_id),
                            reticulum_core::hex(&identity.hash)
                        );
                        if let Some((lid, peer)) = pending_bc {
                            if lid == link_id
                                && send_backchannel_reply(&mut writer, &mut tp, &lid, &peer, &our_dh)
                            {
                                pending_bc = None;
                            }
                        }
                    }
                    Event::LinkKeepalive { link_id, reply } => {
                        writer.write_all(&frame(&reply)).ok();
                        writer.flush().ok();
                        println!("echoed keepalive on {}", reticulum_core::hex(&link_id));
                    }
                    Event::InLinkClosed { link_id } => {
                        println!("inbound link {} closed by initiator", reticulum_core::hex(&link_id));
                    }
                    Event::DataUndecryptable { reason, .. } => {
                        println!("UNDECRYPTABLE: {}", reason);
                    }
                    Event::AddressedUnhandled { packet_type, context, .. } => {
                        println!("addressed-unhandled type={} ctx=0x{:02x}", packet_type, context);
                    }
                    Event::Announce { destination_hash, info } => {
                        println!(
                            "announce: {} app_data={:?}",
                            reticulum_core::hex(&destination_hash),
                            String::from_utf8_lossy(&info.app_data)
                        );
                        // If we're sending and just learned the target, send now.
                        if let Some(t) = target {
                            if destination_hash == t && !sent {
                                if mode == "send-direct" || mode == "sync" || mode == "fetch" {
                                    // Initiate a link; we deliver / sync once it's up.
                                    let known = tp.known(&t).expect("target known").clone();
                                    let mut ex = [0u8; 32];
                                    let mut ed = [0u8; 32];
                                    rand_core::RngCore::fill_bytes(&mut OsRng, &mut ex);
                                    rand_core::RngCore::fill_bytes(&mut OsRng, &mut ed);
                                    let (req, lid) = tp.make_link_request(&t, &known.identity, &ex, &ed, now());
                                    writer.write_all(&frame(&req)).ok();
                                    writer.flush().ok();
                                    println!("sent link request to {} (link {})", reticulum_core::hex(&t), reticulum_core::hex(&lid));
                                } else {
                                    send_message(&mut writer, &tp, &t, &our_dh, &text);
                                }
                                sent = true;
                            }
                        }
                    }
                    Event::OutboundLinkUp { link_id, target: lt } => {
                        println!("OUTBOUND LINK UP {} -> {}", reticulum_core::hex(&link_id), reticulum_core::hex(&lt));
                        // Activate the responder's link first (RNS drops data on an
                        // un-RTT'd link).
                        let mut riv = [0u8; 16];
                        rand_core::RngCore::fill_bytes(&mut OsRng, &mut riv);
                        if let Some(rtt) = tp.make_link_rtt(&link_id, &riv) {
                            writer.write_all(&frame(&rtt)).ok();
                            writer.flush().ok();
                            println!("sent link RTT ({} bytes)", rtt.len());
                        }
                        if mode == "sync" {
                            // Identify to the node, then request the message-id list.
                            let mut iiv = [0u8; 16];
                            rand_core::RngCore::fill_bytes(&mut OsRng, &mut iiv);
                            if let Some(idp) = tp.make_out_link_identify(&link_id, &iiv) {
                                writer.write_all(&frame(&idp)).ok();
                                writer.flush().ok();
                                println!("sync: identified to node");
                            }
                            sync_send_get(&mut writer, &tp, &link_id, Value::Array(vec![Value::Nil, Value::Nil]));
                            sync_phase = 1;
                            println!("sync: requested message list");
                        } else if mode == "fetch" {
                            // Anonymous page request: deliberately NO identify
                            // (node page handlers are ALLOW_ALL). The path may
                            // carry NomadNet-style URL vars after a backtick
                            // ("/page/group.mu`g=mirrors") — sent as the
                            // {"var_<k>": v} request-data dict.
                            let (path, data) = match fetch_path.split_once('`') {
                                Some((p, varstr)) => {
                                    let vars: Vec<(String, Value)> = varstr
                                        .split('|')
                                        .filter_map(|e| e.split_once('='))
                                        .map(|(k, v)| (format!("var_{k}"), Value::Str(v.to_string())))
                                        .collect();
                                    (p.to_string(), Value::StrMap(vars))
                                }
                                None => (fetch_path.clone(), Value::Nil),
                            };
                            send_request(&mut writer, &tp, &link_id, path.as_bytes(), data);
                            println!("fetch: requested {}", fetch_path);
                        } else {
                            // Identify on the link so the peer's LXMRouter registers
                            // a backchannel — large replies then arrive here as
                            // Resources on this same link.
                            let mut iiv = [0u8; 16];
                            rand_core::RngCore::fill_bytes(&mut OsRng, &mut iiv);
                            if let Some(idp) = tp.make_out_link_identify(&link_id, &iiv) {
                                writer.write_all(&frame(&idp)).ok();
                                writer.flush().ok();
                                println!("identified on link (backchannel armed)");
                            }
                            let msg = message::pack(
                                tp.identity(), &lt, &our_dh, now() as f64, b"", text.as_bytes(), &Fields::new(), None,
                            );
                            if msg.packed.len() > 431 {
                                // Too big for one link packet: send as a Resource.
                                let mut r = [0u8; 4];
                                let mut pf = [0u8; 4];
                                let mut iv = [0u8; 16];
                                let mut aiv = [0u8; 16];
                                rand_core::RngCore::fill_bytes(&mut OsRng, &mut r);
                                rand_core::RngCore::fill_bytes(&mut OsRng, &mut pf);
                                rand_core::RngCore::fill_bytes(&mut OsRng, &mut iv);
                                rand_core::RngCore::fill_bytes(&mut OsRng, &mut aiv);
                                if let Some((adv, h)) =
                                    tp.make_link_resource(&link_id, &msg.packed, r, pf, &iv, &aiv)
                                {
                                    writer.write_all(&frame(&adv)).ok();
                                    writer.flush().ok();
                                    println!(
                                        "sent RESOURCE advertisement ({} bytes payload), awaiting proof {}",
                                        msg.packed.len(),
                                        reticulum_core::hex(&h)
                                    );
                                }
                            } else {
                                let mut iv = [0u8; 16];
                                rand_core::RngCore::fill_bytes(&mut OsRng, &mut iv);
                                if let Some((raw, ph)) = tp.make_link_data(&link_id, &msg.packed, &iv) {
                                    writer.write_all(&frame(&raw)).ok();
                                    writer.flush().ok();
                                    println!("sent direct LXMF over link ({} bytes), awaiting proof {}", raw.len(), reticulum_core::hex(&ph));
                                }
                            }
                        }
                    }
                    Event::Delivered { packet_hash } => {
                        println!(">>> DELIVERED (proof matched {})", reticulum_core::hex(&packet_hash));
                    }
                    Event::Data { destination_hash, plaintext, proof } => {
                        // Send the delivery proof back (the sender's ✓), then
                        // prepend our dest hash and parse the LXMF.
                        writer.write_all(&frame(&proof)).ok();
                        writer.flush().ok();
                        let mut lxmf_bytes = destination_hash.to_vec();
                        lxmf_bytes.extend_from_slice(&plaintext);
                        let src_hash = if lxmf_bytes.len() >= 32 {
                            let mut h = [0u8; 16];
                            h.copy_from_slice(&lxmf_bytes[16..32]);
                            Some(h)
                        } else {
                            None
                        };
                        let src_id = src_hash.and_then(|h| tp.known(&h)).map(|k| k.identity.clone());
                        match message::parse(&lxmf_bytes, src_id.as_ref()) {
                            Ok(m) => println!(
                                ">>> LXMF from {} | title={:?} content={:?} | sig_valid={}",
                                reticulum_core::hex(&m.source_hash),
                                m.title_string(),
                                m.content_string(),
                                m.signature_validated
                            ),
                            Err(e) => println!("inbound data, but LXMF parse failed: {:?}", e),
                        }
                    }
                    Event::OutLinkData { link_id, context, plaintext } => {
                        // Serve part requests for a Resource we're sending.
                        if context == CONTEXT_RESOURCE_REQ {
                            let mut iv = [0u8; 16];
                            rand_core::RngCore::fill_bytes(&mut OsRng, &mut iv);
                            let packets = tp.serve_link_resource(&link_id, &plaintext, &iv);
                            if !packets.is_empty() {
                                println!("serving {} resource packet(s)", packets.len());
                                for p in packets {
                                    writer.write_all(&frame(&p)).ok();
                                }
                                writer.flush().ok();
                                continue;
                            }
                        }
                        if mode == "sync" {
                            sync_handle_outlink(&mut writer, &tp, &mut sync_phase, &mut sync_rx, &link_id, context, plaintext);
                        } else if mode == "fetch" {
                            if let Some(payload) =
                                outlink_response(&mut writer, &tp, &mut sync_rx, &link_id, context, plaintext)
                            {
                                if let Some(resp) = parse_resp(&payload) {
                                    fetch_response(resp);
                                    fetch_done = true;
                                }
                            }
                        } else {
                            // A Resource arriving on a link WE opened: the peer's
                            // LXMRouter is replying over the backchannel.
                            link_resource(&mut writer, &tp, &mut in_rxs, &link_id, context, plaintext, false);
                        }
                    }
                    Event::InLinkData { link_id, context, plaintext } => {
                        link_resource(&mut writer, &tp, &mut in_rxs, &link_id, context, plaintext, true);
                    }
                    Event::OutLinkClosed { link_id } => {
                        println!("outbound link {} closed by responder", reticulum_core::hex(&link_id));
                    }
                    Event::PathRequest { destination_hash } => {
                        println!("path request for {} — answering with path response", reticulum_core::hex(&destination_hash));
                        let mut r5 = [0u8; 5];
                        rand_core::RngCore::fill_bytes(&mut OsRng, &mut r5);
                        let resp = tp.make_path_response_with("lxmf", &["delivery"], b"host-client", &r5, now());
                        writer.write_all(&frame(&resp)).ok();
                        writer.flush().ok();
                    }
                    Event::Unhandled { packet_type, context, .. } => {
                        log::debug!("unhandled packet type={} ctx={}", packet_type, context);
                    }
                    Event::Dropped(why) => log::debug!("dropped: {}", why),
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    if mode == "send" && !sent {
        eprintln!("never learned target {} via announce; not sent", args[3]);
        std::process::exit(1);
    }
    println!("done");
}

// ---- propagation-node sync (validates the Resource receiver + /get exchange) ---

fn sync_send_get(writer: &mut TcpStream, tp: &Transport, link_id: &[u8; 16], data: Value) {
    send_request(writer, tp, link_id, b"/get", data);
}

/// Send an RNS request on an out-link: msgpack([now, truncated_hash(path), data])
/// as a DATA packet with context REQUEST. The node replies with
/// msgpack([request_id, response]) as a RESPONSE packet or a Resource.
fn send_request(writer: &mut TcpStream, tp: &Transport, link_id: &[u8; 16], path: &[u8], data: Value) {
    let path_hash = truncated_hash(path);
    let req = Value::Array(vec![Value::F64(now() as f64), Value::Bin(path_hash.to_vec()), data]);
    let packed = msgpack::encode(&req);
    let mut iv = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut iv);
    if let Some(raw) = tp.make_out_link_context(link_id, CONTEXT_REQUEST, &packed, &iv) {
        writer.write_all(&frame(&raw)).ok();
        writer.flush().ok();
    }
}

fn parse_resp(payload: &[u8]) -> Option<Value> {
    let v = msgpack::decode(payload).ok()?;
    let arr = v.as_array()?;
    if arr.len() < 2 {
        return None;
    }
    Some(arr[1].clone())
}

fn sync_handle_outlink(
    writer: &mut TcpStream,
    tp: &Transport,
    phase: &mut u8,
    rx: &mut Option<ResourceReceiver>,
    link_id: &[u8; 16],
    context: u8,
    plaintext: Vec<u8>,
) {
    if let Some(payload) = outlink_response(writer, tp, rx, link_id, context, plaintext) {
        if let Some(resp) = parse_resp(&payload) {
            sync_response(writer, tp, phase, link_id, resp);
        }
    }
}

/// Drive one out-link frame of an RNS request/response exchange. Returns the
/// complete msgpack([request_id, response]) payload once available — directly
/// for a RESPONSE packet, or after downloading + decrypting + proving a
/// response Resource (ADV/HMU/parts pumped via `rx`).
fn outlink_response(
    writer: &mut TcpStream,
    tp: &Transport,
    rx: &mut Option<ResourceReceiver>,
    link_id: &[u8; 16],
    context: u8,
    plaintext: Vec<u8>,
) -> Option<Vec<u8>> {
    match context {
        CONTEXT_RESPONSE => Some(plaintext),
        CONTEXT_RESOURCE_ADV => {
            match ResourceReceiver::accept(&plaintext) {
                Ok(mut r) => {
                    if let Some(req) = r.next_request() {
                        send_resource_req(writer, tp, link_id, &req, false);
                    }
                    *rx = Some(r);
                    println!("receiving resource response…");
                }
                Err(e) => println!("resource advertisement rejected: {e}"),
            }
            None
        }
        CONTEXT_RESOURCE_HMU => {
            if let Some(r) = rx.as_mut() {
                match r.receive_hashmap_update(&plaintext) {
                    Ok(()) => {
                        if let Some(req) = r.next_request() {
                            send_resource_req(writer, tp, link_id, &req, false);
                        }
                    }
                    Err(e) => println!("bad hashmap update: {e}"),
                }
            }
            None
        }
        CONTEXT_RESOURCE => {
            let (complete, next_req) = match rx.as_mut() {
                Some(r) => {
                    let window_done = r.receive_part(&plaintext);
                    if r.is_complete() {
                        (true, None)
                    } else if window_done {
                        (false, r.next_request())
                    } else {
                        (false, None)
                    }
                }
                None => (false, None),
            };
            if let Some(req) = next_req {
                send_resource_req(writer, tp, link_id, &req, false);
            }
            if !complete {
                return None;
            }
            let r = rx.take().unwrap();
            let stream = r.concat();
            let plain = if r.encrypted() {
                match tp.decrypt_out_link(link_id, &stream) {
                    Some(p) => p,
                    None => {
                        println!("resource stream decrypt failed");
                        return None;
                    }
                }
            } else {
                stream
            };
            match r.finish(&plain) {
                Ok((payload, proof)) => {
                    if let Some(p) = tp.make_out_link_resource_proof(link_id, &proof) {
                        writer.write_all(&frame(&p)).ok();
                        writer.flush().ok();
                    }
                    Some(payload)
                }
                Err(e) => {
                    println!("resource finish failed: {e}");
                    None
                }
            }
        }
        _ => None,
    }
}

/// Print a fetched page: the raw micron source, then the parsed line/link dump.
fn fetch_response(resp: Value) {
    let bytes: Vec<u8> = match &resp {
        Value::Int(code) => {
            println!("fetch: node returned error code {code}");
            return;
        }
        Value::Bin(b) => b.clone(),
        Value::Str(s) => s.as_bytes().to_vec(),
        other => {
            println!("fetch: unexpected response shape: {other:?}");
            return;
        }
    };
    let src = String::from_utf8_lossy(&bytes);
    println!("=== PAGE SOURCE ({} bytes) ===", bytes.len());
    println!("{src}");
    let doc = micron::parse(&src);
    println!("=== PARSED ({} lines, {} links) ===", doc.lines.len(), doc.links.len());
    for l in &doc.lines {
        let style = match l.style {
            micron::Style::Regular => "reg ",
            micron::Style::Bold => "bold",
            micron::Style::Mono => "mono",
            micron::Style::Heading(n) => match n {
                1 => "h1  ",
                2 => "h2  ",
                _ => "h3  ",
            },
        };
        let kind = match l.kind {
            micron::Kind::Divider => "—".to_string(),
            micron::Kind::Link(id) => format!("link#{id} {}", l.text),
            micron::Kind::Text => l.text.clone(),
        };
        println!("[{style}] {kind}");
    }
    for (i, link) in doc.links.iter().enumerate() {
        println!("link[{i}] {:?} -> {:?} ({:?})", link.label, link.url, micron::resolve_link(&link.url));
    }
    println!(">>> PAGE OK ({} lines, {} links)", doc.lines.len(), doc.links.len());
}

/// Receive a Resource on a link — a peer sending us a direct message too
/// large for a single link packet. `inbound` selects which key table the
/// link lives in: links peers opened to us vs links we opened (a backchannel
/// reply rides the latter). Accept the advertisement, request the parts,
/// reassemble + decrypt + verify, prove receipt (the sender's delivery
/// confirmation), and parse the recovered LXMF message.
fn link_resource(
    writer: &mut TcpStream,
    tp: &Transport,
    rxs: &mut std::collections::HashMap<[u8; 16], ResourceReceiver>,
    link_id: &[u8; 16],
    context: u8,
    plaintext: Vec<u8>,
    inbound: bool,
) {
    match context {
        CONTEXT_RESOURCE_ADV => match ResourceReceiver::accept(&plaintext) {
            Ok(mut r) => {
                if let Some(req) = r.next_request() {
                    send_resource_req(writer, tp, link_id, &req, inbound);
                }
                rxs.insert(*link_id, r);
                println!("inbound resource on link {} — requesting parts…", reticulum_core::hex(link_id));
            }
            Err(e) => println!("inbound resource advertisement rejected: {e}"),
        },
        CONTEXT_RESOURCE_HMU => {
            if let Some(r) = rxs.get_mut(link_id) {
                match r.receive_hashmap_update(&plaintext) {
                    Ok(()) => {
                        if let Some(req) = r.next_request() {
                            send_resource_req(writer, tp, link_id, &req, inbound);
                        }
                    }
                    Err(e) => println!("inbound resource: bad hashmap update: {e}"),
                }
            }
        }
        CONTEXT_RESOURCE => {
            let (complete, next_req) = match rxs.get_mut(link_id) {
                Some(r) => {
                    let window_done = r.receive_part(&plaintext);
                    if r.is_complete() {
                        (true, None)
                    } else if window_done {
                        (false, r.next_request())
                    } else {
                        (false, None)
                    }
                }
                None => (false, None),
            };
            if let Some(req) = next_req {
                send_resource_req(writer, tp, link_id, &req, inbound);
            }
            if !complete {
                return;
            }
            let r = rxs.remove(link_id).unwrap();
            let stream = r.concat();
            let decrypted = if r.encrypted() {
                if inbound {
                    tp.decrypt_in_link(link_id, &stream)
                } else {
                    tp.decrypt_out_link(link_id, &stream)
                }
            } else {
                Some(stream)
            };
            let plain = match decrypted {
                Some(p) => p,
                None => {
                    println!("inbound resource: stream decrypt failed");
                    return;
                }
            };
            match r.finish(&plain) {
                Ok((payload, proof)) => {
                    let p = if inbound {
                        tp.make_in_link_resource_proof(link_id, &proof)
                    } else {
                        tp.make_out_link_resource_proof(link_id, &proof)
                    };
                    if let Some(p) = p {
                        writer.write_all(&frame(&p)).ok();
                        writer.flush().ok();
                    }
                    // The payload is a full packed LXMF (dest||source||sig||payload).
                    let src_id = if payload.len() >= 32 {
                        let mut h = [0u8; 16];
                        h.copy_from_slice(&payload[16..32]);
                        tp.known(&h).map(|k| k.identity.clone())
                    } else {
                        None
                    };
                    match message::parse(&payload, src_id.as_ref()) {
                        Ok(m) => {
                            let content = m.content_string();
                            let head: String = content.chars().take(60).collect();
                            println!(
                                ">>> RESOURCE LXMF ({} bytes, content {} chars) head={:?} sig_valid={}",
                                payload.len(),
                                content.chars().count(),
                                head,
                                m.signature_validated
                            );
                        }
                        Err(e) => println!("resource LXMF parse failed: {:?}", e),
                    }
                }
                Err(e) => println!("inbound resource finish failed: {e}"),
            }
        }
        _ => println!("inbound resource ctx=0x{context:02x} ignored"),
    }
}

/// Send a `RESOURCE_REQ` on a link: `inbound` selects the responder-side
/// (links a peer opened to us) vs initiator-side (links we opened) key table.
fn send_resource_req(writer: &mut TcpStream, tp: &Transport, link_id: &[u8; 16], req: &[u8], inbound: bool) {
    let mut iv = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut iv);
    let raw = if inbound {
        tp.make_in_link_context(link_id, CONTEXT_RESOURCE_REQ, req, &iv)
    } else {
        tp.make_out_link_context(link_id, CONTEXT_RESOURCE_REQ, req, &iv)
    };
    if let Some(raw) = raw {
        writer.write_all(&frame(&raw)).ok();
        writer.flush().ok();
    }
}

fn sync_response(writer: &mut TcpStream, tp: &Transport, phase: &mut u8, link_id: &[u8; 16], resp: Value) {
    if let Value::Int(code) = resp {
        println!("sync: node returned error code {code}");
        *phase = 0;
        return;
    }
    match *phase {
        1 => {
            let ids: Vec<Value> = resp.as_array().map(|a| a.to_vec()).unwrap_or_default();
            println!("sync: node lists {} message(s)", ids.len());
            if ids.is_empty() {
                *phase = 0;
                return;
            }
            sync_send_get(
                writer,
                tp,
                link_id,
                Value::Array(vec![Value::Array(ids), Value::Array(Vec::new()), Value::Int(1000)]),
            );
            *phase = 2;
        }
        2 => {
            let blobs: Vec<Value> = resp.as_array().map(|a| a.to_vec()).unwrap_or_default();
            let mut haves: Vec<Value> = Vec::new();
            let mut count = 0;
            for b in &blobs {
                if let Some(bin) = b.as_bin() {
                    sync_deliver(tp, bin);
                    haves.push(Value::Bin(full_hash(bin).to_vec()));
                    count += 1;
                }
            }
            println!("sync: downloaded {count} message(s)");
            if !haves.is_empty() {
                let hn = haves.len();
                sync_send_get(writer, tp, link_id, Value::Array(vec![Value::Nil, Value::Array(haves)]));
                println!("sync: sent delete-confirm for {hn} message(s)");
            }
            *phase = 0;
        }
        _ => {}
    }
}

fn sync_deliver(tp: &Transport, blob: &[u8]) {
    if blob.len() <= 16 {
        return;
    }
    match tp.identity().decrypt(&blob[16..], &[]) {
        Ok(plain) => {
            let mut full = blob[..16].to_vec();
            full.extend_from_slice(&plain);
            let src = if full.len() >= 32 {
                let mut h = [0u8; 16];
                h.copy_from_slice(&full[16..32]);
                tp.known(&h).map(|k| k.identity.clone())
            } else {
                None
            };
            match message::parse(&full, src.as_ref()) {
                Ok(m) => println!(
                    ">>> SYNCED MSG from {} | content={:?} | sig_valid={}",
                    reticulum_core::hex(&m.source_hash),
                    m.content_string(),
                    m.signature_validated
                ),
                Err(e) => println!("sync: synced message parse failed: {:?}", e),
            }
        }
        Err(e) => println!("sync: synced message decrypt failed: {e}"),
    }
}

/// Reply over an inbound link (the LXMF backchannel). False if the link isn't
/// identified yet — the caller retries on `LinkIdentified`.
fn send_backchannel_reply(
    writer: &mut TcpStream,
    tp: &mut Transport,
    link_id: &[u8; 16],
    peer: &[u8; 16],
    our_dh: &[u8; 16],
) -> bool {
    let reply = message::pack(
        tp.identity(),
        peer,
        our_dh,
        now() as f64,
        b"",
        b"backchannel reply from host-client",
        &Fields::new(),
        None,
    );
    let mut iv = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut iv);
    match tp.make_in_link_data(link_id, &reply.packed, &iv) {
        Some((raw, ph)) => {
            writer.write_all(&frame(&raw)).ok();
            writer.flush().ok();
            println!(
                "sent BACKCHANNEL reply on {} — awaiting proof {}",
                reticulum_core::hex(link_id),
                reticulum_core::hex(&ph)
            );
            true
        }
        None => false,
    }
}

fn send_message(
    writer: &mut TcpStream,
    tp: &Transport,
    target: &[u8; 16],
    our_dh: &[u8; 16],
    text: &str,
) {
    let known = tp.known(target).expect("target known").clone();
    let msg = message::pack(
        tp.identity(),
        target,
        our_dh,
        now() as f64,
        b"",
        text.as_bytes(),
        &Fields::new(),
        None,
    );
    let pkt = tp.make_opportunistic(
        target,
        &known.identity,
        known.ratchet.as_ref(),
        msg.opportunistic_plaintext(),
        &mut OsRng,
    );
    writer.write_all(&frame(&pkt)).expect("send lxmf");
    writer.flush().ok();
    println!("sent opportunistic LXMF to {} ({} bytes)", reticulum_core::hex(target), pkt.len());
}
