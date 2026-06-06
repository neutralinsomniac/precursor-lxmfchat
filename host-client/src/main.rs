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
//!
//! The identity is fixed (x25519=0x05*32, ed25519=0x06*32) so its address is
//! stable across runs; pass RUST_LOG=info for detail.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lxmf::message::{self, Fields};
use rand_core::OsRng;
use reticulum_core::constants::KEY_HALF;
use reticulum_core::destination::single_destination_hash;
use reticulum_core::hdlc::{Deframer, frame};
use reticulum_core::identity::PrivateIdentity;
use reticulum_core::transport::{Event, Transport};

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
    let listen_secs: u64 = match mode {
        "listen" => args.get(3).and_then(|s| s.parse().ok()).unwrap_or(30),
        _ if is_send => args.get(5).and_then(|s| s.parse().ok()).unwrap_or(30),
        _ => 30,
    };

    let target: Option<[u8; 16]> = if is_send {
        let v = unhex(&args[3]);
        let mut h = [0u8; 16];
        h.copy_from_slice(&v);
        Some(h)
    } else {
        None
    };
    let text = if is_send { args[4].clone() } else { String::new() };
    let mut sent = false;

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
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(raw) => {
                let mut gen = || {
                    let mut b = [0u8; 32];
                    rand_core::RngCore::fill_bytes(&mut OsRng, &mut b);
                    b
                };
                match tp.handle_frame(&raw, &mut gen) {
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
                                if mode == "send-direct" {
                                    // Initiate a link; we deliver once it's up.
                                    let known = tp.known(&t).expect("target known").clone();
                                    let mut ex = [0u8; 32];
                                    let mut ed = [0u8; 32];
                                    rand_core::RngCore::fill_bytes(&mut OsRng, &mut ex);
                                    rand_core::RngCore::fill_bytes(&mut OsRng, &mut ed);
                                    let (req, lid) = tp.make_link_request(&t, &known.identity, &ex, &ed);
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
                        let msg = message::pack(
                            tp.identity(), &lt, &our_dh, now() as f64, b"", text.as_bytes(), &Fields::new(), None,
                        );
                        let mut iv = [0u8; 16];
                        rand_core::RngCore::fill_bytes(&mut OsRng, &mut iv);
                        if let Some((raw, ph)) = tp.make_link_data(&link_id, &msg.packed, &iv) {
                            writer.write_all(&frame(&raw)).ok();
                            writer.flush().ok();
                            println!("sent direct LXMF over link ({} bytes), awaiting proof {}", raw.len(), reticulum_core::hex(&ph));
                        }
                    }
                    Event::Delivered { packet_hash } => {
                        println!(">>> DELIVERED (proof matched {})", reticulum_core::hex(&packet_hash));
                    }
                    Event::Data { destination_hash, plaintext } => {
                        // Opportunistic LXMF: prepend our dest hash, parse.
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
