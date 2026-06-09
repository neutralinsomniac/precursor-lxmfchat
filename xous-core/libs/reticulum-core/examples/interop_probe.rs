//! Host-side interop probe used by `scripts/interop.sh` to cross-check the
//! Rust implementation against the Python Reticulum reference.
//!
//!   interop_probe emit-announce            -> prints a Rust-built announce (hex)
//!   interop_probe validate-announce <hex>  -> validates an announce, prints summary
//!
//! Uses the fixed reference identity (x25519=0x05*32, ed25519=0x06*32).

use reticulum_core::announce::{build_announce, parse_and_validate, random_hash};
use reticulum_core::constants::{CONTEXT_NONE, DEST_SINGLE, KEY_HALF, PACKET_LINKREQUEST};
use reticulum_core::destination::single_destination_hash;
use reticulum_core::identity::PrivateIdentity;
use reticulum_core::packet::Packet;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn ref_identity() -> PrivateIdentity {
    PrivateIdentity::from_bytes(&[0x05u8; KEY_HALF], &[0x06u8; KEY_HALF])
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("emit-announce") => {
            let id = ref_identity();
            let rh = random_hash(&[1, 2, 3, 4, 5], 1_700_000_000);
            let p = build_announce(&id, "lxmf", &["delivery"], b"RustNode", &rh, None);
            println!("{}", reticulum_core::hex(&p.encode()));
        }
        Some("validate-announce") => {
            let raw = unhex(&args[2]);
            let p = Packet::decode(&raw).expect("decode packet");
            match parse_and_validate(&p) {
                Some(a) => {
                    println!(
                        "VALID dest={} appdata={} ratchet={}",
                        reticulum_core::hex(&a.destination_hash),
                        reticulum_core::hex(&a.app_data),
                        a.ratchet.is_some()
                    );
                }
                None => {
                    eprintln!("INVALID");
                    std::process::exit(2);
                }
            }
        }
        Some("link-proof") => {
            // Build a link request from a fake initiator to our reference
            // destination, accept it, and print request/link_id/proof so the
            // Python RNS initiator logic can validate the proof.
            let me = ref_identity();
            let our_dh = single_destination_hash("lxmf", &["delivery"], &me.hash());
            let initiator = PrivateIdentity::from_bytes(&[0x11; KEY_HALF], &[0x12; KEY_HALF]);
            // LKi = initiator X25519 pub (32) || Ed25519 pub (32)
            let lki = initiator.public().public_key().to_vec();
            let request = Packet::header1(DEST_SINGLE, PACKET_LINKREQUEST, CONTEXT_NONE, our_dh, lki);
            let est = reticulum_core::link::accept_request(&request, &me, &[0x33; KEY_HALF])
                .expect("accept link request");
            println!("our_pubkey {}", reticulum_core::hex(&me.public().public_key()));
            println!("request {}", reticulum_core::hex(&request.encode()));
            println!("link_id {}", reticulum_core::hex(&est.link_id));
            println!("proof {}", reticulum_core::hex(&est.proof_packet));
        }
        other => {
            eprintln!("unknown subcommand: {:?}", other);
            std::process::exit(64);
        }
    }
}
