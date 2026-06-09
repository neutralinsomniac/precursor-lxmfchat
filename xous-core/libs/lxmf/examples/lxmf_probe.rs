//! Host-side LXMF interop probe (used by scripts/interop.sh).
//!
//!   lxmf_probe pack  <src_prv_hex> <dst_prv_hex> <title> <content>
//!   lxmf_probe parse <packed_hex> <src_pub_hex>

use lxmf::message::{Fields, pack, parse};
use reticulum_core::constants::KEY_HALF;
use reticulum_core::destination::single_destination_hash;
use reticulum_core::identity::{PrivateIdentity, PublicIdentity};

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn id_from_prv(hex: &str) -> PrivateIdentity {
    let b = unhex(hex);
    let mut x = [0u8; KEY_HALF];
    let mut e = [0u8; KEY_HALF];
    x.copy_from_slice(&b[..KEY_HALF]);
    e.copy_from_slice(&b[KEY_HALF..2 * KEY_HALF]);
    PrivateIdentity::from_bytes(&x, &e)
}

fn delivery_hash(id: &PrivateIdentity) -> [u8; 16] {
    single_destination_hash("lxmf", &["delivery"], &id.hash())
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a[1].as_str() {
        "pack" => {
            let src = id_from_prv(&a[2]);
            let dst = id_from_prv(&a[3]);
            let dh = delivery_hash(&dst);
            let sh = delivery_hash(&src);
            let msg = pack(&src, &dh, &sh, 1_700_000_000.0, a[4].as_bytes(), a[5].as_bytes(), &Fields::new(), None);
            println!("packed {}", reticulum_core::hex(&msg.packed));
            println!("hash {}", reticulum_core::hex(&msg.message_id));
        }
        "parse" => {
            let packed = unhex(&a[2]);
            let src_pub = PublicIdentity::from_public_key(&unhex(&a[3])).expect("src pub");
            let m = parse(&packed, Some(&src_pub)).expect("parse");
            println!("title {}", m.title_string());
            println!("content {}", m.content_string());
            println!("valid {}", m.signature_validated);
        }
        "stamp" => {
            // stamp <material_hex> <cost>  -> generate a propagation stamp.
            let material = unhex(&a[2]);
            let cost: u32 = a[3].parse().expect("cost");
            let stamp = lxmf::stamp::generate_stamp(&material, cost);
            println!("material {}", reticulum_core::hex(&material));
            println!("cost {}", cost);
            println!("stamp {}", reticulum_core::hex(&stamp));
        }
        other => {
            eprintln!("unknown: {}", other);
            std::process::exit(64);
        }
    }
}
