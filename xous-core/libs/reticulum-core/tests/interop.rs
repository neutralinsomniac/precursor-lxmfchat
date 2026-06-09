//! Known-answer interop tests against the Python Reticulum reference (RNS 1.3.5).
//!
//! Vectors were produced by `reference/rnsref.py` from the fixed private key
//! `x25519 = 0x05*32`, `ed25519_seed = 0x06*32`. They lock our identity hashing,
//! public-key layout, destination hashing and Token/HKDF/ECDH decryption to the
//! reference byte-for-byte. The Rust->Python direction is checked by the
//! `scripts/interop.sh` harness.

use reticulum_core::announce::parse_and_validate;
use reticulum_core::constants::KEY_HALF;
use reticulum_core::destination::single_destination_hash;
use reticulum_core::identity::PrivateIdentity;
use reticulum_core::packet::Packet;

fn ref_identity() -> PrivateIdentity {
    PrivateIdentity::from_bytes(&[0x05u8; KEY_HALF], &[0x06u8; KEY_HALF])
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn identity_hash_matches_reference() {
    let id = ref_identity();
    assert_eq!(reticulum_core::hex(&id.hash()), "4c563203807ba6197bab00170ca9e69a");
}

#[test]
fn public_key_matches_reference() {
    let id = ref_identity();
    assert_eq!(
        reticulum_core::hex(&id.public().public_key()),
        "50a61409b1ddd0325e9b16b700e719e9772c07000b1bd7786e907c653d20495d\
         8a875fff1eb38451577acd5afee405456568dd7c89e090863a0557bc7af49f17"
    );
}

#[test]
fn lxmf_delivery_destination_hash_matches_reference() {
    let id = ref_identity();
    let dh = single_destination_hash("lxmf", &["delivery"], &id.hash());
    assert_eq!(reticulum_core::hex(&dh), "20f7e44b55b06cff39719106f2bd1fd2");
}

#[test]
fn decrypts_python_encrypted_token() {
    // `rnsref.py encrypt <prv> "hello reticulum"` (ephemeral key is random, so
    // this is a fixed captured sample).
    let token = unhex(
        "abd246f4eee9edfdbf99869f1f716c519c0ef91cd71926b0b5d0cd30c1e0a517\
         9fd4faeda58bc7199fbd3df0ec65a99d42e7e8ab6a8ba743fc7c1c9bab758393\
         461c46a13af7a3deb7adaabde14da5ae4b784db462c29433fd2ce0bc0feec296",
    );
    let id = ref_identity();
    let pt = id.decrypt(&token, &[]).expect("decrypt python token");
    assert_eq!(pt, b"Hello reticulum");
}

#[test]
fn validates_python_generated_announce() {
    // `rnsref.py announce <prv> "Ref"` for the lxmf.delivery destination (no ratchet).
    let raw = unhex(
        "010020f7e44b55b06cff39719106f2bd1fd20050a61409b1ddd0325e9b16b700e719e9\
         772c07000b1bd7786e907c653d20495d8a875fff1eb38451577acd5afee40545656\
         8dd7c89e090863a0557bc7af49f176ec60bc318e2c0f0d908926996744d006a239e\
         cf76d47df44504733c2211cb36cb0c059c2ef1bdedeef46b9b08d16928d2d7323d3\
         0a17b49faf16d86496d52d8e98b7f38af2f6fd82aa04537a978c8ff01933a0c526566",
    );
    let p = Packet::decode(&raw).unwrap();
    let parsed = parse_and_validate(&p).expect("python announce should validate");
    assert_eq!(reticulum_core::hex(&parsed.destination_hash), "20f7e44b55b06cff39719106f2bd1fd2");
    assert_eq!(parsed.app_data, b"Ref");
    assert!(parsed.ratchet.is_none());
}
