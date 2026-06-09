//! `reticulum-core`: a sans-IO subset of the Reticulum Network Stack (RNS),
//! sufficient to build an LXMF client that connects to a Reticulum transport
//! hub over a single `TCPClientInterface`.
//!
//! The crate performs **no I/O** and has **no Xous dependencies**: randomness,
//! time, persistence and the transport socket are all injected by the caller.
//! This keeps it unit- and interop-testable with plain `cargo test` on the
//! host, and lets the Xous app and a host test client share the exact same code.
//!
//! Layers:
//! - [`constants`] / [`crypto`] — wire constants and the Token/HKDF primitives.
//! - [`identity`] — X25519 + Ed25519 keypair, encrypt/decrypt, sign/validate.
//! - [`destination`] — destination naming + hashing.
//! - [`packet`] — packet header codec.
//! - [`hdlc`] — TCP-interface framing.

pub mod announce;
pub mod constants;
pub mod crypto;
pub mod destination;
pub mod hdlc;
pub mod identity;
pub mod link;
pub mod packet;
pub mod resource;
pub mod transport;
pub mod x25519;

pub use identity::{PrivateIdentity, PublicIdentity};
pub use packet::{HeaderType, Packet};

/// Hex helper for logging hashes/addresses.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Cryptographic known-answer self-test, returning a short human-readable summary.
///
/// On the Precursor the curve25519/sha2 backends are hardware-accelerated forks,
/// whereas a host build uses software. Link- and opportunistic-message keys are
/// derived from `HKDF(SHA256, salt, X25519_ECDH(...))`, so if any of those
/// primitives behaves differently on-device, every such key is wrong and data
/// packets fail HMAC verification — even though announces (Ed25519/SHA only)
/// still work. This runs the exact code paths (`StaticSecret::diffie_hellman`,
/// `Token`, `hkdf`) against fixed vectors so a discrepancy is obvious on-device.
pub fn self_test() -> String {
    use crypto::{Token, hkdf};

    fn unhex32(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        o
    }

    let mut out = String::new();

    // X25519 via our software path (now used for all ECDH), RFC 7748 §5.2 vector.
    let k = unhex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u = unhex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let exp = unhex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    let got = x25519::x25519(&k, &u);
    if got == exp {
        out.push_str("x25519:OK ");
    } else {
        out.push_str(&format!("x25519:FAIL({}) ", &hex(&got)[..12]));
    }

    // Token (AES-256-CBC + HMAC-SHA256) round-trip with a fixed key/IV.
    let tok = Token::new(&[7u8; 64]).unwrap();
    let ct = tok.encrypt_with_iv(b"selftest-vector!", &[3u8; constants::IV_LENGTH]);
    match tok.decrypt(&ct) {
        Ok(p) if p == b"selftest-vector!" => out.push_str("token:OK "),
        _ => out.push_str("token:FAIL "),
    }

    // HKDF-SHA256: show a prefix so a device-vs-host discrepancy is visible.
    let kk = hkdf(32, b"ikm-test", Some(b"salt-test"), None);
    out.push_str(&format!("hkdf:{}", &hex(&kk)[..12]));

    out
}

#[cfg(test)]
mod selftest_tests {
    #[test]
    fn print_self_test() {
        println!("SELFTEST: {}", super::self_test());
    }
}
