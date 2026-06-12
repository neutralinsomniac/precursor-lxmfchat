//! The sans-IO pieces of RNS AutoInterface (zero-conf link-local peering):
//! the discovery multicast-group address and the peering token. The I/O side
//! (sockets, peer table, timers) lives in the app; these derivations are here
//! so they're host-testable against the Python reference.
//!
//! Reference: RNS `Interfaces/AutoInterface.py`.

use core::net::Ipv6Addr;

use crate::crypto::full_hash;

/// Discovery token length (a full SHA-256).
pub const DISCOVERY_TOKEN_LENGTH: usize = 32;

/// The multicast discovery address for a group: `ff12::` (temporary address
/// type, link-local scope) with bytes 2..14 of `SHA-256(group_id)` as the six
/// low segments — the reference's `mcast_discovery_address` arithmetic skips
/// hash bytes 0..2 and zeroes segment 1.
pub fn group_discovery_address(group_id: &[u8]) -> Ipv6Addr {
    let g = full_hash(group_id);
    let seg = |i: usize| ((g[i] as u16) << 8) | g[i + 1] as u16;
    Ipv6Addr::new(0xff12, 0, seg(2), seg(4), seg(6), seg(8), seg(10), seg(12))
}

/// The discovery token the owner of `addr` announces:
/// `SHA-256(group_id ‖ addr-as-text)`. Receivers recompute it from the
/// datagram's source address, proving group membership (not identity — there
/// is none at this layer). The address is hashed in its RFC 5952 canonical
/// text form (lowercase, compressed, no scope suffix) — what both Rust's and
/// Python's formatters produce.
pub fn discovery_token(group_id: &[u8], addr: &Ipv6Addr) -> [u8; DISCOVERY_TOKEN_LENGTH] {
    let mut data = group_id.to_vec();
    data.extend_from_slice(addr.to_string().as_bytes());
    full_hash(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: the Python reference's derivation for the default "reticulum"
    /// group — `.venv` python3:
    /// `g = hashlib.sha256(b"reticulum").digest()` then the
    /// `AutoInterface.__init__` segment arithmetic.
    #[test]
    fn group_address_matches_reference() {
        assert_eq!(
            group_discovery_address(b"reticulum"),
            "ff12:0:d70b:fb1c:16e4:5e39:485e:31e1".parse::<Ipv6Addr>().unwrap()
        );
    }

    /// Oracle: `hashlib.sha256(b"reticulum" + b"fe80::5054:ff:fe12:3456")` —
    /// the token a Python peer expects from a sender at that address. Also
    /// pins Rust's address formatting to the RFC 5952 form Python hashes.
    #[test]
    fn discovery_token_matches_reference() {
        let addr: Ipv6Addr = "fe80::5054:ff:fe12:3456".parse().unwrap();
        assert_eq!(addr.to_string(), "fe80::5054:ff:fe12:3456");
        assert_eq!(
            crate::hex(&discovery_token(b"reticulum", &addr)),
            "4483cd4af544deff80c6886006d361db453ef067316c40701502ae26e748f1fa"
        );
    }
}
