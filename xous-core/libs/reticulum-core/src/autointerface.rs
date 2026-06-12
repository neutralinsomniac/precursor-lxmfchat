//! Sans-IO derivations for RNS AutoInterface (`Interfaces/AutoInterface.py`);
//! the socket/peer-table side lives in the app.

use core::net::Ipv6Addr;

use crate::crypto::full_hash;

pub const DISCOVERY_TOKEN_LENGTH: usize = 32;

/// `ff12::` (temporary address type, link-local scope) with bytes 2..14 of
/// `SHA-256(group_id)` as the six low segments — the reference skips hash
/// bytes 0..2 and zeroes segment 1.
pub fn group_discovery_address(group_id: &[u8]) -> Ipv6Addr {
    let g = full_hash(group_id);
    let seg = |i: usize| ((g[i] as u16) << 8) | g[i + 1] as u16;
    Ipv6Addr::new(0xff12, 0, seg(2), seg(4), seg(6), seg(8), seg(10), seg(12))
}

/// `SHA-256(group_id ‖ addr-as-text)`. The address must be in its RFC 5952
/// canonical form (lowercase, compressed, no scope suffix) — what Python
/// hashes on the receiving side; Rust's `Display` produces the same.
pub fn discovery_token(group_id: &[u8], addr: &Ipv6Addr) -> [u8; DISCOVERY_TOKEN_LENGTH] {
    let mut data = group_id.to_vec();
    data.extend_from_slice(addr.to_string().as_bytes());
    full_hash(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected values computed with the .venv Python (hashlib.sha256 +
    // AutoInterface.__init__'s address arithmetic).

    #[test]
    fn group_address_matches_reference() {
        assert_eq!(
            group_discovery_address(b"reticulum"),
            "ff12:0:d70b:fb1c:16e4:5e39:485e:31e1".parse::<Ipv6Addr>().unwrap()
        );
    }

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
