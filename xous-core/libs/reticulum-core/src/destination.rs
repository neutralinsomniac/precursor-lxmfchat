//! Reticulum destination naming and hashing. Mirrors `RNS/Destination.py`.
//!
//! A destination is named by an `app_name` plus zero or more `aspects`, joined
//! with `.` (e.g. `lxmf.delivery`). For `single` destinations the owning
//! identity is folded into the hash so the address is bound to a keypair.

use crate::constants::{NAME_HASH_LENGTH, TRUNCATED_HASHLENGTH};
use crate::crypto::full_hash;

/// `expand_name`: join app_name and aspects with '.'.
pub fn expand_name(app_name: &str, aspects: &[&str]) -> String {
    let mut s = String::from(app_name);
    for a in aspects {
        s.push('.');
        s.push_str(a);
    }
    s
}

/// `full_name_hash`: first `NAME_HASH_LENGTH` (10) bytes of SHA-256 of the expanded name.
pub fn name_hash(app_name: &str, aspects: &[&str]) -> [u8; NAME_HASH_LENGTH] {
    let full = full_hash(expand_name(app_name, aspects).as_bytes());
    let mut out = [0u8; NAME_HASH_LENGTH];
    out.copy_from_slice(&full[..NAME_HASH_LENGTH]);
    out
}

/// Destination hash for a `single` destination owned by `identity_hash`
/// (`truncated_hash(name_hash || identity_hash)`).
pub fn single_destination_hash(
    app_name: &str,
    aspects: &[&str],
    identity_hash: &[u8; TRUNCATED_HASHLENGTH],
) -> [u8; TRUNCATED_HASHLENGTH] {
    let nh = name_hash(app_name, aspects);
    let mut material = Vec::with_capacity(NAME_HASH_LENGTH + TRUNCATED_HASHLENGTH);
    material.extend_from_slice(&nh);
    material.extend_from_slice(identity_hash);
    let full = full_hash(&material);
    let mut out = [0u8; TRUNCATED_HASHLENGTH];
    out.copy_from_slice(&full[..TRUNCATED_HASHLENGTH]);
    out
}

/// Destination hash for a `plain` destination (no owning identity):
/// `truncated_hash(name_hash)`. Used for control destinations like the
/// transport path-request endpoint (`rnstransport.path.request`).
pub fn plain_destination_hash(app_name: &str, aspects: &[&str]) -> [u8; TRUNCATED_HASHLENGTH] {
    let nh = name_hash(app_name, aspects);
    let full = full_hash(&nh);
    let mut out = [0u8; TRUNCATED_HASHLENGTH];
    out.copy_from_slice(&full[..TRUNCATED_HASHLENGTH]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_hash_is_10_bytes_and_stable() {
        let a = name_hash("lxmf", &["delivery"]);
        let b = name_hash("lxmf", &["delivery"]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 10);
        assert_ne!(name_hash("lxmf", &["delivery"]), name_hash("lxmf", &["propagation"]));
    }

    #[test]
    fn destination_hash_is_16_bytes() {
        let h = single_destination_hash("lxmf", &["delivery"], &[0xABu8; TRUNCATED_HASHLENGTH]);
        assert_eq!(h.len(), 16);
    }
}
