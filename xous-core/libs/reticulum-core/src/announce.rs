//! Announce construction and validation. Mirrors `RNS/Destination.py::announce`
//! and `RNS/Identity.py::validate_announce`.
//!
//! Announce packet DATA layout:
//! `public_key(64) || name_hash(10) || random_hash(10) || [ratchet(32)] || signature(64) || app_data`
//! The signature covers `destination_hash || public_key || name_hash || random_hash || ratchet || app_data`.
//! The packet's `context_flag` is set iff a ratchet is present.

use crate::constants::*;
use crate::crypto::full_hash;
use crate::destination::single_destination_hash;
use crate::identity::{PrivateIdentity, PublicIdentity};
use crate::packet::Packet;

/// A validated inbound announce.
pub struct ParsedAnnounce {
    pub destination_hash: [u8; TRUNCATED_HASHLENGTH],
    pub identity: PublicIdentity,
    pub name_hash: [u8; NAME_HASH_LENGTH],
    pub ratchet: Option<[u8; RATCHET_SIZE]>,
    pub app_data: Vec<u8>,
}

/// Build the 10-byte announce `random_hash` (`5 random bytes || 5-byte big-endian unix time`).
pub fn random_hash(random5: &[u8; 5], unix_time: u64) -> [u8; 10] {
    let mut rh = [0u8; 10];
    rh[..5].copy_from_slice(random5);
    rh[5..].copy_from_slice(&unix_time.to_be_bytes()[3..8]); // low 5 bytes, big-endian
    rh
}

/// Build an ANNOUNCE packet for a SINGLE destination owned by `identity`.
pub fn build_announce(
    identity: &PrivateIdentity,
    app_name: &str,
    aspects: &[&str],
    app_data: &[u8],
    random_hash: &[u8; 10],
    ratchet_pub: Option<&[u8; RATCHET_SIZE]>,
) -> Packet {
    let dest_hash = single_destination_hash(app_name, aspects, &identity.hash());
    let name_hash = crate::destination::name_hash(app_name, aspects);
    let public_key = identity.public().public_key();
    let ratchet = ratchet_pub.map(|r| r.as_slice()).unwrap_or(&[]);

    let mut signed = Vec::new();
    signed.extend_from_slice(&dest_hash);
    signed.extend_from_slice(&public_key);
    signed.extend_from_slice(&name_hash);
    signed.extend_from_slice(random_hash);
    signed.extend_from_slice(ratchet);
    signed.extend_from_slice(app_data);
    let signature = identity.sign(&signed);

    let mut data = Vec::new();
    data.extend_from_slice(&public_key);
    data.extend_from_slice(&name_hash);
    data.extend_from_slice(random_hash);
    data.extend_from_slice(ratchet);
    data.extend_from_slice(&signature);
    data.extend_from_slice(app_data);

    let mut p = Packet::header1(DEST_SINGLE, PACKET_ANNOUNCE, CONTEXT_NONE, dest_hash, data);
    p.context_flag = ratchet_pub.is_some();
    p
}

/// Parse and cryptographically validate an inbound ANNOUNCE packet.
/// Returns `None` if the packet is malformed, the signature is invalid, or the
/// destination hash does not match `truncated_hash(name_hash || identity_hash)`.
pub fn parse_and_validate(packet: &Packet) -> Option<ParsedAnnounce> {
    // Accept both HEADER_1 (direct from origin) and HEADER_2 (retransmitted by a
    // transport node, which prepends a transport_id). `decode` extracts the
    // destination hash correctly for either, and validation only uses that.
    if packet.packet_type != PACKET_ANNOUNCE {
        return None;
    }
    let data = &packet.data;
    let min = KEYSIZE + NAME_HASH_LENGTH + 10 + SIG_LENGTH;
    if data.len() < min {
        return None;
    }

    let public_key = &data[..KEYSIZE];
    let name_hash_slice = &data[KEYSIZE..KEYSIZE + NAME_HASH_LENGTH];
    let rh_off = KEYSIZE + NAME_HASH_LENGTH;
    let random_hash = &data[rh_off..rh_off + 10];

    let (ratchet, sig_off) = if packet.context_flag {
        if data.len() < min + RATCHET_SIZE {
            return None;
        }
        let r_off = rh_off + 10;
        let mut r = [0u8; RATCHET_SIZE];
        r.copy_from_slice(&data[r_off..r_off + RATCHET_SIZE]);
        (Some(r), r_off + RATCHET_SIZE)
    } else {
        (None, rh_off + 10)
    };

    let signature = &data[sig_off..sig_off + SIG_LENGTH];
    let app_data = data[sig_off + SIG_LENGTH..].to_vec();

    let ratchet_slice = ratchet.as_ref().map(|r| r.as_slice()).unwrap_or(&[]);
    let mut signed = Vec::new();
    signed.extend_from_slice(&packet.destination_hash);
    signed.extend_from_slice(public_key);
    signed.extend_from_slice(name_hash_slice);
    signed.extend_from_slice(random_hash);
    signed.extend_from_slice(ratchet_slice);
    signed.extend_from_slice(&app_data);

    let identity = PublicIdentity::from_public_key(public_key).ok()?;
    if !identity.validate(signature, &signed) {
        return None;
    }

    // Bind the destination hash to the announced identity: it must equal
    // truncated_hash(name_hash || identity_hash).
    let mut hash_material = Vec::with_capacity(NAME_HASH_LENGTH + TRUNCATED_HASHLENGTH);
    hash_material.extend_from_slice(name_hash_slice);
    hash_material.extend_from_slice(&identity.hash);
    let expected = &full_hash(&hash_material)[..TRUNCATED_HASHLENGTH];
    if expected != packet.destination_hash {
        return None;
    }

    let mut name_hash = [0u8; NAME_HASH_LENGTH];
    name_hash.copy_from_slice(name_hash_slice);
    Some(ParsedAnnounce { destination_hash: packet.destination_hash, identity, name_hash, ratchet, app_data })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_validate_roundtrip() {
        let id = PrivateIdentity::from_bytes(&[0x05; KEY_HALF], &[0x06; KEY_HALF]);
        let rh = random_hash(&[1, 2, 3, 4, 5], 1_700_000_000);
        let p = build_announce(&id, "lxmf", &["delivery"], b"NodeName", &rh, None);
        assert_eq!(p.packet_type, PACKET_ANNOUNCE);
        assert!(!p.context_flag);

        // round-trip through the wire codec then validate
        let raw = p.encode();
        let decoded = Packet::decode(&raw).unwrap();
        let parsed = parse_and_validate(&decoded).expect("valid announce");
        assert_eq!(parsed.identity.hash, id.hash());
        assert_eq!(parsed.app_data, b"NodeName");
        assert_eq!(
            parsed.destination_hash,
            single_destination_hash("lxmf", &["delivery"], &id.hash())
        );
    }

    #[test]
    fn tampered_announce_rejected() {
        let id = PrivateIdentity::from_bytes(&[0x09; KEY_HALF], &[0x0a; KEY_HALF]);
        let rh = random_hash(&[9; 5], 1_700_000_001);
        let mut p = build_announce(&id, "lxmf", &["delivery"], b"", &rh, None);
        let last = p.data.len() - 1;
        p.data[last] ^= 0xff; // corrupt the signature
        assert!(parse_and_validate(&p).is_none());
    }
}
