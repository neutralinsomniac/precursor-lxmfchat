//! LXMF message packing, signing and verification. Mirrors `LXMF/LXMessage.py`.
//!
//! Wire `packed` layout (plaintext):
//! `destination_hash(16) || source_hash(16) || signature(64) || packed_payload`
//! where `packed_payload = msgpack([timestamp f64, title bin, content bin, fields map])`.
//!
//! - `message_id = SHA-256(destination_hash || source_hash || packed_payload)`
//! - `signature  = Ed25519_sign(source, hashed_part || message_id)`
//!
//! For OPPORTUNISTIC delivery the leading `destination_hash` is dropped (it is
//! carried in the RNS packet header) and the remainder is encrypted to the
//! recipient's identity. DIRECT (link) and PROPAGATED delivery send the full
//! `packed` (encrypted by the link / propagation-node path).

use std::collections::BTreeMap;

use reticulum_core::constants::{IV_LENGTH, KEY_HALF, RATCHET_SIZE, SIG_LENGTH, TRUNCATED_HASHLENGTH};
use reticulum_core::crypto::{full_hash, truncated_hash};
use reticulum_core::identity::{PrivateIdentity, PublicIdentity};

use crate::msgpack::{self, Value};

pub const DEST_LEN: usize = TRUNCATED_HASHLENGTH; // 16

/// LXMF stamp/ticket length: `TRUNCATED_HASHLENGTH/8` bytes (== 16 here, since
/// our `TRUNCATED_HASHLENGTH` is already in bytes). Mirrors
/// `LXMessage.TICKET_LENGTH`.
pub const TICKET_LENGTH: usize = TRUNCATED_HASHLENGTH;

/// LXMF field key for a delivered ticket: `[expiry_unix_seconds, ticket_bytes]`.
/// A recipient with a stamp cost trusts certain senders by handing them a
/// ticket; the sender then stamps each message with
/// `truncated_hash(ticket || message_id)` instead of computing a proof-of-work
/// stamp. Mirrors `LXMF.FIELD_TICKET`.
pub const FIELD_TICKET: i64 = 0x0C;

/// Optional structured fields (LXMF FIELD_* keys -> values).
pub type Fields = BTreeMap<i64, Value>;

/// A ticket extracted from an inbound message's `FIELD_TICKET`.
pub struct InboundTicket {
    /// Unix seconds after which this ticket is no longer valid.
    pub expires: u64,
    pub ticket: [u8; TICKET_LENGTH],
}

/// Pull a `FIELD_TICKET` (`[expiry, ticket]`) out of a parsed message's fields,
/// if present and well-formed. The caller should only trust it from a
/// signature-validated message (mirrors `LXMRouter.lxmf_delivery`).
pub fn extract_ticket(fields: &Fields) -> Option<InboundTicket> {
    let arr = fields.get(&FIELD_TICKET)?.as_array()?;
    if arr.len() < 2 {
        return None;
    }
    let expires = arr[0].as_f64()?;
    if !(expires.is_finite() && expires > 0.0) {
        return None;
    }
    let tb = arr[1].as_bin()?;
    if tb.len() != TICKET_LENGTH {
        return None;
    }
    let mut ticket = [0u8; TICKET_LENGTH];
    ticket.copy_from_slice(tb);
    Some(InboundTicket { expires: expires as u64, ticket })
}

/// A fully packed outbound message.
pub struct PackedMessage {
    /// 32-byte LXMF message id (SHA-256 of dest||source||payload).
    pub message_id: [u8; 32],
    /// `dest(16) || source(16) || signature(64) || packed_payload`.
    pub packed: Vec<u8>,
}

impl PackedMessage {
    /// The bytes encrypted for OPPORTUNISTIC delivery: everything after the
    /// (redundant) leading destination hash.
    pub fn opportunistic_plaintext(&self) -> &[u8] {
        &self.packed[DEST_LEN..]
    }
}

fn pack_payload(timestamp: f64, title: &[u8], content: &[u8], fields: &Fields) -> Vec<u8> {
    let payload = Value::Array(vec![
        Value::F64(timestamp),
        Value::Bin(title.to_vec()),
        Value::Bin(content.to_vec()),
        Value::Map(fields.clone()),
    ]);
    msgpack::encode(&payload)
}

/// Pack and sign a message. `source` is our identity; `destination_hash` and
/// `source_hash` are the recipient's and our `lxmf.delivery` destination hashes.
///
/// `outbound_ticket`, when present, is a ticket the recipient previously handed
/// us (see [`extract_ticket`]). It lets us satisfy the recipient's stamp cost
/// without proof-of-work: we append a stamp `truncated_hash(ticket ||
/// message_id)` as a 5th payload element. The message id and signature still
/// cover only the 4-tuple `[timestamp, title, content, fields]` — the recipient
/// strips the stamp before verifying (see [`parse`]).
pub fn pack(
    source: &PrivateIdentity,
    destination_hash: &[u8; DEST_LEN],
    source_hash: &[u8; DEST_LEN],
    timestamp: f64,
    title: &[u8],
    content: &[u8],
    fields: &Fields,
    outbound_ticket: Option<&[u8; TICKET_LENGTH]>,
) -> PackedMessage {
    let packed_payload = pack_payload(timestamp, title, content, fields);

    let mut hashed_part = Vec::with_capacity(2 * DEST_LEN + packed_payload.len());
    hashed_part.extend_from_slice(destination_hash);
    hashed_part.extend_from_slice(source_hash);
    hashed_part.extend_from_slice(&packed_payload);

    let message_id = full_hash(&hashed_part);

    let mut signed_part = hashed_part.clone();
    signed_part.extend_from_slice(&message_id);
    let signature = source.sign(&signed_part);

    // The bytes that actually go on the wire. With a ticket, re-pack the payload
    // as a 5-tuple with the stamp appended; the signature above is unaffected.
    let wire_payload = match outbound_ticket {
        Some(ticket) => {
            let mut stamp_input = Vec::with_capacity(TICKET_LENGTH + message_id.len());
            stamp_input.extend_from_slice(ticket);
            stamp_input.extend_from_slice(&message_id);
            let stamp = truncated_hash(&stamp_input);
            let payload = Value::Array(vec![
                Value::F64(timestamp),
                Value::Bin(title.to_vec()),
                Value::Bin(content.to_vec()),
                Value::Map(fields.clone()),
                Value::Bin(stamp.to_vec()),
            ]);
            msgpack::encode(&payload)
        }
        None => packed_payload,
    };

    let mut packed = Vec::with_capacity(2 * DEST_LEN + SIG_LENGTH + wire_payload.len());
    packed.extend_from_slice(destination_hash);
    packed.extend_from_slice(source_hash);
    packed.extend_from_slice(&signature);
    packed.extend_from_slice(&wire_payload);

    PackedMessage { message_id, packed }
}

/// Pack a message for **propagated** (store-and-forward) delivery to a propagation
/// node. The node only stores the blob — it stays end-to-end encrypted to the
/// recipient — so we encrypt exactly as for opportunistic delivery and wrap it in
/// the propagation transfer envelope. Mirrors `LXMessage.pack` (PROPAGATED branch,
/// `reference/LXMF/LXMessage.py:426-441`):
///
/// `lxmf_data = recipient_dest_hash(16) || Identity.encrypt(source||sig||payload)`
/// `propagation_packed = msgpack([transfer_timestamp, [ lxmf_data ]])`
///
/// `plaintext` is the message's `opportunistic_plaintext()` (i.e. everything after
/// the leading destination hash). `eph`/`iv` are fresh random bytes (TRNG on
/// device). We do not attach a propagation stamp (PN must accept cost 0).
/// `propagation_cost` is the proof-of-work cost (leading zero bits) the node
/// requires. When > 0 we append a propagation stamp `truncated to STAMP_SIZE`
/// over the message's transient id (`full_hash(lxmf_data)`) — a node rejects the
/// whole transfer otherwise (`LXMRouter.propagation_packet`). This is a few
/// seconds of work; pass 0 only for a node with no stamp requirement.
pub fn pack_propagation(
    recipient: &PublicIdentity,
    recipient_dest_hash: &[u8; DEST_LEN],
    plaintext: &[u8],
    ratchet: Option<&[u8; RATCHET_SIZE]>,
    eph: &[u8; KEY_HALF],
    iv: &[u8; IV_LENGTH],
    transfer_timestamp: f64,
    propagation_cost: u32,
) -> Vec<u8> {
    let pn_encrypted = recipient.encrypt(plaintext, eph, iv, ratchet);
    let mut lxmf_data = Vec::with_capacity(DEST_LEN + pn_encrypted.len());
    lxmf_data.extend_from_slice(recipient_dest_hash);
    lxmf_data.extend_from_slice(&pn_encrypted);

    if propagation_cost > 0 {
        // Stamp covers the transient id (hash of lxmf_data *before* the stamp);
        // the stamp bytes are appended after it.
        let transient_id = full_hash(&lxmf_data);
        let stamp = crate::stamp::generate_stamp(&transient_id, propagation_cost);
        lxmf_data.extend_from_slice(&stamp);
    }

    let envelope = Value::Array(vec![
        Value::F64(transfer_timestamp),
        Value::Array(vec![Value::Bin(lxmf_data)]),
    ]);
    msgpack::encode(&envelope)
}

/// A parsed inbound message.
pub struct ParsedMessage {
    pub message_id: [u8; 32],
    pub destination_hash: [u8; DEST_LEN],
    pub source_hash: [u8; DEST_LEN],
    pub timestamp: f64,
    pub title: Vec<u8>,
    pub content: Vec<u8>,
    pub fields: Fields,
    /// True iff the Ed25519 signature verified against the supplied source identity.
    pub signature_validated: bool,
}

impl ParsedMessage {
    pub fn title_string(&self) -> String { String::from_utf8_lossy(&self.title).into_owned() }
    pub fn content_string(&self) -> String { String::from_utf8_lossy(&self.content).into_owned() }
}

#[derive(Debug)]
pub enum ParseError {
    TooShort,
    BadPayload,
}

/// Parse a full `lxmf_bytes` blob (`dest || source || sig || payload`). For
/// OPPORTUNISTIC packets, prepend the destination hash to the decrypted
/// plaintext before calling this. `source_identity`, when provided, is used to
/// verify the signature (resolved from a prior announce by `source_hash`).
pub fn parse(
    lxmf_bytes: &[u8],
    source_identity: Option<&PublicIdentity>,
) -> Result<ParsedMessage, ParseError> {
    let header = 2 * DEST_LEN + SIG_LENGTH;
    if lxmf_bytes.len() < header {
        return Err(ParseError::TooShort);
    }
    let mut destination_hash = [0u8; DEST_LEN];
    let mut source_hash = [0u8; DEST_LEN];
    destination_hash.copy_from_slice(&lxmf_bytes[..DEST_LEN]);
    source_hash.copy_from_slice(&lxmf_bytes[DEST_LEN..2 * DEST_LEN]);
    let signature = &lxmf_bytes[2 * DEST_LEN..header];
    let mut packed_payload = lxmf_bytes[header..].to_vec();

    let mut unpacked = msgpack::decode(&packed_payload).map_err(|_| ParseError::BadPayload)?;
    let arr = match &mut unpacked {
        Value::Array(a) if a.len() >= 4 => a,
        _ => return Err(ParseError::BadPayload),
    };

    // If a stamp (5th element) is present, strip it and re-pack the 4-tuple so
    // the hash/signature cover only [timestamp,title,content,fields].
    if arr.len() > 4 {
        arr.truncate(4);
        packed_payload = msgpack::encode(&Value::Array(arr.clone()));
    }

    let timestamp = arr[0].as_f64().ok_or(ParseError::BadPayload)?;
    let title = arr[1].as_bin().unwrap_or(&[]).to_vec();
    let content = arr[2].as_bin().unwrap_or(&[]).to_vec();
    let fields = match &arr[3] {
        Value::Map(m) => m.clone(),
        _ => Fields::new(),
    };

    let mut hashed_part = Vec::with_capacity(2 * DEST_LEN + packed_payload.len());
    hashed_part.extend_from_slice(&destination_hash);
    hashed_part.extend_from_slice(&source_hash);
    hashed_part.extend_from_slice(&packed_payload);
    let message_id = full_hash(&hashed_part);

    let mut signed_part = hashed_part;
    signed_part.extend_from_slice(&message_id);
    let signature_validated =
        source_identity.map(|id| id.validate(signature, &signed_part)).unwrap_or(false);

    Ok(ParsedMessage {
        message_id,
        destination_hash,
        source_hash,
        timestamp,
        title,
        content,
        fields,
        signature_validated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_core::constants::KEY_HALF;
    use reticulum_core::destination::single_destination_hash;

    #[test]
    fn pack_parse_roundtrip_verifies() {
        let source = PrivateIdentity::from_bytes(&[0x05; KEY_HALF], &[0x06; KEY_HALF]);
        let recipient = PrivateIdentity::from_bytes(&[0x07; KEY_HALF], &[0x08; KEY_HALF]);
        let dest_hash = single_destination_hash("lxmf", &["delivery"], &recipient.hash());
        let source_hash = single_destination_hash("lxmf", &["delivery"], &source.hash());

        let fields = Fields::new();
        let msg = pack(&source, &dest_hash, &source_hash, 1_700_000_000.0, b"Hi", b"Hello!", &fields, None);

        let parsed = parse(&msg.packed, Some(source.public())).unwrap();
        assert!(parsed.signature_validated);
        assert_eq!(parsed.message_id, msg.message_id);
        assert_eq!(parsed.content, b"Hello!");
        assert_eq!(parsed.title, b"Hi");
        assert_eq!(parsed.destination_hash, dest_hash);
        assert_eq!(parsed.source_hash, source_hash);
    }

    #[test]
    fn wrong_source_fails_verification() {
        let source = PrivateIdentity::from_bytes(&[1; KEY_HALF], &[2; KEY_HALF]);
        let other = PrivateIdentity::from_bytes(&[3; KEY_HALF], &[4; KEY_HALF]);
        let dh = [0xAA; DEST_LEN];
        let sh = [0xBB; DEST_LEN];
        let msg = pack(&source, &dh, &sh, 1.0, b"", b"x", &Fields::new(), None);
        let parsed = parse(&msg.packed, Some(other.public())).unwrap();
        assert!(!parsed.signature_validated);
    }

    #[test]
    fn propagation_envelope_shape_and_recipient_decrypts() {
        let source = PrivateIdentity::from_bytes(&[0x21; KEY_HALF], &[0x22; KEY_HALF]);
        let recipient = PrivateIdentity::from_bytes(&[0x23; KEY_HALF], &[0x24; KEY_HALF]);
        let dest_hash = single_destination_hash("lxmf", &["delivery"], &recipient.hash());
        let source_hash = single_destination_hash("lxmf", &["delivery"], &source.hash());

        let msg = pack(&source, &dest_hash, &source_hash, 1_700_000_000.0, b"", b"stored", &Fields::new(), None);
        let env = pack_propagation(
            recipient.public(), &dest_hash, msg.opportunistic_plaintext(), None,
            &[0x31; KEY_HALF], &[0x32; IV_LENGTH], 1_700_000_001.0, 0,
        );

        // Envelope is [transfer_ts, [lxmf_data]].
        let arr = match msgpack::decode(&env).unwrap() {
            Value::Array(a) => a,
            _ => panic!("not an array"),
        };
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_f64().unwrap(), 1_700_000_001.0);
        let list = arr[1].as_array().unwrap();
        assert_eq!(list.len(), 1);
        let lxmf_data = list[0].as_bin().unwrap();

        // lxmf_data = dest_hash(16) || encrypted(source||sig||payload); the recipient
        // decrypts the tail and recovers a verifiable message.
        assert_eq!(&lxmf_data[..DEST_LEN], &dest_hash[..]);
        let inner = recipient.decrypt(&lxmf_data[DEST_LEN..], &[]).unwrap();
        let mut full = dest_hash.to_vec();
        full.extend_from_slice(&inner);
        let parsed = parse(&full, Some(source.public())).unwrap();
        assert!(parsed.signature_validated);
        assert_eq!(parsed.content, b"stored");
        assert_eq!(parsed.message_id, msg.message_id);
    }

    #[test]
    fn ticket_stamp_is_appended_and_roundtrips() {
        let source = PrivateIdentity::from_bytes(&[0x09; KEY_HALF], &[0x0a; KEY_HALF]);
        let recipient = PrivateIdentity::from_bytes(&[0x0b; KEY_HALF], &[0x0c; KEY_HALF]);
        let dest_hash = single_destination_hash("lxmf", &["delivery"], &recipient.hash());
        let source_hash = single_destination_hash("lxmf", &["delivery"], &source.hash());

        let ticket = [0x42u8; TICKET_LENGTH];
        let msg = pack(
            &source, &dest_hash, &source_hash, 1_700_000_000.0, b"", b"hi", &Fields::new(),
            Some(&ticket),
        );

        // The wire payload carries a 5th element: stamp = H(ticket || message_id).
        let payload = &msg.packed[2 * DEST_LEN + SIG_LENGTH..];
        let arr = match msgpack::decode(payload).unwrap() {
            Value::Array(a) => a,
            _ => panic!("payload is not an array"),
        };
        assert_eq!(arr.len(), 5, "stamp should be appended as the 5th element");
        let mut expected = Vec::new();
        expected.extend_from_slice(&ticket);
        expected.extend_from_slice(&msg.message_id);
        assert_eq!(arr[4].as_bin().unwrap(), &truncated_hash(&expected)[..]);

        // The recipient strips the stamp and the signature still verifies, and the
        // message id is unchanged from the no-ticket case.
        let parsed = parse(&msg.packed, Some(source.public())).unwrap();
        assert!(parsed.signature_validated);
        assert_eq!(parsed.content, b"hi");
        let no_ticket =
            pack(&source, &dest_hash, &source_hash, 1_700_000_000.0, b"", b"hi", &Fields::new(), None);
        assert_eq!(parsed.message_id, no_ticket.message_id);
    }
}
