//! Reticulum Link **responder** — enough to receive LXMF *direct* delivery.
//!
//! When a peer wants reliable delivery it opens a Link to our destination:
//! 1. it sends a LINKREQUEST containing its ephemeral X25519 + Ed25519 pubkeys;
//! 2. we derive a shared key (ECDH + HKDF), and reply with a PROOF addressed to
//!    the link id, signed by our *identity* so the peer can trust it reached us;
//! 3. the peer then sends the LXMF message as link DATA, encrypted with the
//!    session key (the Token/AES-256-CBC+HMAC primitive).
//!
//! We implement both the responder side (accept inbound links, decrypt data) and
//! the initiator side (open a link to a peer, send data, confirm delivery via the
//! returned packet proof) — the latter is what gives outbound messages a real
//! delivery acknowledgement. Mirrors `RNS/Link.py`.

use ed25519_dalek::SigningKey;

use crate::constants::*;
use crate::crypto::{Token, hkdf, truncated_hash};
use crate::x25519::{x25519, x25519_base};
use crate::identity::{PrivateIdentity, PublicIdentity};
use crate::packet::{HeaderType, Packet};

/// X25519 pub (32) || Ed25519 pub (32).
const ECPUBSIZE: usize = 64;
/// Optional MTU/mode signalling appended to requests/proofs.
const LINK_MTU_SIZE: usize = 3;
const MODE_AES256_CBC: u8 = 0x01;
const MTU_BYTEMASK: u32 = 0x001F_FFFF;
const MODE_BYTEMASK: u32 = 0xE0;

/// Result of accepting a link request.
pub struct EstablishedLink {
    pub link_id: [u8; TRUNCATED_HASHLENGTH],
    /// HKDF-derived 64-byte key feeding the link Token (AES-256 + HMAC).
    pub derived_key: [u8; DERIVED_KEY_LENGTH],
    /// The PROOF packet to transmit back to the initiator (already encoded).
    pub proof_packet: Vec<u8>,
    /// The initiator's per-link **ephemeral** Ed25519 verifying key (bytes
    /// 32..64 of the LINKREQUEST). This — not its identity key — signs the
    /// packet proofs it returns for data we send on this link (RNS
    /// `Link.__init__`: initiators use `sig_prv = Ed25519PrivateKey.generate()`).
    pub peer_sig_pub: [u8; KEY_HALF],
}

/// Compute the link id for an inbound LINKREQUEST without accepting it. Used to
/// detect a retransmitted request (so we re-send the original proof rather than
/// regenerating our ephemeral, which would desync the session key).
pub fn link_id_of(request: &Packet) -> [u8; TRUNCATED_HASHLENGTH] {
    link_id(request)
}

/// `link_id_from_lr_packet`: truncated hash of the request's hashable part, with
/// any trailing MTU-signalling bytes removed first.
fn link_id(request: &Packet) -> [u8; TRUNCATED_HASHLENGTH] {
    let mut hp = request.hashable_part();
    if request.data.len() > ECPUBSIZE {
        let diff = request.data.len() - ECPUBSIZE;
        hp.truncate(hp.len() - diff);
    }
    truncated_hash(&hp)
}

/// `signalling_bytes(mtu, mode)` — 3-byte encoding of MTU (21 bits) + mode (3 bits).
fn signalling_bytes(mtu: u32, mode: u8) -> [u8; LINK_MTU_SIZE] {
    let value = (mtu & MTU_BYTEMASK) | ((((mode as u32) << 5) & MODE_BYTEMASK) << 16);
    let b = value.to_be_bytes();
    [b[1], b[2], b[3]]
}

fn requested_mtu(request: &Packet) -> u32 {
    if request.data.len() == ECPUBSIZE + LINK_MTU_SIZE {
        let d = &request.data;
        (((d[ECPUBSIZE] as u32) << 16) | ((d[ECPUBSIZE + 1] as u32) << 8) | (d[ECPUBSIZE + 2] as u32))
            & MTU_BYTEMASK
    } else {
        MTU as u32
    }
}

/// Accept an inbound LINKREQUEST and produce the link state + a signed proof.
/// `ephemeral_secret` is fresh random 32 bytes (our per-link X25519 private key).
pub fn accept_request(
    request: &Packet,
    identity: &PrivateIdentity,
    ephemeral_secret: &[u8; KEY_HALF],
) -> Option<EstablishedLink> {
    if request.header_type != HeaderType::One && request.header_type != HeaderType::Two {
        return None;
    }
    if request.data.len() != ECPUBSIZE && request.data.len() != ECPUBSIZE + LINK_MTU_SIZE {
        return None;
    }
    let mut peer_pub = [0u8; KEY_HALF];
    peer_pub.copy_from_slice(&request.data[..KEY_HALF]);
    let mut peer_sig_pub = [0u8; KEY_HALF];
    peer_sig_pub.copy_from_slice(&request.data[KEY_HALF..ECPUBSIZE]);

    let lid = link_id(request);

    // ECDH: our fresh ephemeral X25519 private key against the peer's ephemeral
    // pub. Software X25519 (the hardware engine's Montgomery ladder is broken).
    let our_pub = x25519_base(ephemeral_secret);
    let shared = x25519(ephemeral_secret, &peer_pub);
    let derived = hkdf(DERIVED_KEY_LENGTH, &shared, Some(&lid), None);
    let mut derived_key = [0u8; DERIVED_KEY_LENGTH];
    derived_key.copy_from_slice(&derived);

    // Proof: sign link_id || our_ephemeral_pub || our_identity_sig_pub || signalling
    // with our long-term identity key (so the initiator can trust the proof).
    let mtu = requested_mtu(request);
    let sig = signalling_bytes(mtu, MODE_AES256_CBC);

    let mut signed = Vec::with_capacity(TRUNCATED_HASHLENGTH + KEY_HALF + KEY_HALF + LINK_MTU_SIZE);
    signed.extend_from_slice(&lid);
    signed.extend_from_slice(&our_pub);
    signed.extend_from_slice(&identity.public().sig_pub);
    signed.extend_from_slice(&sig);
    let signature = identity.sign(&signed);

    let mut proof_data = Vec::with_capacity(SIG_LENGTH + KEY_HALF + LINK_MTU_SIZE);
    proof_data.extend_from_slice(&signature);
    proof_data.extend_from_slice(&our_pub);
    proof_data.extend_from_slice(&sig);

    let proof = Packet::header1(DEST_LINK, PACKET_PROOF, CONTEXT_LRPROOF, lid, proof_data);
    Some(EstablishedLink { link_id: lid, derived_key, proof_packet: proof.encode(), peer_sig_pub })
}

/// Decrypt a link DATA packet's payload with the session key.
pub fn decrypt(derived_key: &[u8; DERIVED_KEY_LENGTH], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    Token::new(derived_key)?.decrypt(data)
}

// ---- Initiator side (we open the link, for outbound direct delivery) ----

/// Build a LINKREQUEST to `target` as the **initiator**. `eph_x25519_secret` and
/// `eph_ed25519_seed` are fresh random 32-byte values — the per-link ephemeral
/// keys (the Ed25519 one is only the link's signing identity; we never need its
/// private half again for plain delivery). Returns the encoded request packet and
/// the link id, which the caller stores to match the responder's LRPROOF. Mirrors
/// the request construction in `RNS/Link.py`.
pub fn initiate_request(
    target: &[u8; TRUNCATED_HASHLENGTH],
    eph_x25519_secret: &[u8; KEY_HALF],
    eph_ed25519_seed: &[u8; KEY_HALF],
) -> (Vec<u8>, [u8; TRUNCATED_HASHLENGTH]) {
    let x_pub = x25519_base(eph_x25519_secret);
    let ed_pub = SigningKey::from_bytes(eph_ed25519_seed).verifying_key().to_bytes();
    let sig = signalling_bytes(MTU as u32, MODE_AES256_CBC);

    let mut data = Vec::with_capacity(ECPUBSIZE + LINK_MTU_SIZE);
    data.extend_from_slice(&x_pub);
    data.extend_from_slice(&ed_pub);
    data.extend_from_slice(&sig);

    let packet = Packet::header1(DEST_SINGLE, PACKET_LINKREQUEST, CONTEXT_NONE, *target, data);
    let lid = link_id(&packet);
    (packet.encode(), lid)
}

/// Complete the initiator handshake from the responder's LRPROOF. The proof data
/// is `signature(64) || responder_ephemeral_x25519_pub(32) || signalling(0|3)`.
/// We validate the signature against `peer_identity` (the recipient's identity,
/// learned from its announce) — the exact inverse of [`accept_request`] — and
/// derive the session key. Returns the 64-byte key, or `None` if malformed or the
/// signature is invalid.
pub fn complete_handshake(
    link_id: &[u8; TRUNCATED_HASHLENGTH],
    eph_x25519_secret: &[u8; KEY_HALF],
    proof_data: &[u8],
    peer_identity: &PublicIdentity,
) -> Option<[u8; DERIVED_KEY_LENGTH]> {
    if proof_data.len() < SIG_LENGTH + KEY_HALF {
        return None;
    }
    let signature = &proof_data[..SIG_LENGTH];
    let mut peer_pub = [0u8; KEY_HALF];
    peer_pub.copy_from_slice(&proof_data[SIG_LENGTH..SIG_LENGTH + KEY_HALF]);
    let signalling = &proof_data[SIG_LENGTH + KEY_HALF..];

    // Reconstruct the responder's signed material: link_id || its ephemeral pub ||
    // its identity sig pub || signalling.
    let mut signed = Vec::with_capacity(TRUNCATED_HASHLENGTH + KEY_HALF + KEY_HALF + signalling.len());
    signed.extend_from_slice(link_id);
    signed.extend_from_slice(&peer_pub);
    signed.extend_from_slice(&peer_identity.sig_pub);
    signed.extend_from_slice(signalling);
    if !peer_identity.validate(signature, &signed) {
        return None;
    }

    let shared = x25519(eph_x25519_secret, &peer_pub);
    let derived = hkdf(DERIVED_KEY_LENGTH, &shared, Some(link_id), None);
    let mut key = [0u8; DERIVED_KEY_LENGTH];
    key.copy_from_slice(&derived);
    Some(key)
}

/// Build the link **RTT packet** the initiator must send right after validating
/// the responder's proof. Real RNS responders only mark the link ACTIVE — and
/// only then start accepting data + firing their established callback — once they
/// receive this packet (`RNS/Link.py:validate_proof` sends it; `rtt_packet`
/// activates on receipt). Without it, the responder silently drops our data.
///
/// Data = Token-encrypt(msgpack(rtt_f64)); a DATA packet with context `LRRTT`
/// addressed to the link id. The rtt value is informational (the responder takes
/// `max` with its own measurement), so any small float works.
pub fn make_rtt_packet(
    link_id: &[u8; TRUNCATED_HASHLENGTH],
    derived_key: &[u8; DERIVED_KEY_LENGTH],
    rtt_seconds: f64,
    iv: &[u8; IV_LENGTH],
) -> Result<Vec<u8>, &'static str> {
    // msgpack float64: 0xcb || 8 bytes big-endian.
    let mut rtt_msgpack = Vec::with_capacity(9);
    rtt_msgpack.push(0xcb);
    rtt_msgpack.extend_from_slice(&rtt_seconds.to_be_bytes());
    let ciphertext = encrypt_data(derived_key, &rtt_msgpack, iv)?;
    Ok(Packet::header1(DEST_LINK, PACKET_DATA, CONTEXT_LRRTT, *link_id, ciphertext).encode())
}

/// Encrypt `plaintext` for transmission as a link DATA packet (Token / AES-256-CBC
/// + HMAC under the session key). Caller supplies the 16-byte IV (TRNG on device).
/// Mirror of [`decrypt`].
pub fn encrypt_data(
    derived_key: &[u8; DERIVED_KEY_LENGTH],
    plaintext: &[u8],
    iv: &[u8; IV_LENGTH],
) -> Result<Vec<u8>, &'static str> {
    Ok(Token::new(derived_key)?.encrypt_with_iv(plaintext, iv))
}

/// Validate a packet PROOF (receipt) returned for a link DATA packet we sent, so
/// we can mark the message delivered. Explicit proof = `packet_hash(32) ||
/// Ed25519_sign(packet_hash)`; implicit = `Ed25519_sign(packet_hash)`. The
/// signature is by the recipient's identity. Mirrors
/// `RNS/Packet.py:PacketReceipt.validate_proof`.
pub fn validate_proof(
    peer_identity: &PublicIdentity,
    packet_hash: &[u8; 32],
    proof_data: &[u8],
) -> bool {
    validate_proof_sig(&peer_identity.sig_pub, packet_hash, proof_data)
}

/// Validate a packet PROOF against a raw Ed25519 verifying key. Which key signs
/// a link packet proof depends on the prover's side of the link (RNS
/// `Link.__init__` / `Packet.py:validate_link_proof` → `link.peer_sig_pub`):
/// a **responder** proves with its identity key, but an **initiator** proves
/// with the per-link ephemeral key from its LINKREQUEST.
pub fn validate_proof_sig(
    sig_pub: &[u8; KEY_HALF],
    packet_hash: &[u8; 32],
    proof_data: &[u8],
) -> bool {
    let signature = if proof_data.len() == 32 + SIG_LENGTH {
        if proof_data[..32] != packet_hash[..] {
            return false;
        }
        &proof_data[32..32 + SIG_LENGTH]
    } else if proof_data.len() == SIG_LENGTH {
        &proof_data[..SIG_LENGTH]
    } else {
        return false;
    };
    let mut sig = [0u8; SIG_LENGTH];
    sig.copy_from_slice(signature);
    crate::ed25519::verify(sig_pub, packet_hash, &sig)
}

/// Build a packet PROOF (receipt) for a received link DATA packet, so the sender
/// gets delivery confirmation and doesn't time out / retry / tear down the link.
/// Proof = `packet_hash(32) || Ed25519_sign(identity, packet_hash)`, sent as an
/// (unencrypted) PROOF packet addressed to the link id. Mirrors `Link.prove_packet`.
pub fn prove_packet(
    identity: &PrivateIdentity,
    link_id: &[u8; TRUNCATED_HASHLENGTH],
    data_packet: &Packet,
) -> Vec<u8> {
    let packet_hash = data_packet.packet_hash(); // full 32-byte SHA-256
    let signature = identity.sign(&packet_hash);
    let mut proof_data = Vec::with_capacity(packet_hash.len() + signature.len());
    proof_data.extend_from_slice(&packet_hash);
    proof_data.extend_from_slice(&signature);
    Packet::header1(DEST_LINK, PACKET_PROOF, CONTEXT_NONE, *link_id, proof_data).encode()
}

/// [`prove_packet`] for a link we **initiated**: the proof must be signed with
/// the per-link ephemeral Ed25519 key whose public half went into our
/// LINKREQUEST — that's the key the responder validates against (RNS
/// `Link.__init__`: `sig_prv = Ed25519PrivateKey.generate()` for initiators;
/// `validate_link_proof` → `link.peer_sig_pub`). Signing with our identity key
/// here would make the peer silently reject the receipt.
pub fn prove_packet_ephemeral(
    eph_ed25519_seed: &[u8; KEY_HALF],
    link_id: &[u8; TRUNCATED_HASHLENGTH],
    data_packet: &Packet,
) -> Vec<u8> {
    let sig_pub = SigningKey::from_bytes(eph_ed25519_seed).verifying_key().to_bytes();
    let packet_hash = data_packet.packet_hash();
    let signature = crate::ed25519::sign(eph_ed25519_seed, &sig_pub, &packet_hash);
    let mut proof_data = Vec::with_capacity(packet_hash.len() + signature.len());
    proof_data.extend_from_slice(&packet_hash);
    proof_data.extend_from_slice(&signature);
    Packet::header1(DEST_LINK, PACKET_PROOF, CONTEXT_NONE, *link_id, proof_data).encode()
}

/// Build an arbitrary link DATA packet: Token-encrypt `plaintext` under the
/// session key and wrap it as a DATA packet with `context` to `link_id`. This is
/// the generic primitive behind RTT / identify / request / response sends over an
/// established link. Caller supplies a fresh 16-byte IV (TRNG on device).
pub fn make_link_context_packet(
    link_id: &[u8; TRUNCATED_HASHLENGTH],
    derived_key: &[u8; DERIVED_KEY_LENGTH],
    context: u8,
    plaintext: &[u8],
    iv: &[u8; IV_LENGTH],
) -> Result<Vec<u8>, &'static str> {
    let ciphertext = encrypt_data(derived_key, plaintext, iv)?;
    Ok(Packet::header1(DEST_LINK, PACKET_DATA, context, *link_id, ciphertext).encode())
}

/// Build a `LINKIDENTIFY` packet that proves *our* identity to the link peer, so
/// e.g. a propagation node knows which stored messages are ours. Mirrors
/// `RNS/Link.identify`: `signed_data = link_id || pub(64)`, the proof is
/// `pub(64) || Ed25519_sign(signed_data)`, sent as an encrypted DATA packet with
/// context `LINKIDENTIFY`. `pub` is `enc_pub(32) || sig_pub(32)` (RNS
/// `Identity.get_public_key`).
/// Validate a received `LINKIDENTIFY` plaintext (`pub(64) || sign(link_id ||
/// pub)`) and return the identified peer. This is how a link initiator tells
/// the responder who it is — which in LXMF opens a **backchannel**: the
/// responder may reply over this same link instead of establishing its own.
pub fn validate_identify(
    link_id: &[u8; TRUNCATED_HASHLENGTH],
    plaintext: &[u8],
) -> Option<PublicIdentity> {
    if plaintext.len() != KEYSIZE + SIG_LENGTH {
        return None;
    }
    let identity = PublicIdentity::from_public_key(&plaintext[..KEYSIZE]).ok()?;
    let mut signed = Vec::with_capacity(TRUNCATED_HASHLENGTH + KEYSIZE);
    signed.extend_from_slice(link_id);
    signed.extend_from_slice(&plaintext[..KEYSIZE]);
    if identity.validate(&plaintext[KEYSIZE..], &signed) { Some(identity) } else { None }
}

pub fn make_identify(
    link_id: &[u8; TRUNCATED_HASHLENGTH],
    derived_key: &[u8; DERIVED_KEY_LENGTH],
    identity: &PrivateIdentity,
    iv: &[u8; IV_LENGTH],
) -> Result<Vec<u8>, &'static str> {
    let pubkey = identity.public().public_key();
    let mut signed = Vec::with_capacity(TRUNCATED_HASHLENGTH + pubkey.len());
    signed.extend_from_slice(link_id);
    signed.extend_from_slice(&pubkey);
    let signature = identity.sign(&signed);
    let mut proof_data = Vec::with_capacity(pubkey.len() + signature.len());
    proof_data.extend_from_slice(&pubkey);
    proof_data.extend_from_slice(&signature);
    make_link_context_packet(link_id, derived_key, CONTEXT_LINKIDENTIFY, &proof_data, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signalling_roundtrip_shape() {
        // default MTU 500, AES-256 mode
        let s = signalling_bytes(MTU as u32, MODE_AES256_CBC);
        // mode is the top 3 bits of the first signalling byte
        assert_eq!((s[0] >> 5) & 0x07, MODE_AES256_CBC);
        let mtu = (((s[0] as u32) << 16) | ((s[1] as u32) << 8) | (s[2] as u32)) & MTU_BYTEMASK;
        assert_eq!(mtu, MTU as u32);
    }

    #[test]
    fn accept_request_produces_proof_and_key() {
        let id = PrivateIdentity::from_bytes(&[1; KEY_HALF], &[2; KEY_HALF]);
        // a fake link request: 64 bytes of peer pubs to our delivery dest
        let mut data = vec![0u8; ECPUBSIZE];
        data[0] = 9; // arbitrary peer x25519 pub bytes
        let req = Packet::header1(DEST_SINGLE, PACKET_LINKREQUEST, CONTEXT_NONE, [0x42; 16], data);
        let est = accept_request(&req, &id, &[7; KEY_HALF]).expect("accept");
        // proof = signature(64) + our_pub(32) + signalling(3)
        let decoded = Packet::decode(&est.proof_packet).unwrap();
        assert_eq!(decoded.packet_type, PACKET_PROOF);
        assert_eq!(decoded.context, CONTEXT_LRPROOF);
        assert_eq!(decoded.destination_hash, est.link_id);
        assert_eq!(decoded.data.len(), SIG_LENGTH + KEY_HALF + LINK_MTU_SIZE);
    }

    #[test]
    fn initiator_and_responder_derive_the_same_key() {
        let responder = PrivateIdentity::from_bytes(&[1; KEY_HALF], &[2; KEY_HALF]);
        let target = [0x55u8; TRUNCATED_HASHLENGTH];
        let init_x = [7u8; KEY_HALF];
        let init_ed = [8u8; KEY_HALF];

        // Initiator builds the request; responder accepts it.
        let (req_raw, lid) = initiate_request(&target, &init_x, &init_ed);
        let req = Packet::decode(&req_raw).unwrap();
        let est = accept_request(&req, &responder, &[9u8; KEY_HALF]).expect("accept");
        assert_eq!(est.link_id, lid, "both sides compute the same link id");

        // Initiator completes from the responder's proof → same session key.
        let proof = Packet::decode(&est.proof_packet).unwrap();
        let key = complete_handshake(&lid, &init_x, &proof.data, responder.public()).expect("handshake");
        assert_eq!(key, est.derived_key);

        // A forged proof (validated against the wrong identity) is rejected.
        let attacker = PrivateIdentity::from_bytes(&[3; KEY_HALF], &[4; KEY_HALF]);
        assert!(complete_handshake(&lid, &init_x, &proof.data, attacker.public()).is_none());
    }

    #[test]
    fn validate_proof_accepts_genuine_receipt_only() {
        let recipient = PrivateIdentity::from_bytes(&[5; KEY_HALF], &[6; KEY_HALF]);
        let data_pkt = Packet::header1(DEST_LINK, PACKET_DATA, CONTEXT_NONE, [0xAB; 16], vec![1, 2, 3]);
        let ph = data_pkt.packet_hash();

        // Explicit proof: packet_hash || sign(packet_hash).
        let mut proof = Vec::new();
        proof.extend_from_slice(&ph);
        proof.extend_from_slice(&recipient.sign(&ph));
        assert!(validate_proof(recipient.public(), &ph, &proof));

        // Implicit proof: just the signature.
        let implicit = recipient.sign(&ph).to_vec();
        assert!(validate_proof(recipient.public(), &ph, &implicit));

        // Wrong hash, or wrong signer, fails.
        assert!(!validate_proof(recipient.public(), &[0u8; 32], &proof));
        let attacker = PrivateIdentity::from_bytes(&[7; KEY_HALF], &[8; KEY_HALF]);
        assert!(!validate_proof(attacker.public(), &ph, &proof));
    }

    #[test]
    fn identify_packet_decrypts_to_valid_proof() {
        // Build a session key the way both sides would, then identify over it.
        let me = PrivateIdentity::from_bytes(&[0x11; KEY_HALF], &[0x12; KEY_HALF]);
        let key = [0x5a_u8; DERIVED_KEY_LENGTH];
        let link_id = [0x77_u8; TRUNCATED_HASHLENGTH];
        let raw = make_identify(&link_id, &key, &me, &[0x33; IV_LENGTH]).expect("identify");

        let pkt = Packet::decode(&raw).unwrap();
        assert_eq!(pkt.packet_type, PACKET_DATA);
        assert_eq!(pkt.context, CONTEXT_LINKIDENTIFY);
        assert_eq!(pkt.destination_hash, link_id);

        // The peer decrypts and validates: pub(64) || sign(link_id || pub).
        let proof = decrypt(&key, &pkt.data).expect("decrypt identify");
        assert_eq!(proof.len(), KEYSIZE + SIG_LENGTH);
        let pubkey = &proof[..KEYSIZE];
        let signature = &proof[KEYSIZE..];
        assert_eq!(pubkey, &me.public().public_key()[..]);
        let mut signed = Vec::new();
        signed.extend_from_slice(&link_id);
        signed.extend_from_slice(pubkey);
        let peer = PublicIdentity::from_public_key(pubkey).expect("pub");
        assert!(peer.validate(signature, &signed), "identify signature must validate");
    }
}
