//! A minimal sans-IO transport for a **leaf** node: it connects to a single
//! Reticulum hub (which does all routing), announces our own destinations,
//! learns peer identities from inbound announces, and decrypts inbound
//! single-destination DATA packets addressed to us.
//!
//! It performs no I/O: feed it deframed packets via [`Transport::handle_frame`]
//! and it returns [`Event`]s; ask it to build outbound packets, then frame and
//! write them yourself. This keeps it testable on the host and reusable by the
//! Xous app. It is intentionally LXMF-agnostic — inbound application data is
//! surfaced as decrypted plaintext for a higher layer (the `lxmf` crate) to
//! parse.

use std::collections::HashMap;
use std::collections::VecDeque;

use rand_core::RngCore;

/// Caps on the in-memory tables so an announce storm (which fills `known`) or a
/// flood of link retries (which fills `links`) can't grow the heap without bound
/// and crash the device. Oldest entries are evicted first (FIFO).
const MAX_KNOWN: usize = 256;
/// Cap on the path table (next-hop routing learned from announces).
const MAX_PATHS: usize = 256;
const MAX_LINKS: usize = 64;
/// Caps for outbound (initiated) link state — links we open to deliver messages
/// directly. Bounded so repeated establishment attempts / unanswered receipts
/// can't grow the heap without limit. Oldest-first (FIFO) eviction.
const MAX_OUT_LINKS: usize = 32;
const MAX_PENDING_OUT: usize = 32;
const MAX_RECEIPTS: usize = 64;

use crate::announce::{ParsedAnnounce, build_announce, parse_and_validate, random_hash};
use crate::constants::*;
use crate::identity::{PrivateIdentity, PublicIdentity};
use crate::link;
use crate::packet::Packet;

/// State for an accepted inbound link: the derived session key plus the exact
/// proof packet we sent. The proof is retained so a retransmitted LINKREQUEST
/// (common on slow, high-RTT links where our first proof hasn't arrived yet) can
/// be answered with the *same* proof — keeping our session key identical to the
/// one the initiator locked in from our first proof. Regenerating it would
/// desync the key and make every data packet fail HMAC verification.
struct LinkState {
    key: [u8; DERIVED_KEY_LENGTH],
    proof: Vec<u8>,
}

/// A link we initiated and are waiting to establish (LINKREQUEST sent, LRPROOF
/// not yet seen). Holds our ephemeral X25519 secret (to finish the ECDH) and the
/// peer's identity (to validate the LRPROOF).
struct PendingOut {
    target: [u8; TRUNCATED_HASHLENGTH],
    eph_secret: [u8; KEY_HALF],
    identity: PublicIdentity,
}

/// An established outbound link, reusable for further messages to `target`.
struct OutLink {
    target: [u8; TRUNCATED_HASHLENGTH],
    key: [u8; DERIVED_KEY_LENGTH],
    /// The peer's identity, to validate the packet proofs (receipts) it returns.
    identity: PublicIdentity,
}

/// A sent opportunistic packet awaiting its delivery proof. The recipient's LXMF
/// layer proves every delivered packet (`LXMRouter.delivery_packet` →
/// `packet.prove()`), sending a PROOF addressed to the *truncated packet hash*;
/// we keep the full hash + recipient identity to validate it. Keyed by that
/// truncated hash (the proof's destination).
struct OppReceipt {
    full_hash: [u8; 32],
    identity: PublicIdentity,
}

/// What we learned about a peer destination (from its announce or a stored contact).
#[derive(Clone)]
pub struct KnownDest {
    pub identity: PublicIdentity,
    pub name_hash: [u8; NAME_HASH_LENGTH],
    pub ratchet: Option<[u8; RATCHET_SIZE]>,
    pub app_data: Vec<u8>,
}

/// A learned route to a destination (RNS path-table entry, `RNS/Transport.py`).
/// Learned from announces: `next_hop` is the transport node that relayed the
/// announce to us (its `transport_id`, present only for HEADER_2 announces), and
/// `hops` is how many hops away the destination is. When a destination is more
/// than one hop away we must inject packets into transport by addressing them to
/// `next_hop` with a HEADER_2 header (see [`Transport::apply_transport`]); a
/// transport node will not forward a plain HEADER_1 packet on our behalf.
#[derive(Clone, Copy)]
pub struct PathEntry {
    pub next_hop: Option<[u8; TRUNCATED_HASHLENGTH]>,
    pub hops: u8,
}

/// Events produced while handling an inbound frame.
pub enum Event {
    /// A validated announce was received (peer identity/path learned).
    Announce { destination_hash: [u8; TRUNCATED_HASHLENGTH], info: KnownDest },
    /// A single-destination DATA packet addressed to one of our destinations was
    /// received and decrypted. `plaintext` is the decrypted payload (for LXMF
    /// opportunistic, this is `source||sig||payload`, with the dest hash stripped).
    Data { destination_hash: [u8; TRUNCATED_HASHLENGTH], plaintext: Vec<u8> },
    /// We accepted an inbound link request; `proof` must be transmitted back to
    /// the initiator so it can start sending data over the link.
    LinkEstablished { link_id: [u8; TRUNCATED_HASHLENGTH], proof: Vec<u8> },
    /// Decrypted application data received over an established link. For LXMF
    /// direct delivery this is the full `dest||source||sig||payload`. `proof` is
    /// a packet receipt to transmit back so the sender confirms delivery.
    LinkData { link_id: [u8; TRUNCATED_HASHLENGTH], plaintext: Vec<u8>, proof: Vec<u8> },
    /// A link we initiated is now established (the responder's LRPROOF validated).
    /// `target` is the destination we opened it to, so queued sends can be flushed.
    OutboundLinkUp { link_id: [u8; TRUNCATED_HASHLENGTH], target: [u8; TRUNCATED_HASHLENGTH] },
    /// A packet proof (receipt) confirmed delivery of a link DATA packet we sent.
    /// `packet_hash` matches the value returned by [`Transport::make_link_data`],
    /// so the caller can mark that specific message delivered.
    Delivered { packet_hash: [u8; 32] },
    /// A DATA packet addressed to us that we could not decrypt.
    DataUndecryptable { destination_hash: [u8; TRUNCATED_HASHLENGTH], reason: &'static str },
    /// A non-DATA packet addressed to one of our destinations that we don't yet
    /// handle (e.g. a link request for direct delivery, or a proof).
    AddressedUnhandled { destination_hash: [u8; TRUNCATED_HASHLENGTH], packet_type: u8, context: u8 },
    /// A packet we recognised but is not for us (its destination hash matched
    /// neither an established link nor one of our own destinations).
    Unhandled { destination_hash: [u8; TRUNCATED_HASHLENGTH], packet_type: u8, context: u8 },
    /// A packet that failed to decode or validate.
    Dropped(&'static str),
}

pub struct Transport {
    identity: PrivateIdentity,
    /// Destination hashes we own (e.g. our lxmf.delivery hash) and their ratchets.
    our_dests: Vec<[u8; TRUNCATED_HASHLENGTH]>,
    /// Peers learned from announces / stored contacts, keyed by destination hash.
    known: HashMap<[u8; TRUNCATED_HASHLENGTH], KnownDest>,
    /// Insertion order of `known` keys, for FIFO eviction past `MAX_KNOWN`.
    known_order: VecDeque<[u8; TRUNCATED_HASHLENGTH]>,
    /// Next-hop routes learned from announces (RNS path table). Used to inject
    /// outbound packets into transport (HEADER_2) for destinations >1 hop away.
    paths: HashMap<[u8; TRUNCATED_HASHLENGTH], PathEntry>,
    paths_order: VecDeque<[u8; TRUNCATED_HASHLENGTH]>,
    /// Active inbound links: link id -> session key + the proof we sent.
    links: HashMap<[u8; TRUNCATED_HASHLENGTH], LinkState>,
    /// Insertion order of `links` keys, for FIFO eviction past `MAX_LINKS`.
    links_order: VecDeque<[u8; TRUNCATED_HASHLENGTH]>,
    /// Links we initiated and are waiting to establish (awaiting LRPROOF).
    pending_out: HashMap<[u8; TRUNCATED_HASHLENGTH], PendingOut>,
    pending_out_order: VecDeque<[u8; TRUNCATED_HASHLENGTH]>,
    /// Established outbound links, reusable for direct delivery.
    out_links: HashMap<[u8; TRUNCATED_HASHLENGTH], OutLink>,
    out_links_order: VecDeque<[u8; TRUNCATED_HASHLENGTH]>,
    /// Outstanding link DATA packets awaiting a proof: packet hash -> link id.
    receipts: HashMap<[u8; 32], [u8; TRUNCATED_HASHLENGTH]>,
    receipts_order: VecDeque<[u8; 32]>,
    /// Outstanding opportunistic packets awaiting a delivery proof, keyed by the
    /// truncated packet hash (== the proof's destination).
    opp_receipts: HashMap<[u8; TRUNCATED_HASHLENGTH], OppReceipt>,
    opp_receipts_order: VecDeque<[u8; TRUNCATED_HASHLENGTH]>,
}

impl Transport {
    pub fn new(identity: PrivateIdentity) -> Transport {
        Transport {
            identity,
            our_dests: Vec::new(),
            known: HashMap::new(),
            known_order: VecDeque::new(),
            paths: HashMap::new(),
            paths_order: VecDeque::new(),
            links: HashMap::new(),
            links_order: VecDeque::new(),
            pending_out: HashMap::new(),
            pending_out_order: VecDeque::new(),
            out_links: HashMap::new(),
            out_links_order: VecDeque::new(),
            receipts: HashMap::new(),
            receipts_order: VecDeque::new(),
            opp_receipts: HashMap::new(),
            opp_receipts_order: VecDeque::new(),
        }
    }

    /// Insert/refresh a known peer, evicting the oldest if over `MAX_KNOWN`.
    fn insert_known(&mut self, hash: [u8; TRUNCATED_HASHLENGTH], info: KnownDest) {
        if self.known.insert(hash, info).is_none() {
            self.known_order.push_back(hash);
            while self.known_order.len() > MAX_KNOWN {
                if let Some(old) = self.known_order.pop_front() {
                    if old != hash {
                        self.known.remove(&old);
                    }
                }
            }
        }
    }

    /// Insert/refresh a learned route, evicting the oldest if over `MAX_PATHS`.
    fn insert_path(&mut self, hash: [u8; TRUNCATED_HASHLENGTH], entry: PathEntry) {
        if self.paths.insert(hash, entry).is_none() {
            self.paths_order.push_back(hash);
            while self.paths_order.len() > MAX_PATHS {
                if let Some(old) = self.paths_order.pop_front() {
                    if old != hash {
                        self.paths.remove(&old);
                    }
                }
            }
        }
    }

    /// True if we have learned a route to `hash` (so an outbound packet can be
    /// correctly addressed — directly or via transport). Callers should request a
    /// path (re-announce) before sending if this is false, mirroring RNS.
    pub fn has_path(&self, hash: &[u8; TRUNCATED_HASHLENGTH]) -> bool {
        self.paths.contains_key(hash)
    }

    /// Rewrite a freshly-built HEADER_1 packet for transport when its destination
    /// is more than one hop away, exactly as `RNS/Transport.py` `outbound` does:
    /// flip the header to HEADER_2 + TRANSPORT and splice the next-hop transport
    /// id in after the hops byte. The hashable part (and thus the packet hash /
    /// link id) is header-type independent, so delivery receipts and proofs are
    /// unaffected. Destinations we know directly (hops ≤ 1, or no learned path)
    /// are left as HEADER_1.
    fn apply_transport(&self, dest: &[u8; TRUNCATED_HASHLENGTH], raw: Vec<u8>) -> Vec<u8> {
        let entry = match self.paths.get(dest) {
            Some(e) => e,
            None => return raw,
        };
        if entry.hops <= 1 {
            return raw;
        }
        let next_hop = match entry.next_hop {
            Some(nh) => nh,
            None => return raw,
        };
        // Only rewrite HEADER_1 packets (matches RNS, which never re-rewrites).
        if raw.is_empty() || (raw[0] & 0b0100_0000) >> 6 != HEADER_1 {
            return raw;
        }
        let new_flags = (HEADER_2 << 6) | (TRANSPORT_TRANSPORT << 4) | (raw[0] & 0b0000_1111);
        let mut out = Vec::with_capacity(raw.len() + TRUNCATED_HASHLENGTH);
        out.push(new_flags);
        out.push(raw[1]); // hops byte, unchanged
        out.extend_from_slice(&next_hop);
        out.extend_from_slice(&raw[2..]); // original dest hash + context + ciphertext
        out
    }

    /// Insert an established link, evicting the oldest if over `MAX_LINKS`.
    fn insert_link(&mut self, link_id: [u8; TRUNCATED_HASHLENGTH], state: LinkState) {
        if self.links.insert(link_id, state).is_none() {
            self.links_order.push_back(link_id);
            while self.links_order.len() > MAX_LINKS {
                if let Some(old) = self.links_order.pop_front() {
                    if old != link_id {
                        self.links.remove(&old);
                    }
                }
            }
        }
    }

    /// Insert a pending outbound link, evicting the oldest past `MAX_PENDING_OUT`.
    fn insert_pending_out(&mut self, link_id: [u8; TRUNCATED_HASHLENGTH], p: PendingOut) {
        if self.pending_out.insert(link_id, p).is_none() {
            self.pending_out_order.push_back(link_id);
            while self.pending_out_order.len() > MAX_PENDING_OUT {
                if let Some(old) = self.pending_out_order.pop_front() {
                    if old != link_id {
                        self.pending_out.remove(&old);
                    }
                }
            }
        }
    }

    /// Insert an established outbound link, evicting the oldest past `MAX_OUT_LINKS`.
    fn insert_out_link(&mut self, link_id: [u8; TRUNCATED_HASHLENGTH], l: OutLink) {
        if self.out_links.insert(link_id, l).is_none() {
            self.out_links_order.push_back(link_id);
            while self.out_links_order.len() > MAX_OUT_LINKS {
                if let Some(old) = self.out_links_order.pop_front() {
                    if old != link_id {
                        self.out_links.remove(&old);
                    }
                }
            }
        }
    }

    /// Register an outstanding receipt (link DATA awaiting proof), FIFO-capped.
    fn insert_receipt(&mut self, packet_hash: [u8; 32], link_id: [u8; TRUNCATED_HASHLENGTH]) {
        if self.receipts.insert(packet_hash, link_id).is_none() {
            self.receipts_order.push_back(packet_hash);
            while self.receipts_order.len() > MAX_RECEIPTS {
                if let Some(old) = self.receipts_order.pop_front() {
                    if old != packet_hash {
                        self.receipts.remove(&old);
                    }
                }
            }
        }
    }

    /// Register an outstanding opportunistic receipt, FIFO-capped.
    fn insert_opp_receipt(&mut self, trunc_hash: [u8; TRUNCATED_HASHLENGTH], rec: OppReceipt) {
        if self.opp_receipts.insert(trunc_hash, rec).is_none() {
            self.opp_receipts_order.push_back(trunc_hash);
            while self.opp_receipts_order.len() > MAX_RECEIPTS {
                if let Some(old) = self.opp_receipts_order.pop_front() {
                    if old != trunc_hash {
                        self.opp_receipts.remove(&old);
                    }
                }
            }
        }
    }

    pub fn identity(&self) -> &PrivateIdentity { &self.identity }

    /// Register one of our own destination hashes so inbound DATA to it is decrypted.
    pub fn register_destination(&mut self, hash: [u8; TRUNCATED_HASHLENGTH]) {
        if !self.our_dests.contains(&hash) {
            self.our_dests.push(hash);
        }
    }

    /// Look up a known peer by destination hash.
    pub fn known(&self, hash: &[u8; TRUNCATED_HASHLENGTH]) -> Option<&KnownDest> {
        self.known.get(hash)
    }

    /// Manually remember a peer (e.g. a contact loaded from storage).
    pub fn remember(&mut self, destination_hash: [u8; TRUNCATED_HASHLENGTH], info: KnownDest) {
        self.insert_known(destination_hash, info);
    }

    /// Handle one deframed inbound packet. `gen_ephemeral` is called (only when
    /// an inbound link request must be answered) to obtain fresh random bytes for
    /// our per-link X25519 key — injected so this layer stays I/O- and RNG-free.
    pub fn handle_frame(
        &mut self,
        raw: &[u8],
        gen_ephemeral: &mut dyn FnMut() -> [u8; KEY_HALF],
    ) -> Event {
        let packet = match Packet::decode(raw) {
            Ok(p) => p,
            Err(e) => return Event::Dropped(e),
        };

        // 0a. LRPROOF completing a link we initiated → derive the session key.
        if packet.packet_type == PACKET_PROOF
            && packet.context == CONTEXT_LRPROOF
            && self.pending_out.contains_key(&packet.destination_hash)
        {
            let lid = packet.destination_hash;
            let pend = self.pending_out.remove(&lid).unwrap();
            return match link::complete_handshake(&lid, &pend.eph_secret, &packet.data, &pend.identity) {
                Some(key) => {
                    let target = pend.target;
                    self.insert_out_link(lid, OutLink { target, key, identity: pend.identity });
                    Event::OutboundLinkUp { link_id: lid, target }
                }
                None => Event::Dropped("invalid LRPROOF for initiated link"),
            };
        }

        // 0b. Packet proof (receipt) confirming a link DATA packet we sent.
        if packet.packet_type == PACKET_PROOF
            && packet.context == CONTEXT_NONE
            && self.out_links.contains_key(&packet.destination_hash)
        {
            let lid = packet.destination_hash;
            let identity = self.out_links[&lid].identity.clone();
            // Explicit proof carries the packet hash; implicit is signature-only, so
            // test it against each outstanding receipt on this link.
            let candidates: Vec<[u8; 32]> = if packet.data.len() >= 32 + SIG_LENGTH {
                let mut ph = [0u8; 32];
                ph.copy_from_slice(&packet.data[..32]);
                vec![ph]
            } else {
                self.receipts.iter().filter(|(_, l)| **l == lid).map(|(h, _)| *h).collect()
            };
            for ph in candidates {
                if self.receipts.get(&ph) == Some(&lid) && link::validate_proof(&identity, &ph, &packet.data) {
                    self.receipts.remove(&ph);
                    return Event::Delivered { packet_hash: ph };
                }
            }
            return Event::AddressedUnhandled {
                destination_hash: lid,
                packet_type: packet.packet_type,
                context: packet.context,
            };
        }

        // 0c. Delivery proof for an opportunistic packet we sent (the recipient's
        // LXMF layer proves every delivered packet). Addressed to the truncated
        // packet hash; validated against the recipient's identity.
        if packet.packet_type == PACKET_PROOF && self.opp_receipts.contains_key(&packet.destination_hash) {
            let rec = &self.opp_receipts[&packet.destination_hash];
            if link::validate_proof(&rec.identity, &rec.full_hash, &packet.data) {
                let full_hash = rec.full_hash;
                self.opp_receipts.remove(&packet.destination_hash);
                return Event::Delivered { packet_hash: full_hash };
            }
        }

        // 1. Data over an already-established inbound link (addressed to a link id).
        if let Some(key) = self.links.get(&packet.destination_hash).map(|s| s.key) {
            if packet.packet_type == PACKET_DATA && packet.context == CONTEXT_NONE {
                return match link::decrypt(&key, &packet.data) {
                    Ok(plaintext) => {
                        let proof = link::prove_packet(&self.identity, &packet.destination_hash, &packet);
                        Event::LinkData { link_id: packet.destination_hash, plaintext, proof }
                    }
                    Err(reason) => {
                        Event::DataUndecryptable { destination_hash: packet.destination_hash, reason }
                    }
                };
            }
            // RTT / keepalive / close and other link control packets: surfaced so
            // the app can report link progress while diagnosing delivery.
            return Event::AddressedUnhandled {
                destination_hash: packet.destination_hash,
                packet_type: packet.packet_type,
                context: packet.context,
            };
        }

        match packet.packet_type {
            PACKET_ANNOUNCE => match parse_and_validate(&packet) {
                Some(ParsedAnnounce { destination_hash, identity, name_hash, ratchet, app_data }) => {
                    let info = KnownDest { identity, name_hash, ratchet, app_data };
                    self.insert_known(destination_hash, info.clone());
                    // Learn the route: `transport_id` (if HEADER_2) is the node that
                    // relayed this to us — our next hop back to the destination. RNS
                    // counts the hop into us, so the destination is `hops + 1` away.
                    self.insert_path(
                        destination_hash,
                        PathEntry { next_hop: packet.transport_id, hops: packet.hops.saturating_add(1) },
                    );
                    Event::Announce { destination_hash, info }
                }
                None => Event::Dropped("invalid announce"),
            },
            _ if self.our_dests.contains(&packet.destination_hash) => {
                // A packet addressed to one of our destinations.
                match packet.packet_type {
                    PACKET_LINKREQUEST => {
                        // A retransmitted request for a link we already accepted
                        // must NOT regenerate our ephemeral: the initiator locked
                        // in the key from our first proof. Re-send that same proof
                        // (in case it was lost) and keep the existing session key.
                        let lid = link::link_id_of(&packet);
                        if let Some(state) = self.links.get(&lid) {
                            return Event::LinkEstablished { link_id: lid, proof: state.proof.clone() };
                        }
                        let eph = gen_ephemeral();
                        match link::accept_request(&packet, &self.identity, &eph) {
                            Some(est) => {
                                self.insert_link(
                                    est.link_id,
                                    LinkState { key: est.derived_key, proof: est.proof_packet.clone() },
                                );
                                Event::LinkEstablished { link_id: est.link_id, proof: est.proof_packet }
                            }
                            None => Event::Dropped("invalid link request"),
                        }
                    }
                    PACKET_DATA => {
                        // Opportunistic delivery: try our ratchets (none yet) then our key.
                        match self.identity.decrypt(&packet.data, &[]) {
                            Ok(plaintext) => Event::Data { destination_hash: packet.destination_hash, plaintext },
                            Err(reason) => {
                                Event::DataUndecryptable { destination_hash: packet.destination_hash, reason }
                            }
                        }
                    }
                    _ => Event::AddressedUnhandled {
                        destination_hash: packet.destination_hash,
                        packet_type: packet.packet_type,
                        context: packet.context,
                    },
                }
            }
            t => Event::Unhandled {
                destination_hash: packet.destination_hash,
                packet_type: t,
                context: packet.context,
            },
        }
    }

    /// Build an ANNOUNCE packet (raw bytes, unframed) for one of our SINGLE
    /// destinations. Caller supplies the app aspects and app_data.
    pub fn make_announce(
        &self,
        app_name: &str,
        aspects: &[&str],
        app_data: &[u8],
        rng: &mut impl RngCore,
        unix_time: u64,
    ) -> Vec<u8> {
        let mut r5 = [0u8; 5];
        rng.fill_bytes(&mut r5);
        self.make_announce_with(app_name, aspects, app_data, &r5, unix_time)
    }

    /// Like [`Transport::make_announce`] but with caller-supplied randomness
    /// (e.g. from the Xous TRNG), avoiding any RNG-trait dependency.
    pub fn make_announce_with(
        &self,
        app_name: &str,
        aspects: &[&str],
        app_data: &[u8],
        random5: &[u8; 5],
        unix_time: u64,
    ) -> Vec<u8> {
        let rh = random_hash(random5, unix_time);
        build_announce(&self.identity, app_name, aspects, app_data, &rh, None).encode()
    }

    /// Build a path request for `target` — asks the network (any transport node
    /// that knows it) to re-announce that destination, so we learn its public
    /// key. Essential on an `access_point` interface, where we never passively
    /// receive announces and so can't otherwise obtain a peer's key to reply.
    ///
    /// Sent as a DATA packet to the well-known PLAIN `rnstransport.path.request`
    /// destination; data = `target_hash(16) || tag(16)` (leaf-node form, no
    /// transport id). `tag` is fresh random bytes (from the TRNG). The response
    /// is an ordinary announce, handled by [`Transport::handle_frame`].
    pub fn make_path_request(
        &self,
        target: &[u8; TRUNCATED_HASHLENGTH],
        tag: &[u8; TRUNCATED_HASHLENGTH],
    ) -> Vec<u8> {
        let pr_dst = crate::destination::plain_destination_hash("rnstransport", &["path", "request"]);
        let mut data = Vec::with_capacity(2 * TRUNCATED_HASHLENGTH);
        data.extend_from_slice(target);
        data.extend_from_slice(tag);
        Packet::header1(DEST_PLAIN, PACKET_DATA, CONTEXT_NONE, pr_dst, data).encode()
    }

    /// Build an opportunistic single-destination DATA packet carrying `plaintext`
    /// encrypted to `recipient`. For LXMF this `plaintext` is the message's
    /// `opportunistic_plaintext()` (source||sig||payload). Returns raw bytes.
    pub fn make_opportunistic(
        &self,
        recipient_hash: &[u8; TRUNCATED_HASHLENGTH],
        recipient: &PublicIdentity,
        ratchet: Option<&[u8; RATCHET_SIZE]>,
        plaintext: &[u8],
        rng: &mut impl RngCore,
    ) -> Vec<u8> {
        let mut eph = [0u8; KEY_HALF];
        let mut iv = [0u8; IV_LENGTH];
        rng.fill_bytes(&mut eph);
        rng.fill_bytes(&mut iv);
        self.make_opportunistic_with(recipient_hash, recipient, ratchet, plaintext, &eph, &iv)
    }

    /// Like [`Transport::make_opportunistic`] but with caller-supplied ephemeral
    /// key and IV (e.g. from the Xous TRNG).
    pub fn make_opportunistic_with(
        &self,
        recipient_hash: &[u8; TRUNCATED_HASHLENGTH],
        recipient: &PublicIdentity,
        ratchet: Option<&[u8; RATCHET_SIZE]>,
        plaintext: &[u8],
        ephemeral_secret: &[u8; KEY_HALF],
        iv: &[u8; IV_LENGTH],
    ) -> Vec<u8> {
        let ciphertext = recipient.encrypt(plaintext, ephemeral_secret, iv, ratchet);
        let raw = Packet::header1(DEST_SINGLE, PACKET_DATA, CONTEXT_NONE, *recipient_hash, ciphertext).encode();
        self.apply_transport(recipient_hash, raw)
    }

    /// Like [`Transport::make_opportunistic_with`], but registers a delivery
    /// receipt so the recipient's returned proof can mark the message delivered
    /// (mirrors how LXMF acknowledges opportunistic delivery). Returns the raw
    /// packet and its full packet hash (the value reported back by
    /// [`Event::Delivered`]).
    pub fn make_opportunistic_tracked(
        &mut self,
        recipient_hash: &[u8; TRUNCATED_HASHLENGTH],
        recipient: &PublicIdentity,
        ratchet: Option<&[u8; RATCHET_SIZE]>,
        plaintext: &[u8],
        ephemeral_secret: &[u8; KEY_HALF],
        iv: &[u8; IV_LENGTH],
    ) -> (Vec<u8>, [u8; 32]) {
        let ciphertext = recipient.encrypt(plaintext, ephemeral_secret, iv, ratchet);
        let packet = Packet::header1(DEST_SINGLE, PACKET_DATA, CONTEXT_NONE, *recipient_hash, ciphertext);
        // The packet hash is over the hashable part, which excludes the header
        // type and transport id, so it is identical whether we send HEADER_1 or
        // the HEADER_2 transport form — the recipient proofs the same value.
        let full = packet.packet_hash();
        let mut trunc = [0u8; TRUNCATED_HASHLENGTH];
        trunc.copy_from_slice(&full[..TRUNCATED_HASHLENGTH]);
        self.insert_opp_receipt(trunc, OppReceipt { full_hash: full, identity: recipient.clone() });
        let raw = self.apply_transport(recipient_hash, packet.encode());
        (raw, full)
    }

    // ---- Outbound (initiated) links, for direct delivery with acks ----

    /// Begin opening a link to `target` (whose `peer_identity` we know from its
    /// announce/contact). `eph_x25519`/`eph_ed25519` are fresh random 32-byte
    /// values (the TRNG on device). Records the pending link and returns the
    /// encoded LINKREQUEST plus its link id. The link becomes usable when the
    /// matching LRPROOF arrives (surfaced as [`Event::OutboundLinkUp`]).
    pub fn make_link_request(
        &mut self,
        target: &[u8; TRUNCATED_HASHLENGTH],
        peer_identity: &PublicIdentity,
        eph_x25519: &[u8; KEY_HALF],
        eph_ed25519: &[u8; KEY_HALF],
    ) -> (Vec<u8>, [u8; TRUNCATED_HASHLENGTH]) {
        let (raw, link_id) = link::initiate_request(target, eph_x25519, eph_ed25519);
        // The link request is addressed to the destination hash, so it must be
        // injected into transport (HEADER_2) when the destination is >1 hop away,
        // or the transport node won't forward it. link_id is over the hashable
        // part (header-independent), so it is unaffected by the rewrite.
        let raw = self.apply_transport(target, raw);
        self.insert_pending_out(
            link_id,
            PendingOut { target: *target, eph_secret: *eph_x25519, identity: peer_identity.clone() },
        );
        (raw, link_id)
    }

    /// An established outbound link to `target`, if one exists (for reuse).
    pub fn outbound_link_for(&self, target: &[u8; TRUNCATED_HASHLENGTH]) -> Option<[u8; TRUNCATED_HASHLENGTH]> {
        self.out_links.iter().find(|(_, l)| l.target == *target).map(|(id, _)| *id)
    }

    /// True if we already have a link to `target` pending establishment (so the
    /// caller can avoid sending a duplicate request).
    pub fn pending_link_to(&self, target: &[u8; TRUNCATED_HASHLENGTH]) -> bool {
        self.pending_out.values().any(|p| p.target == *target)
    }

    /// Build the RTT activation packet for an established outbound link (see
    /// [`link::make_rtt_packet`]). Must be sent immediately after the link comes
    /// up, before any data, or a real RNS responder drops the data. `iv` is fresh
    /// random 16 bytes. Returns None if the link isn't established.
    pub fn make_link_rtt(&self, link_id: &[u8; TRUNCATED_HASHLENGTH], iv: &[u8; IV_LENGTH]) -> Option<Vec<u8>> {
        let key = self.out_links.get(link_id)?.key;
        link::make_rtt_packet(link_id, &key, 0.1, iv).ok()
    }

    /// Encrypt `plaintext` (a full LXMF `dest||source||sig||payload`) and build a
    /// link DATA packet on the established outbound link `link_id`. Registers a
    /// receipt so the matching proof marks delivery. `iv` is fresh random 16 bytes.
    /// Returns the raw packet and its packet hash (the receipt key), or `None` if
    /// the link isn't established.
    pub fn make_link_data(
        &mut self,
        link_id: &[u8; TRUNCATED_HASHLENGTH],
        plaintext: &[u8],
        iv: &[u8; IV_LENGTH],
    ) -> Option<(Vec<u8>, [u8; 32])> {
        let key = self.out_links.get(link_id)?.key;
        let ciphertext = link::encrypt_data(&key, plaintext, iv).ok()?;
        let packet = Packet::header1(DEST_LINK, PACKET_DATA, CONTEXT_NONE, *link_id, ciphertext);
        let packet_hash = packet.packet_hash();
        self.insert_receipt(packet_hash, *link_id);
        Some((packet.encode(), packet_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::single_destination_hash;
    use rand_core::OsRng;

    fn id(seed: u8) -> PrivateIdentity {
        PrivateIdentity::from_bytes(&[seed; KEY_HALF], &[seed.wrapping_add(1); KEY_HALF])
    }

    #[test]
    fn retransmitted_link_request_reuses_original_proof() {
        use crate::packet::Packet;
        let identity = id(0x30);
        let our_dh = single_destination_hash("lxmf", &["delivery"], &identity.hash());
        let mut tp = Transport::new(identity);
        tp.register_destination(our_dh);

        // A valid 64-byte link request (peer x25519 || ed25519 pubs) to our dest.
        let mut data = vec![0u8; 64];
        data[0] = 0x09;
        let req = Packet::header1(DEST_SINGLE, PACKET_LINKREQUEST, CONTEXT_NONE, our_dh, data).encode();

        // Each call yields different ephemeral bytes, as a real TRNG would.
        let mut counter = 0u8;
        let mut eph = || {
            counter += 1;
            [counter; KEY_HALF]
        };

        let proof1 = match tp.handle_frame(&req, &mut eph) {
            Event::LinkEstablished { proof, .. } => proof,
            _ => panic!("expected link established"),
        };
        // The initiator retransmits the *same* request (slow link, our first proof
        // not yet seen). We must answer with the identical proof so its locked-in
        // session key still matches ours.
        let proof2 = match tp.handle_frame(&req, &mut eph) {
            Event::LinkEstablished { proof, .. } => proof,
            _ => panic!("expected link established on retransmit"),
        };
        assert_eq!(proof1, proof2, "retransmitted link request must reuse the original proof/key");
    }

    #[test]
    fn outbound_link_delivers_and_gets_proof() {
        // Initiator (us) opens a link to a responder, sends data, and the
        // responder's packet proof marks it delivered.
        let initiator_id = id(0x40);
        let responder_id = id(0x50);
        let responder_dh = single_destination_hash("lxmf", &["delivery"], &responder_id.hash());

        let mut initiator = Transport::new(initiator_id);
        let mut responder = Transport::new(responder_id);
        responder.register_destination(responder_dh);
        let mut eph = || [0xABu8; KEY_HALF];

        // 1. Initiator builds + sends a link request; responder accepts it.
        let peer_pub = PrivateIdentity::from_bytes(&[0x50; KEY_HALF], &[0x51; KEY_HALF]).public().clone();
        let (req, lid) = initiator.make_link_request(&responder_dh, &peer_pub, &[1; KEY_HALF], &[2; KEY_HALF]);
        let proof = match responder.handle_frame(&req, &mut eph) {
            Event::LinkEstablished { link_id, proof } => {
                assert_eq!(link_id, lid);
                proof
            }
            _ => panic!("responder should accept the link"),
        };

        // 2. Initiator processes the LRPROOF → outbound link is up.
        match initiator.handle_frame(&proof, &mut eph) {
            Event::OutboundLinkUp { link_id, target } => {
                assert_eq!(link_id, lid);
                assert_eq!(target, responder_dh);
            }
            Event::Dropped(e) => panic!("LRPROOF dropped: {e}"),
            _ => panic!("expected outbound link up"),
        }
        assert_eq!(initiator.outbound_link_for(&responder_dh), Some(lid));

        // 3. Initiator sends LXMF data over the link; responder decrypts + proves.
        let (data, packet_hash) =
            initiator.make_link_data(&lid, b"direct hello", &[3u8; IV_LENGTH]).expect("link data");
        let receipt = match responder.handle_frame(&data, &mut eph) {
            Event::LinkData { plaintext, proof, .. } => {
                assert_eq!(plaintext, b"direct hello");
                proof
            }
            Event::DataUndecryptable { reason, .. } => panic!("undecryptable: {reason}"),
            _ => panic!("expected link data"),
        };

        // 4. Initiator processes the packet proof → delivered.
        match initiator.handle_frame(&receipt, &mut eph) {
            Event::Delivered { packet_hash: ph } => assert_eq!(ph, packet_hash),
            _ => panic!("expected delivered"),
        }
    }

    #[test]
    fn opportunistic_send_is_acknowledged_by_proof() {
        use crate::packet::Packet;
        let sender_id = id(0x70);
        let recipient_id = id(0x60);
        let recipient_dh = single_destination_hash("lxmf", &["delivery"], &recipient_id.hash());

        let mut sender = Transport::new(sender_id);
        // Sender knows the recipient (as if from an announce).
        sender.remember(
            recipient_dh,
            KnownDest {
                identity: recipient_id.public().clone(),
                name_hash: crate::destination::name_hash("lxmf", &["delivery"]),
                ratchet: None,
                app_data: Vec::new(),
            },
        );

        // Send a tracked opportunistic packet.
        let (_raw, full_hash) = sender.make_opportunistic_tracked(
            &recipient_dh, recipient_id.public(), None, b"payload", &[3u8; KEY_HALF], &[4u8; IV_LENGTH],
        );

        // The recipient's LXMF layer proves it: PROOF (packet_hash || signature)
        // addressed to the truncated packet hash.
        let mut trunc = [0u8; TRUNCATED_HASHLENGTH];
        trunc.copy_from_slice(&full_hash[..TRUNCATED_HASHLENGTH]);
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&full_hash);
        proof_data.extend_from_slice(&recipient_id.sign(&full_hash));
        let proof = Packet::header1(DEST_SINGLE, PACKET_PROOF, CONTEXT_NONE, trunc, proof_data).encode();

        let mut eph = || [0u8; KEY_HALF];
        match sender.handle_frame(&proof, &mut eph) {
            Event::Delivered { packet_hash } => assert_eq!(packet_hash, full_hash),
            _ => panic!("expected delivered"),
        }
        // A second copy of the proof no longer matches (receipt consumed).
        let proof2 = {
            let mut d = Vec::new();
            d.extend_from_slice(&full_hash);
            d.extend_from_slice(&recipient_id.sign(&full_hash));
            Packet::header1(DEST_SINGLE, PACKET_PROOF, CONTEXT_NONE, trunc, d).encode()
        };
        assert!(!matches!(sender.handle_frame(&proof2, &mut eph), Event::Delivered { .. }));
    }

    #[test]
    fn learns_peer_from_announce_then_messages_it() {
        // id() is deterministic from the seed, so each call yields the same keys.
        let bob_dh = single_destination_hash("lxmf", &["delivery"], &id(0x20).hash());

        // Alice's transport ingests Bob's announce.
        let mut alice_tp = Transport::new(id(0x10));
        let bob_announce = Transport::new(id(0x20))
            .make_announce("lxmf", &["delivery"], b"bob", &mut OsRng, 1_700_000_000);
        let mut eph = || [0u8; KEY_HALF];
        match alice_tp.handle_frame(&bob_announce, &mut eph) {
            Event::Announce { destination_hash, .. } => assert_eq!(destination_hash, bob_dh),
            _ => panic!("expected announce"),
        }
        assert!(alice_tp.known(&bob_dh).is_some());

        // Alice encrypts an opportunistic payload to Bob; Bob's transport decrypts it.
        let bob_known = alice_tp.known(&bob_dh).unwrap().clone();
        let pkt = alice_tp.make_opportunistic(&bob_dh, &bob_known.identity, None, b"secret payload", &mut OsRng);

        let mut bob_tp = Transport::new(id(0x20));
        bob_tp.register_destination(bob_dh);
        match bob_tp.handle_frame(&pkt, &mut eph) {
            Event::Data { destination_hash, plaintext } => {
                assert_eq!(destination_hash, bob_dh);
                assert_eq!(plaintext, b"secret payload");
            }
            Event::Dropped(e) => panic!("dropped: {e}"),
            _ => panic!("expected data"),
        }
    }

    #[test]
    fn remote_announce_routes_outbound_via_transport_header() {
        use crate::packet::{HeaderType, Packet};
        // Bob is reachable only via a transport node ("hub"). His announce reaches
        // us relayed: HEADER_2 with the hub's transport id and a non-zero hop count.
        let bob_dh = single_destination_hash("lxmf", &["delivery"], &id(0x21).hash());
        let hub_id: [u8; TRUNCATED_HASHLENGTH] = [0xAB; TRUNCATED_HASHLENGTH];

        let direct = Transport::new(id(0x21)).make_announce("lxmf", &["delivery"], b"bob", &mut OsRng, 1_700_000_000);
        let mut relayed = Packet::decode(&direct).unwrap();
        relayed.header_type = HeaderType::Two;
        relayed.transport_type = TRANSPORT_TRANSPORT;
        relayed.transport_id = Some(hub_id);
        relayed.hops = 1; // one hop already taken; we count the hop into us → 2 away
        let relayed = relayed.encode();

        let mut alice = Transport::new(id(0x11));
        let mut eph = || [0u8; KEY_HALF];
        match alice.handle_frame(&relayed, &mut eph) {
            Event::Announce { destination_hash, .. } => assert_eq!(destination_hash, bob_dh),
            _ => panic!("expected announce"),
        }
        assert!(alice.has_path(&bob_dh));

        // An opportunistic send to Bob must be injected into transport: HEADER_2,
        // TRANSPORT type, hub id as the first address, Bob's hash as the second.
        let bob = alice.known(&bob_dh).unwrap().clone();
        let (raw, full_hash) = alice.make_opportunistic_tracked(
            &bob_dh, &bob.identity, None, b"hi", &[7u8; KEY_HALF], &[8u8; IV_LENGTH],
        );
        let p = Packet::decode(&raw).unwrap();
        assert_eq!(p.header_type, HeaderType::Two, "remote dest must use the transport header");
        assert_eq!(p.transport_type, TRANSPORT_TRANSPORT);
        assert_eq!(p.transport_id, Some(hub_id), "first address must be the next-hop transport id");
        assert_eq!(p.destination_hash, bob_dh, "second address must be the final destination");
        // The packet hash (receipt key) is over the header-independent hashable
        // part, so it still equals the recipient's proof target.
        assert_eq!(p.packet_hash(), full_hash);

        // A directly-reachable destination (HEADER_1 announce) stays HEADER_1.
        let carol_dh = single_destination_hash("lxmf", &["delivery"], &id(0x23).hash());
        let carol_ann = Transport::new(id(0x23)).make_announce("lxmf", &["delivery"], b"carol", &mut OsRng, 1_700_000_000);
        alice.handle_frame(&carol_ann, &mut eph);
        let carol = alice.known(&carol_dh).unwrap().clone();
        let (raw2, _) = alice.make_opportunistic_tracked(
            &carol_dh, &carol.identity, None, b"hi", &[7u8; KEY_HALF], &[8u8; IV_LENGTH],
        );
        assert_eq!(Packet::decode(&raw2).unwrap().header_type, HeaderType::One, "direct dest stays HEADER_1");
    }
}
