//! Reticulum packet header codec. Mirrors `RNS/Packet.py` `pack`/`unpack`.
//!
//! This layer is purely structural: `data` holds the already-final payload
//! (ciphertext for encrypted single-destination packets, or plaintext for
//! announces / link requests / proofs). Encryption is handled by the layers
//! above (`identity`, `transport`, `link`).

use crate::constants::*;
use crate::crypto::full_hash;

/// Header layout selector.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeaderType {
    /// `[flags][hops][dest(16)][context][data]`
    One,
    /// `[flags][hops][transport_id(16)][dest(16)][context][data]`
    Two,
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub header_type: HeaderType,
    pub context_flag: bool,
    pub transport_type: u8,   // TRANSPORT_BROADCAST / TRANSPORT_TRANSPORT
    pub destination_type: u8, // DEST_SINGLE / DEST_GROUP / DEST_PLAIN / DEST_LINK
    pub packet_type: u8,      // PACKET_DATA / ANNOUNCE / LINKREQUEST / PROOF
    pub hops: u8,
    pub context: u8,
    /// For HEADER_2 this is the transport id, prepended before the destination.
    pub transport_id: Option<[u8; TRUNCATED_HASHLENGTH]>,
    /// Destination hash (or link id for link packets / proofs).
    pub destination_hash: [u8; TRUNCATED_HASHLENGTH],
    pub data: Vec<u8>,
}

impl Packet {
    /// Convenience constructor for a HEADER_1 broadcast packet.
    pub fn header1(
        destination_type: u8,
        packet_type: u8,
        context: u8,
        destination_hash: [u8; TRUNCATED_HASHLENGTH],
        data: Vec<u8>,
    ) -> Packet {
        Packet {
            header_type: HeaderType::One,
            context_flag: false,
            transport_type: TRANSPORT_BROADCAST,
            destination_type,
            packet_type,
            hops: 0,
            context,
            transport_id: None,
            destination_hash,
            data,
        }
    }

    fn packed_flags(&self) -> u8 {
        let ht = match self.header_type {
            HeaderType::One => HEADER_1,
            HeaderType::Two => HEADER_2,
        };
        let cf = if self.context_flag { FLAG_SET } else { FLAG_UNSET };
        (ht << 6) | (cf << 5) | (self.transport_type << 4) | (self.destination_type << 2) | self.packet_type
    }

    /// Serialize to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(HEADER_MAXSIZE() + self.data.len());
        raw.push(self.packed_flags());
        raw.push(self.hops);
        if self.header_type == HeaderType::Two {
            raw.extend_from_slice(&self.transport_id.expect("HEADER_2 requires transport_id"));
        }
        raw.extend_from_slice(&self.destination_hash);
        raw.push(self.context);
        raw.extend_from_slice(&self.data);
        raw
    }

    /// Parse from wire bytes.
    pub fn decode(raw: &[u8]) -> Result<Packet, &'static str> {
        if raw.len() < 2 + TRUNCATED_HASHLENGTH + 1 {
            return Err("packet too short");
        }
        let flags = raw[0];
        let hops = raw[1];
        let header_type = if (flags & 0b0100_0000) >> 6 == HEADER_2 { HeaderType::Two } else { HeaderType::One };
        let context_flag = (flags & 0b0010_0000) >> 5 == FLAG_SET;
        let transport_type = (flags & 0b0001_0000) >> 4;
        let destination_type = (flags & 0b0000_1100) >> 2;
        let packet_type = flags & 0b0000_0011;

        let dl = TRUNCATED_HASHLENGTH;
        let mut destination_hash = [0u8; TRUNCATED_HASHLENGTH];
        let (transport_id, ctx_off) = if header_type == HeaderType::Two {
            if raw.len() < 2 + 2 * dl + 1 {
                return Err("HEADER_2 packet too short");
            }
            let mut tid = [0u8; TRUNCATED_HASHLENGTH];
            tid.copy_from_slice(&raw[2..2 + dl]);
            destination_hash.copy_from_slice(&raw[2 + dl..2 + 2 * dl]);
            (Some(tid), 2 + 2 * dl)
        } else {
            destination_hash.copy_from_slice(&raw[2..2 + dl]);
            (None, 2 + dl)
        };
        let context = raw[ctx_off];
        let data = raw[ctx_off + 1..].to_vec();

        Ok(Packet {
            header_type,
            context_flag,
            transport_type,
            destination_type,
            packet_type,
            hops,
            context,
            transport_id,
            destination_hash,
            data,
        })
    }

    /// `get_hashable_part`: `(flags & 0x0F) || dest_hash || context || data`
    /// (transport_id excluded for HEADER_2). See `RNS/Packet.py`.
    pub fn hashable_part(&self) -> Vec<u8> {
        let raw = self.encode();
        let mut out = Vec::with_capacity(1 + raw.len());
        out.push(raw[0] & 0x0F);
        let skip = match self.header_type {
            HeaderType::One => 2,
            HeaderType::Two => TRUNCATED_HASHLENGTH + 2,
        };
        out.extend_from_slice(&raw[skip..]);
        out
    }

    /// Full SHA-256 packet hash over the hashable part (`get_hash`).
    pub fn packet_hash(&self) -> [u8; 32] {
        full_hash(&self.hashable_part())
    }

    /// Truncated (16-byte) packet hash, used as packet id / link id basis.
    pub fn truncated_hash(&self) -> [u8; TRUNCATED_HASHLENGTH] {
        let full = self.packet_hash();
        let mut out = [0u8; TRUNCATED_HASHLENGTH];
        out.copy_from_slice(&full[..TRUNCATED_HASHLENGTH]);
        out
    }
}

/// Maximum header size in bytes (`2 + 1 + 16*2`); function to avoid const-fn fuss.
#[allow(non_snake_case)]
pub fn HEADER_MAXSIZE() -> usize { 2 + 1 + TRUNCATED_HASHLENGTH * 2 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header1_roundtrip() {
        let p = Packet::header1(DEST_SINGLE, PACKET_DATA, CONTEXT_NONE, [0x11; 16], vec![1, 2, 3, 4]);
        let raw = p.encode();
        // flags, hops, dest(16), context, data(4)
        assert_eq!(raw.len(), 2 + 16 + 1 + 4);
        assert_eq!(raw[0], (HEADER_1 << 6) | (DEST_SINGLE << 2) | PACKET_DATA);
        let d = Packet::decode(&raw).unwrap();
        assert_eq!(d.header_type, HeaderType::One);
        assert_eq!(d.destination_type, DEST_SINGLE);
        assert_eq!(d.packet_type, PACKET_DATA);
        assert_eq!(d.destination_hash, [0x11; 16]);
        assert_eq!(d.data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn header2_roundtrip() {
        let mut p = Packet::header1(DEST_SINGLE, PACKET_ANNOUNCE, CONTEXT_NONE, [0x22; 16], vec![9, 9]);
        p.header_type = HeaderType::Two;
        p.transport_id = Some([0x33; 16]);
        let raw = p.encode();
        assert_eq!(raw.len(), 2 + 16 + 16 + 1 + 2);
        let d = Packet::decode(&raw).unwrap();
        assert_eq!(d.header_type, HeaderType::Two);
        assert_eq!(d.transport_id, Some([0x33; 16]));
        assert_eq!(d.destination_hash, [0x22; 16]);
    }

    #[test]
    fn announce_flags_value() {
        let p = Packet::header1(DEST_SINGLE, PACKET_ANNOUNCE, CONTEXT_NONE, [0; 16], vec![]);
        // header_type 0, ctx 0, transport 0, dest SINGLE(0), type ANNOUNCE(1)
        assert_eq!(p.encode()[0], 0x01);
    }
}
