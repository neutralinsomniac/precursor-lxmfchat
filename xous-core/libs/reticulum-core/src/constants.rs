//! Constants lifted from the Reticulum reference implementation (RNS) so that
//! this client is wire-compatible. Values mirror `RNS/Reticulum.py`,
//! `RNS/Identity.py`, `RNS/Packet.py` and `RNS/Cryptography/Token.py`.

/// Maximum transmission unit of a single Reticulum packet, in bytes.
pub const MTU: usize = 500;

/// Truncated hash length in bits. Destination/address hashes are this many bits.
pub const TRUNCATED_HASHLENGTH_BITS: usize = 128;
/// Destination / address hash length, in bytes (16).
pub const TRUNCATED_HASHLENGTH: usize = TRUNCATED_HASHLENGTH_BITS / 8;

/// Length of the per-aspect name hash prepended into destination hashes (10 bytes).
pub const NAME_HASH_LENGTH: usize = 10;

/// Public key length: 32 byte X25519 (encryption) || 32 byte Ed25519 (signing).
pub const KEYSIZE: usize = 64;
/// X25519 / Ed25519 individual key length.
pub const KEY_HALF: usize = 32;
/// Length of an Ed25519 signature.
pub const SIG_LENGTH: usize = 64;
/// Length of an X25519 ratchet public key.
pub const RATCHET_SIZE: usize = 32;

/// HKDF output length used by `Identity.encrypt` (== KEYSIZE).
pub const DERIVED_KEY_LENGTH: usize = 64;

/// Token (Fernet-like) framing overhead: 16 byte IV + 32 byte HMAC.
pub const TOKEN_OVERHEAD: usize = 48;
pub const IV_LENGTH: usize = 16;
pub const HMAC_LENGTH: usize = 32;

// ---- Header field encodings (see RNS/Packet.py get_packed_flags) ----
// packed = (header_type<<6)|(context_flag<<5)|(transport_type<<4)|(destination_type<<2)|packet_type

pub const HEADER_1: u8 = 0x00; // one address field
pub const HEADER_2: u8 = 0x01; // two address fields (transport_id + destination)

pub const FLAG_UNSET: u8 = 0x00;
pub const FLAG_SET: u8 = 0x01;

// transport_type / propagation
pub const TRANSPORT_BROADCAST: u8 = 0x00;
pub const TRANSPORT_TRANSPORT: u8 = 0x01;

// destination_type (2 bits)
pub const DEST_SINGLE: u8 = 0x00;
pub const DEST_GROUP: u8 = 0x01;
pub const DEST_PLAIN: u8 = 0x02;
pub const DEST_LINK: u8 = 0x03;

// packet_type (2 bits)
pub const PACKET_DATA: u8 = 0x00;
pub const PACKET_ANNOUNCE: u8 = 0x01;
pub const PACKET_LINKREQUEST: u8 = 0x02;
pub const PACKET_PROOF: u8 = 0x03;

// ---- Context byte values (RNS/Packet.py) ----
pub const CONTEXT_NONE: u8 = 0x00;
pub const CONTEXT_RESOURCE: u8 = 0x01;
pub const CONTEXT_RESOURCE_ADV: u8 = 0x02;
pub const CONTEXT_RESOURCE_REQ: u8 = 0x03;
pub const CONTEXT_RESOURCE_HMU: u8 = 0x04;
pub const CONTEXT_RESOURCE_PRF: u8 = 0x05;
pub const CONTEXT_RESOURCE_ICL: u8 = 0x06;
pub const CONTEXT_RESOURCE_RCL: u8 = 0x07;
pub const CONTEXT_CACHE_REQUEST: u8 = 0x08;
pub const CONTEXT_REQUEST: u8 = 0x09;
pub const CONTEXT_RESPONSE: u8 = 0x0A;
pub const CONTEXT_PATH_RESPONSE: u8 = 0x0B;
pub const CONTEXT_COMMAND: u8 = 0x0C;
pub const CONTEXT_COMMAND_STATUS: u8 = 0x0D;
pub const CONTEXT_CHANNEL: u8 = 0x0E;
pub const CONTEXT_KEEPALIVE: u8 = 0xFA;
pub const CONTEXT_LINKIDENTIFY: u8 = 0xFB;
pub const CONTEXT_LINKCLOSE: u8 = 0xFC;
pub const CONTEXT_LINKPROOF: u8 = 0xFD;
pub const CONTEXT_LRRTT: u8 = 0xFE;
pub const CONTEXT_LRPROOF: u8 = 0xFF;

/// Interface Access Code salt (RNS/Reticulum.py IFAC_SALT).
pub const IFAC_SALT: [u8; 32] = [
    0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80, 0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
    0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f, 0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
];
