//! LXMF propagation-node proof-of-work **stamp**. A propagation node requires a
//! stamp on each stored message so that storing is costly (anti-spam). The stamp
//! is a 32-byte value such that `SHA-256(workblock || stamp)` has at least `cost`
//! leading zero bits, where `workblock` is a ~256 KB blob derived from the
//! message's transient id. Mirrors `LXMF/LXStamper.py`.
//!
//! The workblock is fixed and block-aligned while only the 32-byte stamp varies,
//! so we fold the workblock into a SHA-256 midstate **once** and then each mining
//! attempt is a single compression. That makes the propagation cost (13..16 bits)
//! practical on the Precursor — unlike a naive re-hash of the whole workblock per
//! attempt. We vendor the SHA-256 compression here (rather than using a `Digest`)
//! precisely so we can save/restore the midstate, which the hardware SHA backend
//! doesn't expose.

use reticulum_core::crypto::{full_hash, hkdf};

use crate::msgpack::{self, Value};

/// Rounds of HKDF expansion for a propagation-node workblock (LXStamper
/// `WORKBLOCK_EXPAND_ROUNDS_PN`). 1000 × 256 = 256 000 bytes = 4000 × 64, so the
/// workblock is exactly block-aligned (required for the midstate trick).
pub const WORKBLOCK_EXPAND_ROUNDS_PN: usize = 1000;

/// Rounds for a **delivery** stamp's workblock (LXStamper
/// `WORKBLOCK_EXPAND_ROUNDS`) — the stamp a recipient with a `stamp_cost`
/// demands on the message itself, mined over the message id.
pub const WORKBLOCK_EXPAND_ROUNDS_DELIVERY: usize = 3000;

/// Stamp length in bytes (RNS `HASHLENGTH`/8).
pub const STAMP_SIZE: usize = 32;

// ---- vendored SHA-256 compression --------------------------------------------

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Fold one 64-byte block into the SHA-256 state.
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let mut h = *state;
    for i in 0..64 {
        let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);
        let ch = (h[4] & h[5]) ^ ((!h[4]) & h[6]);
        let t1 = h[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
        let maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
        let t2 = s0.wrapping_add(maj);
        h[7] = h[6];
        h[6] = h[5];
        h[5] = h[4];
        h[4] = h[3].wrapping_add(t1);
        h[3] = h[2];
        h[2] = h[1];
        h[1] = h[0];
        h[0] = t1.wrapping_add(t2);
    }
    for i in 0..8 {
        state[i] = state[i].wrapping_add(h[i]);
    }
}

fn digest_leading_zeros(state: &[u32; 8]) -> u32 {
    let mut n = 0;
    for w in state {
        if *w == 0 {
            n += 32;
        } else {
            n += w.leading_zeros();
            break;
        }
    }
    n
}

// ---- workblock + stamp generation --------------------------------------------

/// Build the stamp workblock for `material` (the message's transient id),
/// mirroring `LXStamper.stamp_workblock`: for each round `n`, append
/// `HKDF(len=256, ikm=material, salt=SHA256(material || msgpack(n)), info=None)`.
pub fn stamp_workblock(material: &[u8], expand_rounds: usize) -> Vec<u8> {
    let mut wb = Vec::with_capacity(expand_rounds * 256);
    for n in 0..expand_rounds {
        let mut salt_input = Vec::with_capacity(material.len() + 5);
        salt_input.extend_from_slice(material);
        salt_input.extend_from_slice(&msgpack::encode(&Value::Int(n as i64)));
        let salt = full_hash(&salt_input);
        wb.extend_from_slice(&hkdf(256, material, Some(&salt), None));
    }
    wb
}

/// Generate a stamp of at least `cost` leading zero bits over the workblock
/// derived from `material` with `expand_rounds` rounds (PN: transient id ×
/// [`WORKBLOCK_EXPAND_ROUNDS_PN`]; delivery: message id ×
/// [`WORKBLOCK_EXPAND_ROUNDS_DELIVERY`]). Returns the 32-byte stamp. Cost
/// 8..16 is typically a few hundred to ~65k single-compression attempts after
/// the one-time workblock pass.
pub fn generate_stamp(material: &[u8], cost: u32, expand_rounds: usize) -> [u8; STAMP_SIZE] {
    // Fold the workblock into the midstate AS IT IS GENERATED — 256 B per
    // round, four 64-byte blocks — never materializing the whole thing
    // (256 KB for a PN stamp, 768 KB for a delivery stamp: a real allocation
    // hazard on the device).
    let mut midstate = H0;
    let mut block = [0u8; 64];
    for n in 0..expand_rounds {
        let mut salt_input = Vec::with_capacity(material.len() + 5);
        salt_input.extend_from_slice(material);
        salt_input.extend_from_slice(&msgpack::encode(&Value::Int(n as i64)));
        let salt = full_hash(&salt_input);
        for chunk in hkdf(256, material, Some(&salt), None).chunks_exact(64) {
            block.copy_from_slice(chunk);
            compress(&mut midstate, &block);
        }
    }

    // Final block: stamp(32) || 0x80 || zeros || bit-length(8, big-endian). The
    // stamp lands exactly at a block boundary (workblock is 64-aligned), so the
    // padded final block is one block.
    let bit_len = ((expand_rounds * 256 + STAMP_SIZE) as u64) * 8;
    let mut last = [0u8; 64];
    last[STAMP_SIZE] = 0x80;
    last[56..].copy_from_slice(&bit_len.to_be_bytes());

    let mut counter: u64 = 0;
    loop {
        last[0..8].copy_from_slice(&counter.to_be_bytes());
        let mut state = midstate;
        compress(&mut state, &last);
        if digest_leading_zeros(&state) >= cost {
            let mut stamp = [0u8; STAMP_SIZE];
            stamp.copy_from_slice(&last[0..STAMP_SIZE]);
            return stamp;
        }
        counter = counter.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_matches_full_hash_of_one_block() {
        // SHA-256 of a single padded block must equal full_hash of the message.
        // message = "abc" (3 bytes) → one padded block.
        let msg = b"abc";
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(msg);
        block[3] = 0x80;
        let bit_len = (msg.len() as u64) * 8;
        block[56..].copy_from_slice(&bit_len.to_be_bytes());
        let mut state = H0;
        compress(&mut state, &block);
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        assert_eq!(out, full_hash(msg));
    }

    #[test]
    fn generated_stamp_validates() {
        // Generate a low-cost stamp and confirm SHA256(workblock||stamp) has the
        // required leading zeros (self-consistency; cross-checked vs Python in the
        // interop test).
        let material = [0x42u8; 32];
        let cost = 8;
        // The streaming (never-materialized) midstate fold must agree with a
        // hash of the materialized workblock — this asserts both the stamp
        // and that equivalence.
        let stamp = generate_stamp(&material, cost, WORKBLOCK_EXPAND_ROUNDS_PN);
        let workblock = stamp_workblock(&material, WORKBLOCK_EXPAND_ROUNDS_PN);
        let mut combined = workblock;
        combined.extend_from_slice(&stamp);
        let digest = full_hash(&combined);
        let mut lz = 0u32;
        for b in digest {
            if b == 0 {
                lz += 8;
            } else {
                lz += b.leading_zeros(); // u8::leading_zeros is 0..=8
                break;
            }
        }
        assert!(lz >= cost, "stamp only had {lz} leading zero bits, need {cost}");
    }
}
