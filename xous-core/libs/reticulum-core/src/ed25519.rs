//! Pure-software Ed25519 signature **verification** — a faithful port of the
//! public-domain TweetNaCl `crypto_sign_open` core (verify only; we keep
//! signing on `ed25519-dalek`).
//!
//! Why this exists: on the Precursor, `ed25519-dalek` uses betrusted's hardware
//! engine backend. Signing is fast and correct, but **verification through the
//! engine takes tens of seconds per call** on this device — and announce
//! validation runs under the transport lock, so one inbound announce stalled
//! the sync state machine, sends, everything (the engine's Montgomery/X25519
//! path was already proven wrong and replaced in [`crate::x25519`]; this is the
//! same escape hatch for the verify path). Software verify here is the same
//! cost class as the X25519 port, which the device handles comfortably in the
//! per-packet hot path.
//!
//! Field arithmetic is shared with [`crate::x25519`] (same TweetNaCl `Gf`
//! representation). Verified against the RFC 8032 §7.1 test vectors and the
//! live Python-RNS interop announce (host tests).

use crate::x25519::{add as gf_add, inv25519, mul, pack25519, sel25519, sqr, sub as gf_sub, unpack25519, Gf};

const GF0: Gf = [0; 16];
const GF1: Gf = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// Edwards curve constant d.
const D: Gf = [
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
    0xfe73, 0x2b6f, 0x6cee, 0x5203,
];
/// 2·d.
const D2: Gf = [
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406,
];
/// Base point x.
const X: Gf = [
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
    0x53fe, 0xcd6e, 0x36d3, 0x2169,
];
/// Base point y.
const Y: Gf = [
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
];
/// sqrt(-1).
const I: Gf = [
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
    0xdf0b, 0x4fc1, 0x2480, 0x2b83,
];
/// Group order l (little-endian bytes as i64s, for modL).
const L: [i64; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// Extended Edwards point (X, Y, Z, T).
type Point = [Gf; 4];

/// p += q? No — TweetNaCl `add(p,q)`: p = p + q (extended coordinates).
fn point_add(p: &mut Point, q: &Point) {
    let mut a = mul(&gf_sub(&p[1], &p[0]), &gf_sub(&q[1], &q[0]));
    let b = mul(&gf_add(&p[0], &p[1]), &gf_add(&q[0], &q[1]));
    let c = mul(&mul(&p[3], &q[3]), &D2);
    let d = {
        let zz = mul(&p[2], &q[2]);
        gf_add(&zz, &zz)
    };
    let e = gf_sub(&b, &a);
    let f = gf_sub(&d, &c);
    let g = gf_add(&d, &c);
    let h = gf_add(&b, &a);
    a = e; // keep names aligned with the reference
    p[0] = mul(&a, &f);
    p[1] = mul(&h, &g);
    p[2] = mul(&g, &f);
    p[3] = mul(&a, &h);
}

fn cswap(p: &mut Point, q: &mut Point, b: i64) {
    for i in 0..4 {
        sel25519(&mut p[i], &mut q[i], b);
    }
}

/// Sign bit of the x coordinate.
fn par25519(a: &Gf) -> u8 {
    pack25519(a)[0] & 1
}

/// Vartime equality on packed representations (public data only).
fn neq25519(a: &Gf, b: &Gf) -> bool {
    pack25519(a) != pack25519(b)
}

fn pack_point(p: &Point) -> [u8; 32] {
    let zi = inv25519(&p[2]);
    let tx = mul(&p[0], &zi);
    let ty = mul(&p[1], &zi);
    let mut r = pack25519(&ty);
    r[31] ^= par25519(&tx) << 7;
    r
}

/// x^(2^252 - 3), for the square root in point decompression.
fn pow2523(input: &Gf) -> Gf {
    let mut c = *input;
    for a in (0..=250).rev() {
        c = sqr(&c);
        if a != 1 {
            c = mul(&c, input);
        }
    }
    c
}

/// Returns s · q (TweetNaCl `scalarmult`; `q` is clobbered, as in the original).
fn scalarmult(q: &mut Point, s: &[u8; 32]) -> Point {
    let mut p: Point = [GF0, GF1, GF1, GF0];
    for i in (0..=255).rev() {
        let b = ((s[i / 8] >> (i & 7)) & 1) as i64;
        cswap(&mut p, q, b);
        let pc = p;
        point_add(q, &pc); // q = q + p
        point_add(&mut p, &pc); // p = 2p
        cswap(&mut p, q, b);
    }
    p
}

/// p = s · B (base point).
fn scalarbase(s: &[u8; 32]) -> Point {
    let mut q: Point = [X, Y, GF1, mul(&X, &Y)];
    scalarmult(&mut q, s)
}

/// Decompress a public key / R value into a NEGATED point (TweetNaCl
/// `unpackneg`). Returns None if the bytes aren't a curve point.
fn unpackneg(p: &[u8; 32]) -> Option<Point> {
    let mut r: Point = [GF0, GF0, GF1, GF0];
    r[1] = unpack25519(p);
    let num0 = sqr(&r[1]);
    let den0 = mul(&num0, &D);
    let num = gf_sub(&num0, &r[2]);
    let den = gf_add(&r[2], &den0);

    let den2 = sqr(&den);
    let den4 = sqr(&den2);
    let den6 = mul(&den4, &den2);
    let mut t = mul(&den6, &num);
    t = mul(&t, &den);
    t = pow2523(&t);
    t = mul(&t, &num);
    t = mul(&t, &den);
    t = mul(&t, &den);
    r[0] = mul(&t, &den);

    let mut chk = sqr(&r[0]);
    chk = mul(&chk, &den);
    if neq25519(&chk, &num) {
        r[0] = mul(&r[0], &I);
    }
    let mut chk = sqr(&r[0]);
    chk = mul(&chk, &den);
    if neq25519(&chk, &num) {
        return None;
    }
    if par25519(&r[0]) == (p[31] >> 7) {
        r[0] = gf_sub(&GF0, &r[0]);
    }
    r[3] = mul(&r[0], &r[1]);
    Some(r)
}

/// Reduce a 64-byte value mod the group order l, in place over the first 32
/// bytes (TweetNaCl `reduce`/`modL`).
fn reduce(h: &[u8; 64]) -> [u8; 32] {
    let mut x = [0i64; 64];
    for i in 0..64 {
        x[i] = h[i] as i64;
    }
    let mut r = [0u8; 32];
    modl(&mut r, &mut x);
    r
}

fn modl(r: &mut [u8; 32], x: &mut [i64; 64]) {
    for i in (32..64).rev() {
        let mut carry = 0i64;
        for j in (i - 32)..(i - 12) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[i - 12] += carry;
        x[i] = 0;
    }
    let mut carry = 0i64;
    for j in 0..32 {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for j in 0..32 {
        x[j] -= carry * L[j];
    }
    for i in 0..32 {
        x[i + 1] += x[i] >> 8;
        r[i] = (x[i] & 255) as u8;
    }
}

/// Verify a detached Ed25519 signature. `true` iff valid.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let q = match unpackneg(public_key) {
        Some(q) => q,
        None => return false,
    };

    // h = SHA-512(R || A || M) mod l
    let mut preimage = Vec::with_capacity(64 + message.len());
    preimage.extend_from_slice(&signature[..32]);
    preimage.extend_from_slice(public_key);
    preimage.extend_from_slice(message);
    let h = reduce(&sha512(&preimage));

    // P = h·(-A) + s·B ; valid iff pack(P) == R
    let mut qq = q;
    let mut p = scalarmult(&mut qq, &h);
    let s: [u8; 32] = signature[32..].try_into().unwrap();
    let sb = scalarbase(&s);
    point_add(&mut p, &sb);
    let t = pack_point(&p);
    t == signature[..32]
}

// ---- SHA-512 (FIPS 180-4), software ------------------------------------------
// Self-contained so verification never touches the hardware hash engine either.

const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];
    // Padded message: data || 0x80 || zeros || 128-bit big-endian bit length.
    let bitlen = (data.len() as u128) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 128 != 112 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    let mut w = [0u64; 80];
    for block in msg.chunks_exact(128) {
        for i in 0..16 {
            w[i] = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 64];
    for i in 0..8 {
        out[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sha512_matches_fips_vector() {
        // FIPS 180-4 "abc" vector.
        let d = sha512(b"abc");
        assert_eq!(
            d.to_vec(),
            unhex(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }

    #[test]
    fn rfc8032_test_vectors_verify() {
        // RFC 8032 §7.1 TEST 1 (empty message).
        let pk: [u8; 32] =
            unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").try_into().unwrap();
        let sig: [u8; 64] = unhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .try_into()
        .unwrap();
        assert!(verify(&pk, b"", &sig));

        // RFC 8032 §7.1 TEST 2 (one-byte message 0x72).
        let pk2: [u8; 32] =
            unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c").try_into().unwrap();
        let sig2: [u8; 64] = unhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        )
        .try_into()
        .unwrap();
        assert!(verify(&pk2, &[0x72], &sig2));

        // TEST 3 (two-byte message af82).
        let pk3: [u8; 32] =
            unhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025").try_into().unwrap();
        let sig3: [u8; 64] = unhex(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        )
        .try_into()
        .unwrap();
        assert!(verify(&pk3, &unhex("af82"), &sig3));

        // Tampered signature must fail.
        let mut bad = sig3;
        bad[0] ^= 1;
        assert!(!verify(&pk3, &unhex("af82"), &bad));
        // Wrong message must fail.
        assert!(!verify(&pk3, &unhex("af83"), &sig3));
    }

    #[test]
    fn verifies_dalek_signature() {
        // Cross-check against ed25519-dalek signing (software on the host).
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let msg = b"interoperability between dalek sign and tweetnacl verify";
        let sig = sk.sign(msg).to_bytes();
        let pk = sk.verifying_key().to_bytes();
        assert!(verify(&pk, msg, &sig));
        assert!(!verify(&pk, b"other message", &sig));
    }
}
