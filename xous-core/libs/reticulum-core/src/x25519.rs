//! Pure-software X25519 (RFC 7748) — a faithful port of the public-domain
//! TweetNaCl `crypto_scalarmult`.
//!
//! Why this exists: on the Precursor, `curve25519-dalek` uses betrusted's
//! hardware engine backend (`u32e_backend`). Its Edwards/Ed25519 path is correct
//! (so announces and link proofs verify), but the **Montgomery ladder used by
//! X25519 ECDH computes the wrong result** — and the engine doesn't report an
//! error, so the library's software fallback never triggers. Every key derived
//! from `HKDF(SHA256, salt, ECDH_shared)` (link sessions + opportunistic
//! messages) was therefore wrong, failing HMAC verification, even though
//! everything signature-related worked.
//!
//! Doing the scalar multiplication in plain integer arithmetic here sidesteps the
//! engine entirely and matches the host bit-for-bit. Verified against the
//! RFC 7748 §5.2 test vector (see `lib::self_test`).

/// Field element: 16 limbs, radix 2^16, signed to allow lazy reduction.
type Gf = [i64; 16];

const GF_121665: Gf = [0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fn car25519(o: &mut Gf) {
    for i in 0..16 {
        o[i] += 1 << 16;
        let c = o[i] >> 16;
        let idx = if i < 15 { i + 1 } else { 0 };
        o[idx] += if i == 15 { 38 * (c - 1) } else { c - 1 };
        o[i] -= c << 16;
    }
}

/// Constant-time conditional swap of `p` and `q` when `b == 1`.
fn sel25519(p: &mut Gf, q: &mut Gf, b: i64) {
    let c = !(b - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn add(a: &Gf, b: &Gf) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
    o
}

fn sub(a: &Gf, b: &Gf) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
    o
}

fn mul(a: &Gf, b: &Gf) -> Gf {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o = [0i64; 16];
    o[..16].copy_from_slice(&t[..16]);
    car25519(&mut o);
    car25519(&mut o);
    o
}

fn sqr(a: &Gf) -> Gf {
    mul(a, a)
}

fn inv25519(input: &Gf) -> Gf {
    let mut c = *input;
    for a in (0..=253).rev() {
        c = sqr(&c);
        if a != 2 && a != 4 {
            c = mul(&c, input);
        }
    }
    c
}

fn unpack25519(n: &[u8; 32]) -> Gf {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = n[2 * i] as i64 + ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
    o
}

fn pack25519(n: &Gf) -> [u8; 32] {
    let mut t = *n;
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    for _ in 0..2 {
        let mut m: Gf = [0; 16];
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(&mut t, &mut m, 1 - b);
    }
    let mut o = [0u8; 32];
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = (t[i] >> 8) as u8;
    }
    o
}

/// X25519 scalar multiplication `q = scalarmult(scalar, point)`. The scalar is
/// clamped internally (RFC 7748), matching `x25519_dalek::StaticSecret`.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut z = *scalar;
    z[0] &= 248;
    z[31] = (z[31] & 127) | 64;

    let x = unpack25519(point);
    let mut a: Gf = [0; 16];
    let mut b: Gf = x;
    let mut c: Gf = [0; 16];
    let mut d: Gf = [0; 16];
    a[0] = 1;
    d[0] = 1;

    for i in (0..=254).rev() {
        let r = ((z[i >> 3] >> (i & 7)) & 1) as i64;
        sel25519(&mut a, &mut b, r);
        sel25519(&mut c, &mut d, r);
        let e1 = add(&a, &c);
        a = sub(&a, &c);
        c = add(&b, &d);
        b = sub(&b, &d);
        d = sqr(&e1);
        let f = sqr(&a);
        a = mul(&c, &a);
        c = mul(&b, &e1);
        let e2 = add(&a, &c);
        a = sub(&a, &c);
        b = sqr(&a);
        c = sub(&d, &f);
        a = mul(&c, &GF_121665);
        a = add(&a, &d);
        c = mul(&c, &a);
        a = mul(&d, &f);
        d = mul(&b, &x);
        b = sqr(&e2);
        sel25519(&mut a, &mut b, r);
        sel25519(&mut c, &mut d, r);
    }

    let cinv = inv25519(&c);
    let out = mul(&a, &cinv);
    pack25519(&out)
}

/// X25519 base-point multiplication: the public key for `scalar`.
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    x25519(scalar, &basepoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex32(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        o
    }

    #[test]
    fn rfc7748_vector() {
        let k = unhex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = unhex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let exp = unhex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519(&k, &u), exp);
    }

    #[test]
    fn dh_is_symmetric() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let pa = x25519_base(&a);
        let pb = x25519_base(&b);
        assert_eq!(x25519(&a, &pb), x25519(&b, &pa));
    }
}
