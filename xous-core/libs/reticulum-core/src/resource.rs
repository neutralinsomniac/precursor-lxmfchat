//! Reticulum **Resource** receiver — enough to download an LXMF propagation-node
//! message sync (the node returns the stored messages as a Resource over the
//! link). Mirrors the receiver half of `RNS/Resource.py`.
//!
//! A Resource transfers an arbitrary blob that doesn't fit a single packet:
//! 1. the sender link-encrypts `random_prefix(4) || [bz2?]payload` and splits the
//!    ciphertext into `sdu`-sized **parts**;
//! 2. it sends a `RESOURCE_ADV` advertisement (a umsgpack map) carrying the
//!    resource hash, part count, and a **hashmap** (one 4-byte map-hash per part);
//! 3. the receiver requests parts by map-hash via `RESOURCE_REQ`, collects the
//!    `RESOURCE` part packets (raw ciphertext chunks), reassembles in order,
//!    link-decrypts the whole stream, strips the prefix, verifies the hash, and
//!    returns a `RESOURCE_PRF` proof.
//!
//! Scope: **single-segment** resources (≤ `HASHMAP_MAX_LEN` ≈ 74 parts, ≈ 31 KB
//! of transfer) — which comfortably covers a normal LXMF sync batch or direct
//! message. The whole hashmap then fits in the advertisement, so no
//! `RESOURCE_HMU` round-trips are needed and every part is in the sender's serve
//! window, letting us request them all at once. Multi-segment resources are
//! detected and rejected. bz2-compressed resources ARE handled: RNS
//! auto-compresses when it shrinks the payload — the norm for large *text*
//! direct messages (propagation-sync blobs are encrypted → incompressible →
//! sent uncompressed). The resource hash and proof are computed over the
//! **decompressed** payload (`RNS/Resource.py` `assemble`).

use crate::crypto::full_hash;

/// Upper bound on a decompressed payload, so a malicious bz2 bomb inside a
/// ≤31 KB transfer can't balloon into an enormous allocation on the device.
/// Generous vs. anything the chat UI can display (a dialogue's whole byte
/// budget is 56 KB).
const DECOMPRESSED_MAX: u64 = 256 * 1024;

/// Bytes per map-hash (`Resource.MAPHASH_LEN`).
const MAPHASH_LEN: usize = 4;
/// Random-hash size, both the stream prefix and the hash salt (`RANDOM_HASH_SIZE`).
const RANDOM_HASH_SIZE: usize = 4;
/// `HASHMAP_IS_NOT_EXHAUSTED` flag byte for a `RESOURCE_REQ` (full hashmap known).
const HASHMAP_NOT_EXHAUSTED: u8 = 0x00;

/// Parsed `RESOURCE_ADV` advertisement (the subset we need). Mirrors the umsgpack
/// map produced by `RNS.ResourceAdvertisement.pack` (string keys).
struct Advertisement {
    /// Resource hash `h` (full SHA-256 of `payload || r`).
    hash: [u8; 32],
    /// Random hash `r` — salt for the resource + part map-hashes.
    random_hash: Vec<u8>,
    /// Number of parts `n`.
    parts: usize,
    /// Hashmap `m`: `n` concatenated 4-byte map-hashes (this segment).
    hashmap: Vec<u8>,
    /// Total segments `l`.
    total_segments: u64,
    /// `compressed` flag (bit 1 of `f`).
    compressed: bool,
    /// `encrypted` flag (bit 0 of `f`).
    encrypted: bool,
}

/// State of an in-progress single-segment Resource download.
pub struct ResourceReceiver {
    hash: [u8; 32],
    random_hash: Vec<u8>,
    /// Per-part 4-byte map-hashes (parsed from the advertisement hashmap).
    map_hashes: Vec<[u8; MAPHASH_LEN]>,
    /// Received part data by index; `None` until that part arrives.
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
    encrypted: bool,
    compressed: bool,
}

impl ResourceReceiver {
    /// Parse a `RESOURCE_ADV` plaintext and set up the receiver. Returns an error
    /// for the cases we don't handle (multi-segment, compressed, malformed).
    pub fn accept(adv_plaintext: &[u8]) -> Result<ResourceReceiver, &'static str> {
        let adv = parse_advertisement(adv_plaintext)?;
        if adv.total_segments > 1 {
            return Err("multi-segment resource not supported");
        }
        if adv.parts == 0 || adv.hashmap.len() < adv.parts * MAPHASH_LEN {
            return Err("resource advertisement hashmap too short");
        }
        let mut map_hashes = Vec::with_capacity(adv.parts);
        for i in 0..adv.parts {
            let mut h = [0u8; MAPHASH_LEN];
            h.copy_from_slice(&adv.hashmap[i * MAPHASH_LEN..(i + 1) * MAPHASH_LEN]);
            map_hashes.push(h);
        }
        Ok(ResourceReceiver {
            hash: adv.hash,
            random_hash: adv.random_hash,
            map_hashes,
            parts: vec![None; adv.parts],
            received: 0,
            encrypted: adv.encrypted,
            compressed: adv.compressed,
        })
    }

    /// Whether the assembled stream must be link-decrypted (always true for a
    /// resource sent over a link, but we respect the advertised flag).
    pub fn encrypted(&self) -> bool { self.encrypted }

    /// Build a `RESOURCE_REQ` payload requesting every still-missing part:
    /// `0x00 || resource_hash(32) || missing map-hashes`. For a single-segment
    /// resource all parts are in the sender's serve window, so one request
    /// suffices; re-call after a timeout to re-request whatever is still missing.
    pub fn request_data(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + self.parts.len() * MAPHASH_LEN);
        out.push(HASHMAP_NOT_EXHAUSTED);
        out.extend_from_slice(&self.hash);
        for (i, slot) in self.parts.iter().enumerate() {
            if slot.is_none() {
                out.extend_from_slice(&self.map_hashes[i]);
            }
        }
        out
    }

    /// Ingest a raw `RESOURCE` part (the still-encrypted chunk). Computes the
    /// part's map-hash (`full_hash(part || r)[:4]`) and stores it at the matching
    /// index; ignores unknown/duplicate parts.
    pub fn receive_part(&mut self, part_data: &[u8]) {
        let mut salted = Vec::with_capacity(part_data.len() + self.random_hash.len());
        salted.extend_from_slice(part_data);
        salted.extend_from_slice(&self.random_hash);
        let digest = full_hash(&salted);
        let map_hash = &digest[..MAPHASH_LEN];
        for (i, mh) in self.map_hashes.iter().enumerate() {
            if mh == map_hash {
                if self.parts[i].is_none() {
                    self.parts[i] = Some(part_data.to_vec());
                    self.received += 1;
                }
                return;
            }
        }
    }

    /// True once every part has arrived.
    pub fn is_complete(&self) -> bool { self.received == self.parts.len() }

    /// Concatenate the received parts into the (still-encrypted) stream. Only
    /// meaningful once [`Self::is_complete`].
    pub fn concat(&self) -> Vec<u8> {
        let mut stream = Vec::new();
        for slot in &self.parts {
            if let Some(p) = slot {
                stream.extend_from_slice(p);
            }
        }
        stream
    }

    /// Finish the transfer from the (already link-decrypted, if [`Self::encrypted`])
    /// stream: strip the 4-byte random prefix, bz2-decompress if the sender
    /// compressed, verify `full_hash(payload || r) == hash`, and return
    /// `(payload, proof_data)` where `proof_data = hash || full_hash(payload ||
    /// hash)` for a `RESOURCE_PRF` proof packet. Hash and proof are over the
    /// decompressed payload, exactly as `RNS/Resource.py` computes them.
    pub fn finish(&self, stream_plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        if stream_plaintext.len() < RANDOM_HASH_SIZE {
            return Err("resource stream shorter than random prefix");
        }
        let payload = if self.compressed {
            decompress_bz2(&stream_plaintext[RANDOM_HASH_SIZE..])?
        } else {
            stream_plaintext[RANDOM_HASH_SIZE..].to_vec()
        };

        let mut salted = Vec::with_capacity(payload.len() + self.random_hash.len());
        salted.extend_from_slice(&payload);
        salted.extend_from_slice(&self.random_hash);
        if full_hash(&salted) != self.hash {
            return Err("resource hash mismatch");
        }

        let mut proof_salted = Vec::with_capacity(payload.len() + self.hash.len());
        proof_salted.extend_from_slice(&payload);
        proof_salted.extend_from_slice(&self.hash);
        let mut proof_data = Vec::with_capacity(self.hash.len() + 32);
        proof_data.extend_from_slice(&self.hash);
        proof_data.extend_from_slice(&full_hash(&proof_salted));
        Ok((payload, proof_data))
    }
}

/// bz2-decompress a resource payload, bounded by [`DECOMPRESSED_MAX`].
fn decompress_bz2(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    use std::io::Read;
    let mut out = Vec::new();
    let mut decoder = bzip2_rs::DecoderReader::new(data).take(DECOMPRESSED_MAX + 1);
    match decoder.read_to_end(&mut out) {
        Ok(_) if out.len() as u64 > DECOMPRESSED_MAX => Err("decompressed resource too large"),
        Ok(_) => Ok(out),
        Err(_) => Err("resource bz2 decompression failed"),
    }
}

// ---- minimal umsgpack advertisement parser -----------------------------------

/// Walk the advertisement umsgpack map (string keys) and pull the fields we need.
/// Handles the encodings RNS emits: fixmap/map16, fixstr keys, (u)int values,
/// bin8/16/32 values. Mirrors `ResourceAdvertisement.unpack`.
fn parse_advertisement(data: &[u8]) -> Result<Advertisement, &'static str> {
    let mut p = Reader { b: data, i: 0 };
    let n = p.map_len()?;

    let mut hash: Option<Vec<u8>> = None;
    let mut random_hash: Option<Vec<u8>> = None;
    let mut hashmap: Option<Vec<u8>> = None;
    let mut parts: Option<u64> = None;
    let mut total_segments: u64 = 1;
    let mut flags: u64 = 0;

    for _ in 0..n {
        let key = p.str_key()?;
        match key {
            b"h" => hash = Some(p.bin()?),
            b"r" => random_hash = Some(p.bin()?),
            b"m" => hashmap = Some(p.bin()?),
            b"n" => parts = Some(p.uint()?),
            b"l" => total_segments = p.uint()?,
            b"f" => flags = p.uint()?,
            // t, d, o, i, q — present but unused here; skip their values.
            _ => p.skip_value()?,
        }
    }

    let hash = hash.ok_or("advertisement missing hash")?;
    if hash.len() != 32 {
        return Err("advertisement hash wrong length");
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&hash);
    Ok(Advertisement {
        hash: h,
        random_hash: random_hash.ok_or("advertisement missing random hash")?,
        parts: parts.ok_or("advertisement missing part count")? as usize,
        hashmap: hashmap.ok_or("advertisement missing hashmap")?,
        total_segments,
        encrypted: (flags & 0x01) == 0x01,
        compressed: ((flags >> 1) & 0x01) == 0x01,
    })
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8, &'static str> {
        let v = *self.b.get(self.i).ok_or("msgpack truncated")?;
        self.i += 1;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        if self.i + n > self.b.len() {
            return Err("msgpack truncated");
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn be(&mut self, n: usize) -> Result<u64, &'static str> {
        let mut v = 0u64;
        for b in self.take(n)? {
            v = (v << 8) | *b as u64;
        }
        Ok(v)
    }
    fn map_len(&mut self) -> Result<usize, &'static str> {
        let m = self.u8()?;
        match m {
            0x80..=0x8f => Ok((m & 0x0f) as usize),
            0xde => Ok(self.be(2)? as usize),
            0xdf => Ok(self.be(4)? as usize),
            _ => Err("expected msgpack map"),
        }
    }
    fn str_key(&mut self) -> Result<&'a [u8], &'static str> {
        let m = self.u8()?;
        let len = match m {
            0xa0..=0xbf => (m & 0x1f) as usize,
            0xd9 => self.u8()? as usize,
            0xda => self.be(2)? as usize,
            0xdb => self.be(4)? as usize,
            _ => return Err("expected msgpack string key"),
        };
        self.take(len)
    }
    fn bin(&mut self) -> Result<Vec<u8>, &'static str> {
        let m = self.u8()?;
        let len = match m {
            0xc4 => self.u8()? as usize,
            0xc5 => self.be(2)? as usize,
            0xc6 => self.be(4)? as usize,
            // RNS uses bin for byte fields, but tolerate str-encoded too.
            0xa0..=0xbf => (m & 0x1f) as usize,
            _ => return Err("expected msgpack bin"),
        };
        Ok(self.take(len)?.to_vec())
    }
    fn uint(&mut self) -> Result<u64, &'static str> {
        let m = self.u8()?;
        match m {
            0x00..=0x7f => Ok(m as u64),
            0xcc => Ok(self.u8()? as u64),
            0xcd => self.be(2),
            0xce => self.be(4),
            0xcf => self.be(8),
            // small negatives shouldn't appear for these fields; treat as 0.
            0xe0..=0xff => Ok(0),
            _ => Err("expected msgpack uint"),
        }
    }
    /// Skip one value of any type we might encounter in the advertisement.
    fn skip_value(&mut self) -> Result<(), &'static str> {
        let m = self.u8()?;
        match m {
            0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => Ok(()),
            0xcc | 0xd0 => { self.u8()?; Ok(()) }
            0xcd | 0xd1 => { self.be(2)?; Ok(()) }
            0xce | 0xd2 => { self.be(4)?; Ok(()) }
            0xcf | 0xd3 => { self.be(8)?; Ok(()) }
            0xca => { self.take(4)?; Ok(()) }
            0xcb => { self.take(8)?; Ok(()) }
            0xa0..=0xbf => { let l = (m & 0x1f) as usize; self.take(l)?; Ok(()) }
            0xd9 => { let l = self.u8()? as usize; self.take(l)?; Ok(()) }
            0xda => { let l = self.be(2)? as usize; self.take(l)?; Ok(()) }
            0xdb => { let l = self.be(4)? as usize; self.take(l)?; Ok(()) }
            0xc4 => { let l = self.u8()? as usize; self.take(l)?; Ok(()) }
            0xc5 => { let l = self.be(2)? as usize; self.take(l)?; Ok(()) }
            0xc6 => { let l = self.be(4)? as usize; self.take(l)?; Ok(()) }
            _ => Err("unsupported msgpack value in advertisement"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Token;
    use crate::constants::DERIVED_KEY_LENGTH;

    /// Build a single-segment `RESOURCE_ADV` umsgpack map the way RNS does, for the
    /// fields the receiver reads (`h, r, m, n, l, f`).
    fn build_adv(hash: &[u8; 32], r: &[u8; 4], hashmap: &[u8], n: usize, flags: u8) -> Vec<u8> {
        fn bin8(out: &mut Vec<u8>, b: &[u8]) {
            out.push(0xc4);
            out.push(b.len() as u8);
            out.extend_from_slice(b);
        }
        fn key(out: &mut Vec<u8>, k: u8) {
            out.push(0xa1);
            out.push(k);
        }
        let mut out = vec![0x86]; // fixmap, 6 entries
        key(&mut out, b'h'); bin8(&mut out, hash);
        key(&mut out, b'r'); bin8(&mut out, r);
        key(&mut out, b'm'); bin8(&mut out, hashmap);
        key(&mut out, b'n'); out.push(n as u8); // n < 128 → fixint
        key(&mut out, b'l'); out.push(1u8);
        key(&mut out, b'f'); out.push(flags);
        out
    }

    #[test]
    fn receives_and_assembles_a_resource() {
        // Construct a resource exactly as an RNS sender would.
        let key = [0x5a_u8; DERIVED_KEY_LENGTH];
        let payload: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();

        // stream_plaintext = random_prefix(4) || payload ; then link-encrypt whole.
        let prefix = [0xAA, 0xBB, 0xCC, 0xDD];
        let mut stream_plain = Vec::new();
        stream_plain.extend_from_slice(&prefix);
        stream_plain.extend_from_slice(&payload);
        let ciphertext = Token::new(&key).unwrap().encrypt_with_iv(&stream_plain, &[0x11; 16]);

        // Resource hash + random hash salt.
        let r = [0x01u8, 0x02, 0x03, 0x04];
        let mut hsalt = payload.clone();
        hsalt.extend_from_slice(&r);
        let hash = full_hash(&hsalt);

        // Split the CIPHERTEXT into parts and build the hashmap of part map-hashes.
        let sdu = 100usize;
        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut hashmap = Vec::new();
        for chunk in ciphertext.chunks(sdu) {
            parts.push(chunk.to_vec());
            let mut salted = chunk.to_vec();
            salted.extend_from_slice(&r);
            hashmap.extend_from_slice(&full_hash(&salted)[..MAPHASH_LEN]);
        }
        let n = parts.len();
        let adv = build_adv(&hash, &r, &hashmap, n, 0x01); // encrypted, not compressed

        let mut rx = ResourceReceiver::accept(&adv).expect("accept advertisement");
        assert!(rx.encrypted());
        // The request lists all parts (1 flag + 32 hash + n*4 hashes).
        assert_eq!(rx.request_data().len(), 1 + 32 + n * MAPHASH_LEN);

        // Deliver parts OUT OF ORDER — receive_part must place each by map-hash.
        let mut order: Vec<usize> = (0..n).collect();
        order.reverse();
        for idx in order {
            rx.receive_part(&parts[idx]);
        }
        assert!(rx.is_complete());
        assert_eq!(rx.concat(), ciphertext, "reassembled stream must match");

        // Decrypt the whole stream, finish, and check the payload + proof.
        let decrypted = Token::new(&key).unwrap().decrypt(&rx.concat()).expect("token");
        let (got, proof) = rx.finish(&decrypted).expect("finish");
        assert_eq!(got, payload, "recovered payload must match");

        let mut proof_salted = payload.clone();
        proof_salted.extend_from_slice(&hash);
        let mut expected_proof = hash.to_vec();
        expected_proof.extend_from_slice(&full_hash(&proof_salted));
        assert_eq!(proof, expected_proof, "RESOURCE_PRF proof data must match");
    }

    #[test]
    fn decompresses_a_bz2_compressed_resource() {
        // RNS compresses with Python's bz2; this vector is bz2.compress() of the
        // payload below, generated with the reference implementation.
        let payload: Vec<u8> = b"reticulum resource test payload ".repeat(40);
        let comp = hexdec(
            "425a6839314159265359096f7be00001c1918040002e26de202000902980000a551a9a36534f53c13b13a1\
             3d89913427d1342644d09813227027026c4d84fc26c4d89813809e04c09c89c89d89d09e09a13f8bb9229c\
             284804b7bdf000",
        );

        // The sender prefixes + link-encrypts the COMPRESSED data, but hashes the
        // ORIGINAL payload (RNS/Resource.py: hash = full_hash(data + random_hash)
        // where `data` is pre-compression; assemble() verifies post-decompress).
        let key = [0x77_u8; DERIVED_KEY_LENGTH];
        let prefix = [0x10, 0x20, 0x30, 0x40];
        let mut stream_plain = prefix.to_vec();
        stream_plain.extend_from_slice(&comp);
        let ciphertext = Token::new(&key).unwrap().encrypt_with_iv(&stream_plain, &[0x22; 16]);

        let r = [0x05u8, 0x06, 0x07, 0x08];
        let mut hsalt = payload.clone();
        hsalt.extend_from_slice(&r);
        let hash = full_hash(&hsalt);

        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut hashmap = Vec::new();
        for chunk in ciphertext.chunks(50) {
            parts.push(chunk.to_vec());
            let mut salted = chunk.to_vec();
            salted.extend_from_slice(&r);
            hashmap.extend_from_slice(&full_hash(&salted)[..MAPHASH_LEN]);
        }
        let adv = build_adv(&hash, &r, &hashmap, parts.len(), 0x03); // encrypted | compressed

        let mut rx = ResourceReceiver::accept(&adv).expect("accept compressed advertisement");
        for p in &parts {
            rx.receive_part(p);
        }
        assert!(rx.is_complete());
        let decrypted = Token::new(&key).unwrap().decrypt(&rx.concat()).expect("token");
        let (got, proof) = rx.finish(&decrypted).expect("finish");
        assert_eq!(got, payload, "decompressed payload must match the original");

        let mut proof_salted = payload.clone();
        proof_salted.extend_from_slice(&hash);
        let mut expected_proof = hash.to_vec();
        expected_proof.extend_from_slice(&full_hash(&proof_salted));
        assert_eq!(proof, expected_proof, "proof must be over the decompressed payload");
    }

    #[test]
    fn rejects_multisegment_and_bz2_bombs() {
        let hash = [0u8; 32];
        let r = [0u8; 4];
        let hashmap = [0u8; 4];
        // multi-segment (l = 2) → rejected.
        let mut adv = build_adv(&hash, &r, &hashmap, 1, 0x01);
        let lpos = adv.len() - 4; // ...key('l') 1 key('f') flags — patch l's value
        assert_eq!(adv[lpos], 1);
        adv[lpos] = 2;
        assert!(ResourceReceiver::accept(&adv).is_err());
        // compressed (bit 1) alone is fine now.
        assert!(ResourceReceiver::accept(&build_adv(&hash, &r, &hashmap, 1, 0x03)).is_ok());
        // a decompression result over the cap is rejected, not allocated:
        // bz2 of 1 MB of zeros (tiny input, huge output) must error out.
        // bz2.compress(b"\0" * (1024*1024)) — 45 bytes in, 1 MB out (> the cap).
        let bomb = hexdec(
            "425a683931415926535938571ce50008084000c0040008200030cc0529a60806c4201e2ee48a70a12070\
             ae39ca",
        );
        assert_eq!(decompress_bz2(&bomb), Err("decompressed resource too large"));
    }

    fn hexdec(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
