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
//! The advertisement only carries the first **page** of map-hashes
//! (`HASHMAP_MAX_LEN` = 74), and a sender only serves parts near the
//! receiver's progress — so larger transfers are driven by the receiver:
//! parts are requested in **windows** (slow-start, like
//! `Resource.request_next`), and when the known hashmap runs out the request
//! carries a `HASHMAP_IS_EXHAUSTED` flag and the sender answers with a
//! `RESOURCE_HMU` (hashmap update) carrying the next page. This receiver
//! implements both, so a transfer is bounded by [`MAX_TRANSFER_BYTES`]
//! (device memory), not by the advertisement size.
//!
//! Still rejected: resources **split across multiple Resource segments** —
//! RNS only splits above `MAX_EFFICIENT_SIZE` (1 MiB), beyond what the
//! Precursor can buffer anyway. bz2-compressed resources ARE handled: RNS
//! auto-compresses when it shrinks the payload — the norm for large *text*
//! direct messages (propagation-sync blobs are encrypted → incompressible →
//! sent uncompressed). The resource hash and proof are computed over the
//! **decompressed** payload (`RNS/Resource.py` `assemble`).

use crate::crypto::full_hash;

/// Upper bound on a decompressed payload, so a malicious bz2 bomb can't
/// balloon into an enormous allocation on the device.
const DECOMPRESSED_MAX: u64 = 256 * 1024;

/// Upper bound on the (encrypted) transfer itself: parts buffer + reassembled
/// stream both live in RAM, so this is a device-memory budget, not a protocol
/// limit. ~600 parts.
pub const MAX_TRANSFER_BYTES: usize = 256 * 1024;

/// Bytes per map-hash (`Resource.MAPHASH_LEN`).
const MAPHASH_LEN: usize = 4;
/// Random-hash size, both the stream prefix and the hash salt (`RANDOM_HASH_SIZE`).
const RANDOM_HASH_SIZE: usize = 4;
/// `HASHMAP_IS_NOT_EXHAUSTED` / `HASHMAP_IS_EXHAUSTED` flag bytes for a
/// `RESOURCE_REQ`.
const HASHMAP_NOT_EXHAUSTED: u8 = 0x00;
const HASHMAP_EXHAUSTED: u8 = 0xFF;
/// Map-hashes per advertisement / hashmap-update page
/// (`ResourceAdvertisement.HASHMAP_MAX_LEN` = floor((Link.MDU − 134) / 4)).
/// The sender derives the page a receiver asks for from this constant, so it
/// must match the reference exactly.
const HASHMAP_MAX_LEN: usize = 74;
/// Initial part-request window (`Resource.WINDOW`)…
const WINDOW_START: usize = 4;
/// …growing by one per completed window, up to (`Resource.WINDOW_MAX_FAST`).
/// Over the hub's TCP link there's no loss to manage; the window mostly
/// bounds the sender's burst, so growing to the fast cap is safe and makes a
/// real difference on high-RTT links (75 × 431 B ≈ 32 KB per round trip).
const WINDOW_MAX: usize = 75;

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

/// State of an in-progress (single-segment) Resource download, with windowed
/// part requests and hashmap-update paging. Sans-IO: feed it advertisement /
/// part / HMU plaintexts, send whatever [`Self::next_request`] returns.
pub struct ResourceReceiver {
    hash: [u8; 32],
    random_hash: Vec<u8>,
    /// Per-part 4-byte map-hashes; `None` until the page carrying it arrives
    /// (page 0 comes with the advertisement, the rest via `RESOURCE_HMU`).
    map_hashes: Vec<Option<[u8; MAPHASH_LEN]>>,
    /// Count of leading `Some` entries in `map_hashes` (RNS `hashmap_height`;
    /// pages always arrive in order, so the known prefix is contiguous).
    hashmap_height: usize,
    /// Received part data by index; `None` until that part arrives.
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
    /// Count of leading received parts (RNS `consecutive_completed_height`+1).
    consecutive: usize,
    /// Current request window (slow-start).
    window: usize,
    /// Parts requested and not yet received in the current window.
    outstanding: usize,
    /// A hashmap-update request is in flight; don't re-request until it lands.
    waiting_for_hmu: bool,
    encrypted: bool,
    compressed: bool,
}

impl ResourceReceiver {
    /// Parse a `RESOURCE_ADV` plaintext and set up the receiver. Returns an error
    /// for the cases we don't handle (multi-segment, oversized, malformed).
    pub fn accept(adv_plaintext: &[u8]) -> Result<ResourceReceiver, &'static str> {
        let adv = parse_advertisement(adv_plaintext)?;
        if adv.total_segments > 1 {
            return Err("multi-segment resource not supported");
        }
        if adv.parts == 0 {
            return Err("resource advertisement has no parts");
        }
        // SDU-sized parts: bound the whole transfer by the device budget.
        if adv.parts > MAX_TRANSFER_BYTES / 431 + 1 {
            return Err("resource too large");
        }
        // The advertisement carries (at most) the first page of map-hashes.
        let mut map_hashes: Vec<Option<[u8; MAPHASH_LEN]>> = vec![None; adv.parts];
        let in_adv = (adv.hashmap.len() / MAPHASH_LEN).min(adv.parts);
        if in_adv == 0 {
            return Err("resource advertisement hashmap empty");
        }
        for (i, slot) in map_hashes.iter_mut().enumerate().take(in_adv) {
            let mut h = [0u8; MAPHASH_LEN];
            h.copy_from_slice(&adv.hashmap[i * MAPHASH_LEN..(i + 1) * MAPHASH_LEN]);
            *slot = Some(h);
        }
        Ok(ResourceReceiver {
            hash: adv.hash,
            random_hash: adv.random_hash,
            map_hashes,
            hashmap_height: in_adv,
            parts: vec![None; adv.parts],
            received: 0,
            consecutive: 0,
            window: WINDOW_START,
            outstanding: 0,
            waiting_for_hmu: false,
            encrypted: adv.encrypted,
            compressed: adv.compressed,
        })
    }

    /// Whether the assembled stream must be link-decrypted (always true for a
    /// resource sent over a link, but we respect the advertised flag).
    pub fn encrypted(&self) -> bool { self.encrypted }

    /// Build the next `RESOURCE_REQ` payload (mirrors `Resource.request_next`):
    /// up to `window` missing parts from the lowest incomplete index, in order:
    /// `flag(1) [last_map_hash(4) if exhausted] resource_hash(32) map-hashes…`.
    /// When the walk hits a part whose map-hash isn't known yet, the request
    /// carries `HASHMAP_IS_EXHAUSTED` + the last known map-hash, and the sender
    /// replies with the next hashmap page (`RESOURCE_HMU` →
    /// [`Self::receive_hashmap_update`]). Returns `None` when there is nothing
    /// to ask for right now (transfer complete, all requestable parts already
    /// outstanding, or an HMU is in flight). Re-call after a stall to
    /// re-request the outstanding window.
    pub fn next_request(&mut self) -> Option<Vec<u8>> {
        if self.is_complete() || self.waiting_for_hmu {
            return None;
        }
        let mut requested = Vec::new();
        let mut exhausted = false;
        self.outstanding = 0;
        for i in self.consecutive..(self.consecutive + self.window).min(self.parts.len()) {
            if self.parts[i].is_some() {
                continue;
            }
            match self.map_hashes[i] {
                Some(h) => {
                    requested.extend_from_slice(&h);
                    self.outstanding += 1;
                }
                None => {
                    exhausted = true;
                    break;
                }
            }
        }
        if requested.is_empty() && !exhausted {
            return None;
        }
        let mut out = Vec::with_capacity(1 + MAPHASH_LEN + 32 + requested.len());
        if exhausted {
            out.push(HASHMAP_EXHAUSTED);
            out.extend_from_slice(
                &self.map_hashes[self.hashmap_height - 1].expect("known prefix"),
            );
            self.waiting_for_hmu = true;
        } else {
            out.push(HASHMAP_NOT_EXHAUSTED);
        }
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&requested);
        Some(out)
    }

    /// Ingest a `RESOURCE_HMU` plaintext: `resource_hash(32) ||
    /// umsgpack([page, hashmap_bytes])`, filling map-hashes from
    /// `page × HASHMAP_MAX_LEN`. Follow with [`Self::next_request`].
    pub fn receive_hashmap_update(&mut self, plaintext: &[u8]) -> Result<(), &'static str> {
        if plaintext.len() < 32 || plaintext[..32] != self.hash {
            return Err("hashmap update for a different resource");
        }
        let (page, bytes) = parse_hashmap_update(&plaintext[32..])?;
        let base = page * HASHMAP_MAX_LEN;
        for (k, chunk) in bytes.chunks_exact(MAPHASH_LEN).enumerate() {
            let i = base + k;
            if i >= self.map_hashes.len() {
                break;
            }
            if self.map_hashes[i].is_none() {
                let mut h = [0u8; MAPHASH_LEN];
                h.copy_from_slice(chunk);
                self.map_hashes[i] = Some(h);
                self.hashmap_height += 1;
            }
        }
        self.waiting_for_hmu = false;
        Ok(())
    }

    /// Ingest a raw `RESOURCE` part (the still-encrypted chunk). Computes the
    /// part's map-hash (`full_hash(part || r)[:4]`) and stores it at the
    /// matching index. Like RNS, the match is limited to the current window
    /// past the lowest incomplete part — 4-byte hashes can collide across a
    /// large resource, the window keeps lookups unambiguous. Ignores
    /// unknown/duplicate parts. Returns true once the current window is fully
    /// received (time to send the next request).
    pub fn receive_part(&mut self, part_data: &[u8]) -> bool {
        let mut salted = Vec::with_capacity(part_data.len() + self.random_hash.len());
        salted.extend_from_slice(part_data);
        salted.extend_from_slice(&self.random_hash);
        let digest = full_hash(&salted);
        let mut map_hash = [0u8; MAPHASH_LEN];
        map_hash.copy_from_slice(&digest[..MAPHASH_LEN]);
        let end = (self.consecutive + self.window).min(self.parts.len());
        for i in self.consecutive..end {
            if self.map_hashes[i] == Some(map_hash) && self.parts[i].is_none() {
                self.parts[i] = Some(part_data.to_vec());
                self.received += 1;
                self.outstanding = self.outstanding.saturating_sub(1);
                while self.consecutive < self.parts.len() && self.parts[self.consecutive].is_some() {
                    self.consecutive += 1;
                }
                if self.outstanding == 0 {
                    // a full window landed: open it up (slow start)
                    self.window = (self.window + 1).min(WINDOW_MAX);
                    return true;
                }
                return false;
            }
        }
        false
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

/// Parse the umsgpack `[page, hashmap_bytes]` body of a `RESOURCE_HMU`.
fn parse_hashmap_update(data: &[u8]) -> Result<(usize, Vec<u8>), &'static str> {
    let mut p = Reader { b: data, i: 0 };
    let n = p.array_len()?;
    if n < 2 {
        return Err("hashmap update too short");
    }
    let page = p.uint()? as usize;
    let bytes = p.bin()?;
    Ok((page, bytes))
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
    fn array_len(&mut self) -> Result<usize, &'static str> {
        let m = self.u8()?;
        match m {
            0x90..=0x9f => Ok((m & 0x0f) as usize),
            0xdc => Ok(self.be(2)? as usize),
            0xdd => Ok(self.be(4)? as usize),
            _ => Err("expected msgpack array"),
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
    /// fields the receiver reads (`h, r, m, n, l, f`). `hashmap` is the FIRST
    /// PAGE only (≤ `HASHMAP_MAX_LEN` entries), exactly like a real ADV.
    fn build_adv(hash: &[u8; 32], r: &[u8; 4], hashmap: &[u8], n: usize, flags: u8) -> Vec<u8> {
        fn bin8(out: &mut Vec<u8>, b: &[u8]) {
            if b.len() < 256 {
                out.push(0xc4);
                out.push(b.len() as u8);
            } else {
                out.push(0xc5); // bin16: a full hashmap page is 296 bytes
                out.extend_from_slice(&(b.len() as u16).to_be_bytes());
            }
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
        key(&mut out, b'n');
        if n < 128 {
            out.push(n as u8); // fixint
        } else {
            out.push(0xcd); // uint16
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        key(&mut out, b'l'); out.push(1u8);
        key(&mut out, b'f'); out.push(flags);
        out
    }

    /// A simulated RNS sender: answers `RESOURCE_REQ`s with the matching parts
    /// (optionally out of order) and exhausted-hashmap flags with the right
    /// `RESOURCE_HMU` page, mirroring `Resource.request`.
    struct SimSender {
        hash: [u8; 32],
        parts: Vec<Vec<u8>>,
        map_hashes: Vec<[u8; MAPHASH_LEN]>,
    }

    impl SimSender {
        /// Build the resource exactly as an RNS sender would: prefix + (already
        /// compressed, if the caller chose) stream, link-encrypted, split into
        /// `sdu` chunks; the advertisement carries only the first hashmap page.
        fn new(stream_data: &[u8], key: &[u8; DERIVED_KEY_LENGTH], r: &[u8; 4], sdu: usize, payload_hash: [u8; 32]) -> (SimSender, Vec<u8>, Vec<u8>) {
            let mut stream_plain = vec![0xA0, 0xA1, 0xA2, 0xA3]; // random prefix
            stream_plain.extend_from_slice(stream_data);
            let ciphertext = Token::new(key).unwrap().encrypt_with_iv(&stream_plain, &[0x11; 16]);
            let mut parts = Vec::new();
            let mut map_hashes = Vec::new();
            for chunk in ciphertext.chunks(sdu) {
                parts.push(chunk.to_vec());
                let mut salted = chunk.to_vec();
                salted.extend_from_slice(r);
                let mut mh = [0u8; MAPHASH_LEN];
                mh.copy_from_slice(&full_hash(&salted)[..MAPHASH_LEN]);
                map_hashes.push(mh);
            }
            let page0: Vec<u8> =
                map_hashes.iter().take(HASHMAP_MAX_LEN).flat_map(|h| h.to_vec()).collect();
            let sender = SimSender { hash: payload_hash, parts, map_hashes };
            (sender, page0, ciphertext)
        }

        /// Handle one receiver request → (parts to deliver, optional HMU).
        fn handle(&self, req: &[u8]) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
            let exhausted = req[0] == HASHMAP_EXHAUSTED;
            let (last_hash, rest) = if exhausted {
                (Some(&req[1..1 + MAPHASH_LEN]), &req[1 + MAPHASH_LEN..])
            } else {
                (None, &req[1..])
            };
            assert_eq!(&rest[..32], &self.hash, "request for the wrong resource");
            let wanted = &rest[32..];
            let mut out = Vec::new();
            for w in wanted.chunks_exact(MAPHASH_LEN) {
                if let Some(i) = self.map_hashes.iter().position(|h| h == w) {
                    out.push(self.parts[i].clone());
                }
            }
            let hmu = last_hash.map(|lh| {
                // mirror Resource.request: the receiver's known hashmap must end
                // exactly on a page boundary; serve the next page.
                let idx = self.map_hashes.iter().position(|h| h == lh).unwrap();
                assert_eq!((idx + 1) % HASHMAP_MAX_LEN, 0, "sequencing error");
                let page = (idx + 1) / HASHMAP_MAX_LEN;
                let bytes: Vec<u8> = self
                    .map_hashes
                    .iter()
                    .skip(page * HASHMAP_MAX_LEN)
                    .take(HASHMAP_MAX_LEN)
                    .flat_map(|h| h.to_vec())
                    .collect();
                // hash(32) || umsgpack([page, bin(bytes)])
                let mut hmu = self.hash.to_vec();
                hmu.push(0x92); // fixarray(2)
                hmu.push(page as u8); // page < 128 in tests → fixint
                if bytes.len() < 256 {
                    hmu.push(0xc4);
                    hmu.push(bytes.len() as u8);
                } else {
                    hmu.push(0xc5);
                    hmu.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                }
                hmu.extend_from_slice(&bytes);
                hmu
            });
            (out, hmu)
        }
    }

    /// Drive a full transfer through the windowed request pump, delivering each
    /// window's parts in reverse order to exercise out-of-order placement.
    fn pump_transfer(rx: &mut ResourceReceiver, sender: &SimSender) -> (usize, usize) {
        let (mut requests, mut hmus) = (0, 0);
        let mut guard = 0;
        while !rx.is_complete() {
            let req = rx.next_request().expect("transfer must always have a next step");
            requests += 1;
            let (mut parts, hmu) = sender.handle(&req);
            parts.reverse();
            for p in &parts {
                rx.receive_part(p);
            }
            if let Some(h) = hmu {
                hmus += 1;
                rx.receive_hashmap_update(&h).expect("hashmap update");
            }
            guard += 1;
            assert!(guard < 1000, "transfer did not converge");
        }
        (requests, hmus)
    }

    #[test]
    fn receives_and_assembles_a_resource() {
        // Small resource: hashmap fits the advertisement, a few windows.
        let key = [0x5a_u8; DERIVED_KEY_LENGTH];
        let payload: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let r = [0x01u8, 0x02, 0x03, 0x04];
        let mut hsalt = payload.clone();
        hsalt.extend_from_slice(&r);
        let hash = full_hash(&hsalt);

        let (sender, page0, ciphertext) = SimSender::new(&payload, &key, &r, 100, hash);
        let n = sender.parts.len();
        let adv = build_adv(&hash, &r, &page0, n, 0x01); // encrypted, not compressed

        let mut rx = ResourceReceiver::accept(&adv).expect("accept advertisement");
        assert!(rx.encrypted());
        let (requests, hmus) = pump_transfer(&mut rx, &sender);
        assert!(requests > 1, "small transfer still takes multiple windows");
        assert_eq!(hmus, 0, "hashmap fit the advertisement");
        assert_eq!(rx.concat(), ciphertext, "reassembled stream must match");

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
    fn windows_and_hashmap_updates_drive_a_large_resource() {
        // ~60 KB at the real SDU (431 B) → ~140 parts → 2 hashmap pages: the
        // advertisement only covers page 0, so the transfer must request a
        // RESOURCE_HMU mid-flight, while the window grows from 4 upward.
        let key = [0x66_u8; DERIVED_KEY_LENGTH];
        let payload: Vec<u8> = (0..60_000u32).map(|i| (i * 31 + i / 251) as u8).collect();
        let r = [0x0Au8, 0x0B, 0x0C, 0x0D];
        let mut hsalt = payload.clone();
        hsalt.extend_from_slice(&r);
        let hash = full_hash(&hsalt);

        let (sender, page0, _ciphertext) = SimSender::new(&payload, &key, &r, 431, hash);
        let n = sender.parts.len();
        assert!(n > HASHMAP_MAX_LEN, "test must exceed one hashmap page (n={n})");
        assert_eq!(page0.len(), HASHMAP_MAX_LEN * MAPHASH_LEN, "ADV carries only page 0");
        let adv = build_adv(&hash, &r, &page0, n, 0x01);

        let mut rx = ResourceReceiver::accept(&adv).expect("accept advertisement");
        let (requests, hmus) = pump_transfer(&mut rx, &sender);
        assert!(hmus >= 1, "must have needed at least one hashmap update");
        assert!(requests >= n / WINDOW_MAX, "windowed transfer takes multiple requests");

        let decrypted = Token::new(&key).unwrap().decrypt(&rx.concat()).expect("token");
        let (got, _proof) = rx.finish(&decrypted).expect("finish");
        assert_eq!(got, payload, "recovered 60 KB payload must match");
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
        let r = [0x05u8, 0x06, 0x07, 0x08];
        let mut hsalt = payload.clone();
        hsalt.extend_from_slice(&r);
        let hash = full_hash(&hsalt);

        let (sender, page0, _) = SimSender::new(&comp, &key, &r, 50, hash);
        let adv = build_adv(&hash, &r, &page0, sender.parts.len(), 0x03); // encrypted | compressed

        let mut rx = ResourceReceiver::accept(&adv).expect("accept compressed advertisement");
        pump_transfer(&mut rx, &sender);
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
