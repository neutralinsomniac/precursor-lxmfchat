//! Reticulum `Identity`: an X25519 (encryption) + Ed25519 (signing) keypair,
//! and the per-recipient encrypt/decrypt + sign/validate operations.
//! Mirrors `RNS/Identity.py`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroize;

use crate::constants::*;
use crate::crypto::{Token, hkdf, truncated_hash};
use crate::x25519::{x25519, x25519_base};

/// A full identity with private keys (ours). X25519 ECDH is done in software
/// (see [`crate::x25519`]); Ed25519 stays on `ed25519-dalek` (the hardware
/// engine's Edwards path is correct).
pub struct PrivateIdentity {
    x25519_seed: [u8; KEY_HALF],
    ed25519: SigningKey,
    public: PublicIdentity,
}

/// The public half of an identity (a peer's, or the public view of ours).
#[derive(Clone)]
pub struct PublicIdentity {
    /// X25519 public key (encryption).
    pub enc_pub: [u8; KEY_HALF],
    /// Ed25519 public key (signing).
    pub sig_pub: [u8; KEY_HALF],
    /// `truncated_hash(enc_pub || sig_pub)` (16 bytes).
    pub hash: [u8; TRUNCATED_HASHLENGTH],
}

impl PublicIdentity {
    /// 64-byte concatenation `enc_pub || sig_pub` (RNS `get_public_key`).
    pub fn public_key(&self) -> [u8; KEYSIZE] {
        let mut out = [0u8; KEYSIZE];
        out[..KEY_HALF].copy_from_slice(&self.enc_pub);
        out[KEY_HALF..].copy_from_slice(&self.sig_pub);
        out
    }

    /// Parse a 64-byte public key blob into a `PublicIdentity` (RNS `load_public_key`).
    pub fn from_public_key(bytes: &[u8]) -> Result<PublicIdentity, &'static str> {
        if bytes.len() != KEYSIZE {
            return Err("public key must be 64 bytes");
        }
        let mut enc_pub = [0u8; KEY_HALF];
        let mut sig_pub = [0u8; KEY_HALF];
        enc_pub.copy_from_slice(&bytes[..KEY_HALF]);
        sig_pub.copy_from_slice(&bytes[KEY_HALF..]);
        Ok(PublicIdentity { enc_pub, sig_pub, hash: truncated_hash(bytes) })
    }

    /// Verify an Ed25519 signature over `message`.
    pub fn validate(&self, signature: &[u8], message: &[u8]) -> bool {
        let vk = match VerifyingKey::from_bytes(&self.sig_pub) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let sig = match <[u8; SIG_LENGTH]>::try_from(signature) {
            Ok(s) => Signature::from_bytes(&s),
            Err(_) => return false,
        };
        vk.verify(message, &sig).is_ok()
    }

    /// Encrypt `plaintext` to this identity (RNS `Identity.encrypt`).
    ///
    /// Returns `ephemeral_x25519_pub(32) || token`. The caller supplies the
    /// ephemeral private scalar bytes (so the operation is deterministic and
    /// testable); on device these come from the TRNG.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        ephemeral_secret: &[u8; KEY_HALF],
        iv: &[u8; IV_LENGTH],
        ratchet_pub: Option<&[u8; RATCHET_SIZE]>,
    ) -> Vec<u8> {
        let eph_pub = x25519_base(ephemeral_secret);

        let target_pub = ratchet_pub.unwrap_or(&self.enc_pub);
        let shared = x25519(ephemeral_secret, target_pub);

        // salt = identity hash; context = None (RNS Identity case)
        let derived = hkdf(DERIVED_KEY_LENGTH, &shared, Some(&self.hash), None);
        let token = Token::new(&derived).expect("64-byte derived key");
        let ct = token.encrypt_with_iv(plaintext, iv);

        let mut out = Vec::with_capacity(KEY_HALF + ct.len());
        out.extend_from_slice(&eph_pub);
        out.extend_from_slice(&ct);
        out
    }
}

impl PrivateIdentity {
    /// Create an identity from raw key material (2 × 32 random bytes).
    pub fn from_bytes(x25519_seed: &[u8; KEY_HALF], ed25519_seed: &[u8; KEY_HALF]) -> PrivateIdentity {
        let ed25519 = SigningKey::from_bytes(ed25519_seed);
        let enc_pub = x25519_base(x25519_seed);
        let sig_pub = ed25519.verifying_key().to_bytes();
        let mut concat = [0u8; KEYSIZE];
        concat[..KEY_HALF].copy_from_slice(&enc_pub);
        concat[KEY_HALF..].copy_from_slice(&sig_pub);
        let public = PublicIdentity { enc_pub, sig_pub, hash: truncated_hash(&concat) };
        PrivateIdentity { x25519_seed: *x25519_seed, ed25519, public }
    }

    /// Generate a new identity from an RNG (used on host; on Xous, feed the TRNG).
    pub fn generate(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> PrivateIdentity {
        let mut xs = [0u8; KEY_HALF];
        let mut es = [0u8; KEY_HALF];
        rng.fill_bytes(&mut xs);
        rng.fill_bytes(&mut es);
        let id = PrivateIdentity::from_bytes(&xs, &es);
        xs.zeroize();
        es.zeroize();
        id
    }

    pub fn public(&self) -> &PublicIdentity { &self.public }
    pub fn hash(&self) -> [u8; TRUNCATED_HASHLENGTH] { self.public.hash }

    /// The 64-byte private key material `x25519_seed || ed25519_seed`, for PDDB storage.
    pub fn private_bytes(&self) -> [u8; KEYSIZE] {
        let mut out = [0u8; KEYSIZE];
        out[..KEY_HALF].copy_from_slice(&self.x25519_seed);
        out[KEY_HALF..].copy_from_slice(&self.ed25519.to_bytes());
        out
    }

    /// Ed25519 signature over `message` (RNS `sign`).
    pub fn sign(&self, message: &[u8]) -> [u8; SIG_LENGTH] {
        self.ed25519.sign(message).to_bytes()
    }

    /// Decrypt a blob produced by `PublicIdentity::encrypt` (RNS `Identity.decrypt`).
    ///
    /// Tries each provided ratchet private key first, then falls back to our
    /// X25519 private key.
    pub fn decrypt(
        &self,
        blob: &[u8],
        ratchets: &[[u8; RATCHET_SIZE]],
    ) -> Result<Vec<u8>, &'static str> {
        if blob.len() <= KEY_HALF {
            return Err("encrypted blob too short");
        }
        let mut peer_pub = [0u8; KEY_HALF];
        peer_pub.copy_from_slice(&blob[..KEY_HALF]);
        let ciphertext = &blob[KEY_HALF..];

        for r in ratchets {
            let shared = x25519(r, &peer_pub);
            let derived = hkdf(DERIVED_KEY_LENGTH, &shared, Some(&self.public.hash), None);
            if let Ok(token) = Token::new(&derived) {
                if let Ok(pt) = token.decrypt(ciphertext) {
                    return Ok(pt);
                }
            }
        }

        let shared = x25519(&self.x25519_seed, &peer_pub);
        let derived = hkdf(DERIVED_KEY_LENGTH, &shared, Some(&self.public.hash), None);
        let token = Token::new(&derived)?;
        token.decrypt(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(seed: u8) -> PrivateIdentity {
        PrivateIdentity::from_bytes(&[seed; KEY_HALF], &[seed.wrapping_add(1); KEY_HALF])
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let recipient = test_identity(5);
        let pt = b"the quick brown fox jumps over the lazy dog";
        let blob = recipient.public().encrypt(pt, &[9u8; KEY_HALF], &[2u8; IV_LENGTH], None);
        // ephemeral pub (32) + token (>= 48)
        assert!(blob.len() >= KEY_HALF + TOKEN_OVERHEAD);
        let back = recipient.decrypt(&blob, &[]).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn sign_validate_roundtrip() {
        let id = test_identity(11);
        let msg = b"sign me";
        let sig = id.sign(msg);
        assert!(id.public().validate(&sig, msg));
        assert!(!id.public().validate(&sig, b"different"));
    }

    #[test]
    fn public_key_roundtrip() {
        let id = test_identity(3);
        let pk = id.public().public_key();
        let parsed = PublicIdentity::from_public_key(&pk).unwrap();
        assert_eq!(parsed.hash, id.hash());
    }
}
