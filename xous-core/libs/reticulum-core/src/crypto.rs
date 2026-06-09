//! Low-level cryptographic helpers mirroring `RNS/Cryptography`.

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::constants::*;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// SHA-256 of `data` (RNS `full_hash`).
pub fn full_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// First `TRUNCATED_HASHLENGTH` bytes of SHA-256 (RNS `truncated_hash`).
pub fn truncated_hash(data: &[u8]) -> [u8; TRUNCATED_HASHLENGTH] {
    let full = full_hash(data);
    let mut out = [0u8; TRUNCATED_HASHLENGTH];
    out.copy_from_slice(&full[..TRUNCATED_HASHLENGTH]);
    out
}

/// SHA-512, used by some RNS contexts.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize().into()
}

/// HKDF-SHA256 expand to `length` bytes (RNS `Cryptography.hkdf`).
///
/// RNS passes the ECDH shared secret as `derive_from` (IKM), an optional salt,
/// and no info/context for the `Identity` case.
pub fn hkdf(length: usize, derive_from: &[u8], salt: Option<&[u8]>, context: Option<&[u8]>) -> Vec<u8> {
    let salt = salt.unwrap_or(&[]);
    let hk = Hkdf::<Sha256>::new(Some(salt), derive_from);
    let mut okm = vec![0u8; length];
    hk.expand(context.unwrap_or(&[]), &mut okm).expect("hkdf expand");
    okm
}

/// The Reticulum `Token` (Fernet-like) symmetric primitive.
///
/// A token's key is either 32 bytes (AES-128) or 64 bytes (AES-256). RNS uses
/// 64-byte keys derived via HKDF, so we implement the AES-256 path: the first
/// 32 bytes are the HMAC-SHA256 signing key, the last 32 bytes are the AES-256
/// key. The token wire layout is `IV(16) || ciphertext || HMAC(32)`, where the
/// HMAC covers `IV || ciphertext`.
pub struct Token {
    signing_key: [u8; 32],
    encryption_key: [u8; 32],
}

impl Token {
    /// Construct from a 64-byte derived key.
    pub fn new(key: &[u8]) -> Result<Token, &'static str> {
        if key.len() != 64 {
            return Err("Token requires a 64-byte key (AES-256 mode)");
        }
        let mut signing_key = [0u8; 32];
        let mut encryption_key = [0u8; 32];
        signing_key.copy_from_slice(&key[..32]);
        encryption_key.copy_from_slice(&key[32..]);
        Ok(Token { signing_key, encryption_key })
    }

    /// Encrypt `plaintext` with the provided 16-byte IV (injected for testability).
    pub fn encrypt_with_iv(&self, plaintext: &[u8], iv: &[u8; IV_LENGTH]) -> Vec<u8> {
        let ct = Aes256CbcEnc::new(self.encryption_key.as_slice().into(), iv.as_slice().into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        let mut signed = Vec::with_capacity(IV_LENGTH + ct.len());
        signed.extend_from_slice(iv);
        signed.extend_from_slice(&ct);

        let mut mac = HmacSha256::new_from_slice(&self.signing_key).expect("hmac key");
        mac.update(&signed);
        let tag = mac.finalize().into_bytes();

        let mut token = signed;
        token.extend_from_slice(&tag);
        token
    }

    /// Verify and decrypt a token (`IV || ct || HMAC`).
    pub fn decrypt(&self, token: &[u8]) -> Result<Vec<u8>, &'static str> {
        if token.len() < IV_LENGTH + HMAC_LENGTH {
            return Err("token too short");
        }
        let (signed, recv_mac) = token.split_at(token.len() - HMAC_LENGTH);

        let mut mac = HmacSha256::new_from_slice(&self.signing_key).expect("hmac key");
        mac.update(signed);
        let expected = mac.finalize().into_bytes();
        if expected.ct_eq(recv_mac).unwrap_u8() != 1 {
            return Err("token HMAC verification failed");
        }

        let (iv, ct) = signed.split_at(IV_LENGTH);
        Aes256CbcDec::new(self.encryption_key.as_slice().into(), iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .map_err(|_| "token padding error")
    }
}

/// HMAC-SHA256 over `data` with `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_roundtrip() {
        let key = [7u8; 64];
        let token = Token::new(&key).unwrap();
        let iv = [3u8; IV_LENGTH];
        let pt = b"hello reticulum";
        let ct = token.encrypt_with_iv(pt, &iv);
        // layout: IV || ciphertext || HMAC
        assert_eq!(&ct[..IV_LENGTH], &iv);
        assert_eq!(ct.len(), IV_LENGTH + 16 /*one padded block*/ + HMAC_LENGTH);
        let back = token.decrypt(&ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn token_detects_tamper() {
        let token = Token::new(&[1u8; 64]).unwrap();
        let iv = [0u8; IV_LENGTH];
        let mut ct = token.encrypt_with_iv(b"abc", &iv);
        let n = ct.len();
        ct[n - 1] ^= 0x01; // flip last HMAC byte
        assert!(token.decrypt(&ct).is_err());
    }

    #[test]
    fn truncated_is_16_bytes() {
        assert_eq!(truncated_hash(b"x").len(), 16);
    }
}
