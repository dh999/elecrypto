//! Symmetric encryption algorithms
//!
//! This module provides authenticated encryption using modern algorithms:
//! - AES-256-GCM
//! - ChaCha20-Poly1305
//!
//! Both provide authenticated encryption with associated data (AEAD).

mod aes_gcm;
mod chacha20;

pub use aes_gcm::{aes_gcm_encrypt, aes_gcm_decrypt, aes_generate_key};
pub use chacha20::{chacha20_poly1305_encrypt, chacha20_poly1305_decrypt, chacha20_generate_key};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = aes_generate_key();
        let plaintext = b"Test message";

        let (ciphertext, nonce) = aes_gcm_encrypt(plaintext, &key, None, None).unwrap();
        let decrypted = aes_gcm_decrypt(&ciphertext, &key, &nonce, None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = chacha20_generate_key();
        let plaintext = b"Test message";

        let (ciphertext, nonce) = chacha20_poly1305_encrypt(plaintext, &key, None, None).unwrap();
        let decrypted = chacha20_poly1305_decrypt(&ciphertext, &key, &nonce, None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
