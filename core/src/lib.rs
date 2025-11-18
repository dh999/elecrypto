//! # Elecrypto Core
//!
//! Core cryptographic library providing modern, secure encryption functionality.
//!
//! ## Features
//!
//! - **Symmetric Encryption**: AES-GCM, ChaCha20-Poly1305
//! - **Asymmetric Encryption**: RSA, ECIES
//! - **Hash Functions**: SHA-256/512, SHA-3, BLAKE3
//! - **Key Derivation**: PBKDF2, Argon2, HKDF
//! - **Digital Signatures**: Ed25519, ECDSA, RSA-PSS
//! - **Post-Quantum Crypto (NIST)**: ML-KEM (Kyber), ML-DSA (Dilithium), FN-DSA (Falcon), SLH-DSA (SPHINCS+)
//! - **Post-Quantum Crypto (KPQC)**: NTRU+, SMAUG, TiGER, PALOMA, AIMer, HAETAE, SOLMAE, GCKSign
//! - **Random Generation**: CSPRNG
//! - **DRBG**: HMAC-DRBG, Hash-DRBG, CTR-DRBG (NIST SP 800-90A)
//!
//! ## Safety
//!
//! - Constant-time operations to prevent timing attacks
//! - Automatic memory zeroing for sensitive data
//! - No unsafe code in public API
//!
//! ## Example
//!
//! ```rust
//! use elecrypto_core::symmetric::{aes_gcm_encrypt, aes_gcm_decrypt, aes_generate_key};
//!
//! // Generate a key
//! let key = aes_generate_key();
//!
//! // Encrypt
//! let plaintext = b"Hello, World!";
//! let (ciphertext, nonce) = aes_gcm_encrypt(plaintext, &key, None, None).unwrap();
//!
//! // Decrypt
//! let decrypted = aes_gcm_decrypt(&ciphertext, &key, &nonce, None).unwrap();
//! assert_eq!(plaintext.as_slice(), decrypted.as_slice());
//! ```

#![warn(missing_docs, rust_2018_idioms)]
// Note: unsafe code is allowed only in the FFI module for C interop

pub mod symmetric;
pub mod asymmetric;
pub mod hash;
pub mod kdf;
pub mod signing;
pub mod random;
pub mod drbg;
pub mod pqc;
pub mod kpqc;
pub mod ffi;

mod error;
pub use error::{Error, Result};

/// Version of the elecrypto-core library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
