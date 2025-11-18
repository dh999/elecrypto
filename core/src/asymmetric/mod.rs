//! Asymmetric encryption
//!
//! Provides public-key encryption:
//! - RSA-OAEP
//! - ECIES (planned)
//!
//! **Note**: This module is under development.
//! Initial implementation provides placeholder functions.

use crate::{Error, Result};

/// RSA key sizes
pub enum RsaKeySize {
    /// 2048-bit RSA key
    Rsa2048 = 2048,
    /// 3072-bit RSA key
    Rsa3072 = 3072,
    /// 4096-bit RSA key
    Rsa4096 = 4096,
}

/// Placeholder: Generate RSA key pair
///
/// **Status**: Implementation pending
pub fn rsa_generate_keypair(_key_size: RsaKeySize) -> Result<(Vec<u8>, Vec<u8>)> {
    Err(Error::UnsupportedAlgorithm(
        "RSA key generation not yet implemented".to_string(),
    ))
}

/// Placeholder: RSA-OAEP encryption
///
/// **Status**: Implementation pending
pub fn rsa_encrypt(_plaintext: &[u8], _public_key: &[u8]) -> Result<Vec<u8>> {
    Err(Error::UnsupportedAlgorithm(
        "RSA encryption not yet implemented".to_string(),
    ))
}

/// Placeholder: RSA-OAEP decryption
///
/// **Status**: Implementation pending
pub fn rsa_decrypt(_ciphertext: &[u8], _private_key: &[u8]) -> Result<Vec<u8>> {
    Err(Error::UnsupportedAlgorithm(
        "RSA decryption not yet implemented".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_not_implemented() {
        let result = rsa_generate_keypair(RsaKeySize::Rsa2048);
        assert!(matches!(result, Err(Error::UnsupportedAlgorithm(_))));
    }
}
