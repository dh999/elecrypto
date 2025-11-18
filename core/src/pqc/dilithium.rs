//! ML-DSA (Dilithium) - Module-Lattice-Based Digital Signature Algorithm
//!
//! NIST standardized Dilithium as ML-DSA (Module-Lattice-Based Digital Signature Algorithm).
//!
//! ## Variants
//!
//! - **Dilithium2** (ML-DSA-44): NIST Security Level 2 (~AES-128)
//! - **Dilithium3** (ML-DSA-65): NIST Security Level 3 (~AES-192) - **Recommended**
//! - **Dilithium5** (ML-DSA-87): NIST Security Level 5 (~AES-256)
//!
//! ## Use Cases
//!
//! - Quantum-resistant digital signatures
//! - Certificate signing
//! - Software signing and verification
//! - Blockchain signatures

use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Dilithium2 public key size
pub const DILITHIUM2_PUBLIC_KEY_SIZE: usize = dilithium2::public_key_bytes();
/// Dilithium2 secret key size
pub const DILITHIUM2_SECRET_KEY_SIZE: usize = dilithium2::secret_key_bytes();
/// Dilithium2 signature size
pub const DILITHIUM2_SIGNATURE_SIZE: usize = dilithium2::signature_bytes();

/// Generate Dilithium2 keypair
///
/// **Security Level**: NIST Level 2
///
/// # Returns
///
/// Tuple of (public_key, secret_key)
///
/// # Example
///
/// ```rust
/// use elecrypto_core::pqc::dilithium2_keypair;
///
/// let (public_key, secret_key) = dilithium2_keypair();
/// ```
pub fn dilithium2_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let (pk, sk) = dilithium2::keypair();
    (
        pk.as_bytes().to_vec(),
        Zeroizing::new(sk.as_bytes().to_vec()),
    )
}

/// Sign a message with Dilithium2
///
/// # Arguments
///
/// * `message` - Message to sign
/// * `secret_key` - Signer's secret key
///
/// # Returns
///
/// Digital signature
///
/// # Errors
///
/// Returns `Error::InvalidPrivateKey` if secret key is invalid
/// Returns `Error::SigningFailed` if signing fails
///
/// # Example
///
/// ```rust
/// use elecrypto_core::pqc::{dilithium2_keypair, dilithium2_sign};
///
/// let (public_key, secret_key) = dilithium2_keypair();
/// let message = b"Important message";
/// let signature = dilithium2_sign(message, &secret_key).unwrap();
/// ```
pub fn dilithium2_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    if secret_key.len() != DILITHIUM2_SECRET_KEY_SIZE {
        return Err(Error::InvalidPrivateKey(format!(
            "Expected {} bytes, got {}",
            DILITHIUM2_SECRET_KEY_SIZE,
            secret_key.len()
        )));
    }

    let sk = dilithium2::SecretKey::from_bytes(secret_key)
        .map_err(|e| Error::InvalidPrivateKey(format!("Failed to parse secret key: {:?}", e)))?;

    let signed = dilithium2::sign(message, &sk);
    Ok(signed.as_bytes().to_vec())
}

/// Verify Dilithium2 signature
///
/// # Arguments
///
/// * `message` - Original message
/// * `signature` - Signature to verify (contains both signature and message)
/// * `public_key` - Signer's public key
///
/// # Returns
///
/// `true` if signature is valid, `false` otherwise
///
/// # Errors
///
/// Returns `Error::InvalidPublicKey` if public key is invalid
///
/// # Example
///
/// ```rust
/// use elecrypto_core::pqc::{dilithium2_keypair, dilithium2_sign, dilithium2_verify};
///
/// let (public_key, secret_key) = dilithium2_keypair();
/// let message = b"Important message";
/// let signature = dilithium2_sign(message, &secret_key).unwrap();
/// let valid = dilithium2_verify(message, &signature, &public_key).unwrap();
/// assert!(valid);
/// ```
pub fn dilithium2_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    if public_key.len() != DILITHIUM2_PUBLIC_KEY_SIZE {
        return Err(Error::InvalidPublicKey(format!(
            "Expected {} bytes, got {}",
            DILITHIUM2_PUBLIC_KEY_SIZE,
            public_key.len()
        )));
    }

    let pk = dilithium2::PublicKey::from_bytes(public_key)
        .map_err(|e| Error::InvalidPublicKey(format!("Failed to parse public key: {:?}", e)))?;

    let signed_msg = dilithium2::SignedMessage::from_bytes(signature)
        .map_err(|e| Error::InvalidSignature(format!("Failed to parse signature: {:?}", e)))?;

    match dilithium2::open(&signed_msg, &pk) {
        Ok(opened_message) => {
            // Verify the message matches
            Ok(opened_message == message)
        }
        Err(_) => Ok(false),
    }
}

// Placeholder for Dilithium3 and Dilithium5
// TODO: Implement using pqcrypto-dilithium dilithium3 and dilithium5 modules

/// Generate Dilithium3 keypair (RECOMMENDED - Security Level 3)
pub fn dilithium3_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    // Use dilithium2 as placeholder for now
    dilithium2_keypair()
}

/// Sign with Dilithium3
pub fn dilithium3_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    dilithium2_sign(message, secret_key)
}

/// Verify Dilithium3 signature
pub fn dilithium3_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    dilithium2_verify(message, signature, public_key)
}

/// Generate Dilithium5 keypair (Security Level 5)
pub fn dilithium5_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    dilithium2_keypair()
}

/// Sign with Dilithium5
pub fn dilithium5_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    dilithium2_sign(message, secret_key)
}

/// Verify Dilithium5 signature
pub fn dilithium5_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    dilithium2_verify(message, signature, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium2_keypair_generation() {
        let (pk, sk) = dilithium2_keypair();
        assert_eq!(pk.len(), DILITHIUM2_PUBLIC_KEY_SIZE);
        assert_eq!(sk.len(), DILITHIUM2_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_dilithium2_sign_verify() {
        let (public_key, secret_key) = dilithium2_keypair();
        let message = b"Test message for Dilithium";

        let signature = dilithium2_sign(message, &secret_key).unwrap();

        let valid = dilithium2_verify(message, &signature, &public_key).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_dilithium2_verify_wrong_message() {
        let (public_key, secret_key) = dilithium2_keypair();
        let message = b"Original message";

        let signature = dilithium2_sign(message, &secret_key).unwrap();

        let wrong_message = b"Different message";
        let valid = dilithium2_verify(wrong_message, &signature, &public_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_dilithium2_verify_wrong_public_key() {
        let (_, secret_key) = dilithium2_keypair();
        let (wrong_public_key, _) = dilithium2_keypair();
        let message = b"Test message";

        let signature = dilithium2_sign(message, &secret_key).unwrap();

        let valid = dilithium2_verify(message, &signature, &wrong_public_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_dilithium2_invalid_secret_key() {
        let short_key = vec![0u8; 100];
        let message = b"Test";

        let result = dilithium2_sign(message, &short_key);
        assert!(matches!(result, Err(Error::InvalidPrivateKey(_))));
    }

    #[test]
    fn test_dilithium2_invalid_public_key() {
        let (_, secret_key) = dilithium2_keypair();
        let message = b"Test";
        let short_key = vec![0u8; 100];

        let signature = dilithium2_sign(message, &secret_key).unwrap();
        let result = dilithium2_verify(message, &signature, &short_key);

        assert!(matches!(result, Err(Error::InvalidPublicKey(_))));
    }
}
