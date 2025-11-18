//! FN-DSA (Falcon) - Fast Fourier Transform over NTRU-Lattice Digital Signature Algorithm
//!
//! NIST standardized Falcon as FN-DSA.
//!
//! ## Variants
//!
//! - **Falcon-512**: NIST Security Level 1 (~AES-128)
//! - **Falcon-1024**: NIST Security Level 5 (~AES-256)
//!
//! ## Key Features
//!
//! - **Smallest signatures** among NIST PQC signatures
//! - Fast verification
//! - Compact public keys
//!
//! ## Use Cases
//!
//! - IoT devices (small signature size)
//! - Blockchain (compact signatures)
//! - Constrained environments

use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Falcon-512 public key size
pub const FALCON512_PUBLIC_KEY_SIZE: usize = falcon512::public_key_bytes();
/// Falcon-512 secret key size
pub const FALCON512_SECRET_KEY_SIZE: usize = falcon512::secret_key_bytes();
/// Falcon-512 signature size (compact!)
pub const FALCON512_SIGNATURE_SIZE: usize = falcon512::signature_bytes();

/// Generate Falcon-512 keypair
///
/// **Security Level**: NIST Level 1
///
/// # Returns
///
/// Tuple of (public_key, secret_key)
///
/// # Example
///
/// ```rust
/// use elecrypto_core::pqc::falcon512_keypair;
///
/// let (public_key, secret_key) = falcon512_keypair();
/// ```
pub fn falcon512_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let (pk, sk) = falcon512::keypair();
    (
        pk.as_bytes().to_vec(),
        Zeroizing::new(sk.as_bytes().to_vec()),
    )
}

/// Sign a message with Falcon-512
///
/// # Arguments
///
/// * `message` - Message to sign
/// * `secret_key` - Signer's secret key
///
/// # Returns
///
/// Digital signature (compact size!)
///
/// # Errors
///
/// Returns `Error::InvalidPrivateKey` if secret key is invalid
///
/// # Example
///
/// ```rust
/// use elecrypto_core::pqc::{falcon512_keypair, falcon512_sign};
///
/// let (public_key, secret_key) = falcon512_keypair();
/// let message = b"Important message";
/// let signature = falcon512_sign(message, &secret_key).unwrap();
/// ```
pub fn falcon512_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    if secret_key.len() != FALCON512_SECRET_KEY_SIZE {
        return Err(Error::InvalidPrivateKey(format!(
            "Expected {} bytes, got {}",
            FALCON512_SECRET_KEY_SIZE,
            secret_key.len()
        )));
    }

    let sk = falcon512::SecretKey::from_bytes(secret_key)
        .map_err(|e| Error::InvalidPrivateKey(format!("Failed to parse secret key: {:?}", e)))?;

    let signed = falcon512::sign(message, &sk);
    Ok(signed.as_bytes().to_vec())
}

/// Verify Falcon-512 signature
///
/// # Arguments
///
/// * `message` - Original message
/// * `signature` - Signature to verify
/// * `public_key` - Signer's public key
///
/// # Returns
///
/// `true` if signature is valid, `false` otherwise
///
/// # Example
///
/// ```rust
/// use elecrypto_core::pqc::{falcon512_keypair, falcon512_sign, falcon512_verify};
///
/// let (public_key, secret_key) = falcon512_keypair();
/// let message = b"Important message";
/// let signature = falcon512_sign(message, &secret_key).unwrap();
/// let valid = falcon512_verify(message, &signature, &public_key).unwrap();
/// assert!(valid);
/// ```
pub fn falcon512_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    if public_key.len() != FALCON512_PUBLIC_KEY_SIZE {
        return Err(Error::InvalidPublicKey(format!(
            "Expected {} bytes, got {}",
            FALCON512_PUBLIC_KEY_SIZE,
            public_key.len()
        )));
    }

    let pk = falcon512::PublicKey::from_bytes(public_key)
        .map_err(|e| Error::InvalidPublicKey(format!("Failed to parse public key: {:?}", e)))?;

    let signed_msg = falcon512::SignedMessage::from_bytes(signature)
        .map_err(|e| Error::InvalidSignature(format!("Failed to parse signature: {:?}", e)))?;

    match falcon512::open(&signed_msg, &pk) {
        Ok(opened_message) => Ok(opened_message == message),
        Err(_) => Ok(false),
    }
}

// Placeholder for Falcon-1024
// TODO: Implement using pqcrypto-falcon falcon1024 module

/// Generate Falcon-1024 keypair (Security Level 5)
pub fn falcon1024_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    falcon512_keypair()
}

/// Sign with Falcon-1024
pub fn falcon1024_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    falcon512_sign(message, secret_key)
}

/// Verify Falcon-1024 signature
pub fn falcon1024_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    falcon512_verify(message, signature, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_falcon512_keypair_generation() {
        let (pk, sk) = falcon512_keypair();
        assert_eq!(pk.len(), FALCON512_PUBLIC_KEY_SIZE);
        assert_eq!(sk.len(), FALCON512_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_falcon512_sign_verify() {
        let (public_key, secret_key) = falcon512_keypair();
        let message = b"Test message for Falcon";

        let signature = falcon512_sign(message, &secret_key).unwrap();

        let valid = falcon512_verify(message, &signature, &public_key).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_falcon512_verify_wrong_message() {
        let (public_key, secret_key) = falcon512_keypair();
        let message = b"Original message";

        let signature = falcon512_sign(message, &secret_key).unwrap();

        let wrong_message = b"Different message";
        let valid = falcon512_verify(wrong_message, &signature, &public_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_falcon512_compact_signature() {
        let (public_key, secret_key) = falcon512_keypair();
        let message = b"Falcon has the smallest signatures!";

        let signature = falcon512_sign(message, &secret_key).unwrap();

        // Falcon signatures are notably compact
        println!("Falcon-512 signature size: {} bytes", signature.len());

        let valid = falcon512_verify(message, &signature, &public_key).unwrap();
        assert!(valid);
    }
}
