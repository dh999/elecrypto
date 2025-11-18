//! SLH-DSA (SPHINCS+) - Stateless Hash-Based Digital Signature Algorithm
//!
//! NIST standardized SPHINCS+ as SLH-DSA.
//!
//! ## Key Features
//!
//! - **Stateless** (unlike XMSS/LMS)
//! - Based only on hash functions (conservative security)
//! - Multiple variants with size/speed tradeoffs
//!
//! ## Variants
//!
//! We implement SHAKE variants:
//! - **SPHINCS+-SHAKE-128f**: Fast, Security Level 1
//! - **SPHINCS+-SHAKE-256f**: Fast, Security Level 5
//!
//! Note: 'f' = fast signing, 's' = small signatures (not implemented yet)
//!
//! ## Use Cases
//!
//! - Long-term signatures
//! - Conservative security (hash-based)
//! - When stateful signatures are not acceptable

use pqcrypto_sphincsplus::sphincssha256128fsimple as shake128f;
use pqcrypto_sphincsplus::sphincssha256256fsimple as shake256f;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use zeroize::Zeroizing;

use crate::{Error, Result};

// SPHINCS+-SHAKE-128f constants
/// SPHINCS+-SHAKE-128f public key size
pub const SPHINCS_SHAKE128F_PUBLIC_KEY_SIZE: usize = shake128f::public_key_bytes();
/// SPHINCS+-SHAKE-128f secret key size
pub const SPHINCS_SHAKE128F_SECRET_KEY_SIZE: usize = shake128f::secret_key_bytes();

// SPHINCS+-SHAKE-256f constants
/// SPHINCS+-SHAKE-256f public key size
pub const SPHINCS_SHAKE256F_PUBLIC_KEY_SIZE: usize = shake256f::public_key_bytes();
/// SPHINCS+-SHAKE-256f secret key size
pub const SPHINCS_SHAKE256F_SECRET_KEY_SIZE: usize = shake256f::secret_key_bytes();

/// Generate SPHINCS+-SHAKE-128f keypair
///
/// **Security Level**: NIST Level 1
/// **Variant**: Fast signing
///
/// # Returns
///
/// Tuple of (public_key, secret_key)
///
/// # Example
///
/// ```rust
/// use elecrypto_core::pqc::sphincsplus_shake_128f_keypair;
///
/// let (public_key, secret_key) = sphincsplus_shake_128f_keypair();
/// ```
pub fn sphincsplus_shake_128f_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let (pk, sk) = shake128f::keypair();
    (
        pk.as_bytes().to_vec(),
        Zeroizing::new(sk.as_bytes().to_vec()),
    )
}

/// Sign a message with SPHINCS+-SHAKE-128f
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
///
/// # Example
///
/// ```rust
/// use elecrypto_core::pqc::{sphincsplus_shake_128f_keypair, sphincsplus_shake_128f_sign};
///
/// let (public_key, secret_key) = sphincsplus_shake_128f_keypair();
/// let message = b"Important message";
/// let signature = sphincsplus_shake_128f_sign(message, &secret_key).unwrap();
/// ```
pub fn sphincsplus_shake_128f_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    if secret_key.len() != SPHINCS_SHAKE128F_SECRET_KEY_SIZE {
        return Err(Error::InvalidPrivateKey(format!(
            "Expected {} bytes, got {}",
            SPHINCS_SHAKE128F_SECRET_KEY_SIZE,
            secret_key.len()
        )));
    }

    let sk = shake128f::SecretKey::from_bytes(secret_key)
        .map_err(|e| Error::InvalidPrivateKey(format!("Failed to parse secret key: {:?}", e)))?;

    let signed = shake128f::sign(message, &sk);
    Ok(signed.as_bytes().to_vec())
}

/// Verify SPHINCS+-SHAKE-128f signature
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
/// use elecrypto_core::pqc::{
///     sphincsplus_shake_128f_keypair,
///     sphincsplus_shake_128f_sign,
///     sphincsplus_shake_128f_verify
/// };
///
/// let (public_key, secret_key) = sphincsplus_shake_128f_keypair();
/// let message = b"Important message";
/// let signature = sphincsplus_shake_128f_sign(message, &secret_key).unwrap();
/// let valid = sphincsplus_shake_128f_verify(message, &signature, &public_key).unwrap();
/// assert!(valid);
/// ```
pub fn sphincsplus_shake_128f_verify(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool> {
    if public_key.len() != SPHINCS_SHAKE128F_PUBLIC_KEY_SIZE {
        return Err(Error::InvalidPublicKey(format!(
            "Expected {} bytes, got {}",
            SPHINCS_SHAKE128F_PUBLIC_KEY_SIZE,
            public_key.len()
        )));
    }

    let pk = shake128f::PublicKey::from_bytes(public_key)
        .map_err(|e| Error::InvalidPublicKey(format!("Failed to parse public key: {:?}", e)))?;

    let signed_msg = shake128f::SignedMessage::from_bytes(signature)
        .map_err(|e| Error::InvalidSignature(format!("Failed to parse signature: {:?}", e)))?;

    match shake128f::open(&signed_msg, &pk) {
        Ok(opened_message) => Ok(opened_message == message),
        Err(_) => Ok(false),
    }
}

/// Generate SPHINCS+-SHAKE-256f keypair
///
/// **Security Level**: NIST Level 5
/// **Variant**: Fast signing
///
/// # Returns
///
/// Tuple of (public_key, secret_key)
pub fn sphincsplus_shake_256f_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let (pk, sk) = shake256f::keypair();
    (
        pk.as_bytes().to_vec(),
        Zeroizing::new(sk.as_bytes().to_vec()),
    )
}

/// Sign a message with SPHINCS+-SHAKE-256f
pub fn sphincsplus_shake_256f_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    if secret_key.len() != SPHINCS_SHAKE256F_SECRET_KEY_SIZE {
        return Err(Error::InvalidPrivateKey(format!(
            "Expected {} bytes, got {}",
            SPHINCS_SHAKE256F_SECRET_KEY_SIZE,
            secret_key.len()
        )));
    }

    let sk = shake256f::SecretKey::from_bytes(secret_key)
        .map_err(|e| Error::InvalidPrivateKey(format!("Failed to parse secret key: {:?}", e)))?;

    let signed = shake256f::sign(message, &sk);
    Ok(signed.as_bytes().to_vec())
}

/// Verify SPHINCS+-SHAKE-256f signature
pub fn sphincsplus_shake_256f_verify(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool> {
    if public_key.len() != SPHINCS_SHAKE256F_PUBLIC_KEY_SIZE {
        return Err(Error::InvalidPublicKey(format!(
            "Expected {} bytes, got {}",
            SPHINCS_SHAKE256F_PUBLIC_KEY_SIZE,
            public_key.len()
        )));
    }

    let pk = shake256f::PublicKey::from_bytes(public_key)
        .map_err(|e| Error::InvalidPublicKey(format!("Failed to parse public key: {:?}", e)))?;

    let signed_msg = shake256f::SignedMessage::from_bytes(signature)
        .map_err(|e| Error::InvalidSignature(format!("Failed to parse signature: {:?}", e)))?;

    match shake256f::open(&signed_msg, &pk) {
        Ok(opened_message) => Ok(opened_message == message),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincsplus_shake128f_keypair() {
        let (pk, sk) = sphincsplus_shake_128f_keypair();
        assert_eq!(pk.len(), SPHINCS_SHAKE128F_PUBLIC_KEY_SIZE);
        assert_eq!(sk.len(), SPHINCS_SHAKE128F_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_sphincsplus_shake128f_sign_verify() {
        let (public_key, secret_key) = sphincsplus_shake_128f_keypair();
        let message = b"Test message for SPHINCS+";

        let signature = sphincsplus_shake_128f_sign(message, &secret_key).unwrap();

        let valid = sphincsplus_shake_128f_verify(message, &signature, &public_key).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sphincsplus_shake128f_verify_wrong_message() {
        let (public_key, secret_key) = sphincsplus_shake_128f_keypair();
        let message = b"Original message";

        let signature = sphincsplus_shake_128f_sign(message, &secret_key).unwrap();

        let wrong_message = b"Different message";
        let valid =
            sphincsplus_shake_128f_verify(wrong_message, &signature, &public_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_sphincsplus_shake256f_keypair() {
        let (pk, sk) = sphincsplus_shake_256f_keypair();
        assert_eq!(pk.len(), SPHINCS_SHAKE256F_PUBLIC_KEY_SIZE);
        assert_eq!(sk.len(), SPHINCS_SHAKE256F_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_sphincsplus_shake256f_sign_verify() {
        let (public_key, secret_key) = sphincsplus_shake_256f_keypair();
        let message = b"High security SPHINCS+ test";

        let signature = sphincsplus_shake_256f_sign(message, &secret_key).unwrap();

        let valid = sphincsplus_shake_256f_verify(message, &signature, &public_key).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sphincsplus_hash_based_security() {
        // SPHINCS+ is stateless and hash-based
        // This makes it conservative but slower
        let (public_key, secret_key) = sphincsplus_shake_128f_keypair();
        let message = b"Hash-based signatures are quantum-safe";

        let signature = sphincsplus_shake_128f_sign(message, &secret_key).unwrap();

        println!(
            "SPHINCS+-SHAKE-128f signature size: {} bytes",
            signature.len()
        );

        let valid = sphincsplus_shake_128f_verify(message, &signature, &public_key).unwrap();
        assert!(valid);
    }
}
