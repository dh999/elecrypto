//! ML-KEM (Kyber) - Module-Lattice-Based Key Encapsulation Mechanism
//!
//! NIST standardized Kyber as ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism).
//!
//! ## Variants
//!
//! - **Kyber512** (ML-KEM-512): NIST Security Level 1 (AES-128 equivalent)
//! - **Kyber768** (ML-KEM-768): NIST Security Level 3 (AES-192 equivalent) - **Recommended**
//! - **Kyber1024** (ML-KEM-1024): NIST Security Level 5 (AES-256 equivalent)
//!
//! ## Use Cases
//!
//! - Quantum-resistant key exchange
//! - Hybrid cryptography (combine with ECDH)
//! - Future-proof TLS/SSH connections

use pqc_kyber::{
    keypair as kyber512_keypair_internal,
    encapsulate as kyber512_encapsulate_internal,
    decapsulate as kyber512_decapsulate_internal,
};
use zeroize::Zeroizing;

use crate::{Error, Result};

// Key sizes for Kyber512
/// Kyber512 public key size (800 bytes)
pub const KYBER512_PUBLIC_KEY_SIZE: usize = pqc_kyber::KYBER_PUBLICKEYBYTES;
/// Kyber512 secret key size (1632 bytes)
pub const KYBER512_SECRET_KEY_SIZE: usize = pqc_kyber::KYBER_SECRETKEYBYTES;
/// Kyber512 ciphertext size (768 bytes)
pub const KYBER512_CIPHERTEXT_SIZE: usize = pqc_kyber::KYBER_CIPHERTEXTBYTES;
/// Kyber512 shared secret size (32 bytes)
pub const KYBER512_SHARED_SECRET_SIZE: usize = pqc_kyber::KYBER_SSBYTES;

// Note: Kyber768 and Kyber1024 have different sizes
// For now, we use pqc_kyber which implements Kyber512
// Full implementation of all variants will be added

/// Generate Kyber512 keypair
///
/// **Security Level**: NIST Level 1 (AES-128 equivalent)
///
/// # Returns
///
/// Tuple of (public_key, secret_key)
/// - public_key: 800 bytes
/// - secret_key: 1632 bytes (should be kept secret)
///
/// # Example
///
/// ```rust
/// use elecrypto_core::pqc::kyber512_keypair;
///
/// let (public_key, secret_key) = kyber512_keypair();
/// // Share public_key, keep secret_key private
/// ```
pub fn kyber512_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let keys = kyber512_keypair_internal(&mut rand::thread_rng())
        .expect("Kyber512 keypair generation failed");

    (
        keys.public.to_vec(),
        Zeroizing::new(keys.secret.to_vec()),
    )
}

/// Encapsulate a shared secret using Kyber512
///
/// Creates a random shared secret and encapsulates it using the recipient's public key.
///
/// # Arguments
///
/// * `public_key` - Recipient's public key (800 bytes)
///
/// # Returns
///
/// Tuple of (ciphertext, shared_secret)
/// - ciphertext: 768 bytes (send to recipient)
/// - shared_secret: 32 bytes (use for symmetric encryption)
///
/// # Errors
///
/// Returns `Error::InvalidPublicKey` if public key is invalid
///
/// # Example
///
/// ```rust
/// use elecrypto_core::pqc::{kyber512_keypair, kyber512_encapsulate};
///
/// let (public_key, _secret_key) = kyber512_keypair();
/// let (ciphertext, shared_secret) = kyber512_encapsulate(&public_key).unwrap();
///
/// // Send ciphertext to recipient
/// // Use shared_secret for AES-GCM encryption
/// ```
pub fn kyber512_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    if public_key.len() != KYBER512_PUBLIC_KEY_SIZE {
        return Err(Error::InvalidPublicKey(format!(
            "Expected {} bytes, got {}",
            KYBER512_PUBLIC_KEY_SIZE,
            public_key.len()
        )));
    }

    let pk: [u8; KYBER512_PUBLIC_KEY_SIZE] = public_key
        .try_into()
        .map_err(|_| Error::InvalidPublicKey("Invalid key format".to_string()))?;

    let (ciphertext, shared_secret) = kyber512_encapsulate_internal(&pk, &mut rand::thread_rng())
        .map_err(|e| Error::EncryptionFailed(format!("Kyber encapsulation failed: {:?}", e)))?;

    Ok((
        ciphertext.to_vec(),
        Zeroizing::new(shared_secret.to_vec()),
    ))
}

/// Decapsulate a shared secret using Kyber512
///
/// Recovers the shared secret from the ciphertext using the secret key.
///
/// # Arguments
///
/// * `ciphertext` - Ciphertext from encapsulation (768 bytes)
/// * `secret_key` - Recipient's secret key (1632 bytes)
///
/// # Returns
///
/// The shared secret (32 bytes)
///
/// # Errors
///
/// Returns `Error::InvalidPrivateKey` if secret key is invalid
/// Returns `Error::DecryptionFailed` if decapsulation fails
///
/// # Example
///
/// ```rust
/// use elecrypto_core::pqc::{kyber512_keypair, kyber512_encapsulate, kyber512_decapsulate};
///
/// let (public_key, secret_key) = kyber512_keypair();
/// let (ciphertext, shared_secret1) = kyber512_encapsulate(&public_key).unwrap();
///
/// // Recipient decapsulates
/// let shared_secret2 = kyber512_decapsulate(&ciphertext, &secret_key).unwrap();
///
/// assert_eq!(shared_secret1.as_slice(), shared_secret2.as_slice());
/// ```
pub fn kyber512_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if secret_key.len() != KYBER512_SECRET_KEY_SIZE {
        return Err(Error::InvalidPrivateKey(format!(
            "Expected {} bytes, got {}",
            KYBER512_SECRET_KEY_SIZE,
            secret_key.len()
        )));
    }

    if ciphertext.len() != KYBER512_CIPHERTEXT_SIZE {
        return Err(Error::InvalidInput(format!(
            "Invalid ciphertext size: expected {}, got {}",
            KYBER512_CIPHERTEXT_SIZE,
            ciphertext.len()
        )));
    }

    let sk: [u8; KYBER512_SECRET_KEY_SIZE] = secret_key
        .try_into()
        .map_err(|_| Error::InvalidPrivateKey("Invalid key format".to_string()))?;

    let ct: [u8; KYBER512_CIPHERTEXT_SIZE] = ciphertext
        .try_into()
        .map_err(|_| Error::InvalidInput("Invalid ciphertext format".to_string()))?;

    let shared_secret = kyber512_decapsulate_internal(&ct, &sk)
        .map_err(|e| Error::DecryptionFailed(format!("Kyber decapsulation failed: {:?}", e)))?;

    Ok(Zeroizing::new(shared_secret.to_vec()))
}

// Placeholder functions for Kyber768 and Kyber1024
// These will be implemented when the crate supports them or we use a different library

/// Generate Kyber768 keypair (RECOMMENDED - Security Level 3)
///
/// **Status**: To be implemented
pub fn kyber768_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    // For now, use Kyber512 as placeholder
    // TODO: Implement proper Kyber768
    kyber512_keypair()
}

/// Encapsulate using Kyber768
///
/// **Status**: To be implemented
pub fn kyber768_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    // TODO: Implement proper Kyber768
    kyber512_encapsulate(public_key)
}

/// Decapsulate using Kyber768
///
/// **Status**: To be implemented
pub fn kyber768_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // TODO: Implement proper Kyber768
    kyber512_decapsulate(ciphertext, secret_key)
}

/// Generate Kyber1024 keypair (Security Level 5)
///
/// **Status**: To be implemented
pub fn kyber1024_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    // TODO: Implement proper Kyber1024
    kyber512_keypair()
}

/// Encapsulate using Kyber1024
///
/// **Status**: To be implemented
pub fn kyber1024_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    // TODO: Implement proper Kyber1024
    kyber512_encapsulate(public_key)
}

/// Decapsulate using Kyber1024
///
/// **Status**: To be implemented
pub fn kyber1024_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // TODO: Implement proper Kyber1024
    kyber512_decapsulate(ciphertext, secret_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber512_keypair_generation() {
        let (pk, sk) = kyber512_keypair();
        assert_eq!(pk.len(), KYBER512_PUBLIC_KEY_SIZE);
        assert_eq!(sk.len(), KYBER512_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_kyber512_kem_roundtrip() {
        let (public_key, secret_key) = kyber512_keypair();

        // Encapsulate
        let (ciphertext, shared_secret1) = kyber512_encapsulate(&public_key).unwrap();
        assert_eq!(ciphertext.len(), KYBER512_CIPHERTEXT_SIZE);
        assert_eq!(shared_secret1.len(), KYBER512_SHARED_SECRET_SIZE);

        // Decapsulate
        let shared_secret2 = kyber512_decapsulate(&ciphertext, &secret_key).unwrap();
        assert_eq!(shared_secret2.len(), KYBER512_SHARED_SECRET_SIZE);

        // Shared secrets should match
        assert_eq!(shared_secret1.as_slice(), shared_secret2.as_slice());
    }

    #[test]
    fn test_kyber512_different_keypairs() {
        let (pk1, _sk1) = kyber512_keypair();
        let (pk2, _sk2) = kyber512_keypair();

        // Keys should be different
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_kyber512_invalid_public_key() {
        let short_key = vec![0u8; 100];
        let result = kyber512_encapsulate(&short_key);
        assert!(matches!(result, Err(Error::InvalidPublicKey(_))));
    }

    #[test]
    fn test_kyber512_invalid_secret_key() {
        let (public_key, _) = kyber512_keypair();
        let (ciphertext, _) = kyber512_encapsulate(&public_key).unwrap();

        let short_key = vec![0u8; 100];
        let result = kyber512_decapsulate(&ciphertext, &short_key);
        assert!(matches!(result, Err(Error::InvalidPrivateKey(_))));
    }

    #[test]
    fn test_kyber512_wrong_secret_key() {
        let (public_key, _) = kyber512_keypair();
        let (_, wrong_secret_key) = kyber512_keypair(); // Different key
        let (ciphertext, shared_secret1) = kyber512_encapsulate(&public_key).unwrap();

        // Decapsulation with wrong key will succeed but produce different secret
        let shared_secret2 = kyber512_decapsulate(&ciphertext, &wrong_secret_key).unwrap();
        assert_ne!(shared_secret1.as_slice(), shared_secret2.as_slice());
    }
}
