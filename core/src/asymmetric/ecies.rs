//! ECIES (Elliptic Curve Integrated Encryption Scheme)
//!
//! Hybrid encryption using:
//! - P-256 elliptic curve for key exchange (ECDH)
//! - HKDF-SHA256 for key derivation
//! - AES-256-GCM for symmetric encryption

use p256::{
    SecretKey,
    ecdh::EphemeralSecret,
    PublicKey as P256PublicKey,
    EncodedPoint,
};
use p256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};
use crate::symmetric::{aes_gcm_encrypt, aes_gcm_decrypt};

/// ECIES public key (P-256)
#[derive(Clone)]
pub struct EciesPublicKey(P256PublicKey);

/// ECIES private key (P-256)
pub struct EciesPrivateKey(Zeroizing<Vec<u8>>);

const P256_PUBLIC_KEY_SIZE: usize = 65; // Uncompressed point: 04 || X || Y
const P256_PRIVATE_KEY_SIZE: usize = 32;
const AES_KEY_SIZE: usize = 32;

/// Generate ECIES key pair using P-256 curve
///
/// # Returns
///
/// A tuple of (public_key, private_key)
///
/// # Example
///
/// ```rust
/// use elecrypto_core::asymmetric::ecies_generate_keypair;
///
/// let (public_key, private_key) = ecies_generate_keypair().unwrap();
/// ```
pub fn ecies_generate_keypair() -> Result<(EciesPublicKey, EciesPrivateKey)> {
    let secret = SecretKey::random(&mut rand::thread_rng());
    let public_key = secret.public_key();

    // Extract private key bytes
    let private_bytes = secret.to_bytes();

    Ok((
        EciesPublicKey(public_key),
        EciesPrivateKey(Zeroizing::new(private_bytes.to_vec()))
    ))
}

/// Encrypt data using ECIES
///
/// # Arguments
///
/// * `plaintext` - The data to encrypt
/// * `public_key` - The recipient's ECIES public key
///
/// # Returns
///
/// The encrypted data containing: ephemeral_public_key || ciphertext || nonce
///
/// # Example
///
/// ```rust
/// use elecrypto_core::asymmetric::{ecies_generate_keypair, ecies_encrypt};
///
/// let (public_key, _) = ecies_generate_keypair().unwrap();
/// let plaintext = b"Secret message";
/// let ciphertext = ecies_encrypt(plaintext, &public_key).unwrap();
/// ```
pub fn ecies_encrypt(plaintext: &[u8], public_key: &EciesPublicKey) -> Result<Vec<u8>> {
    // Generate ephemeral key pair
    let ephemeral_secret = EphemeralSecret::random(&mut rand::thread_rng());
    let ephemeral_public = ephemeral_secret.public_key();

    // Perform ECDH
    let shared_secret = ephemeral_secret.diffie_hellman(&public_key.0);

    // Derive encryption key using HKDF
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes().as_ref());
    let mut derived_key = Zeroizing::new(vec![0u8; AES_KEY_SIZE]);
    hkdf.expand(b"ecies-aes-key", &mut derived_key)
        .map_err(|e| Error::KeyDerivationFailed(format!("HKDF expansion failed: {}", e)))?;

    // Encrypt using AES-256-GCM
    let (ciphertext, nonce) = aes_gcm_encrypt(plaintext, &derived_key, None, None)?;

    // Encode ephemeral public key
    let ephemeral_public_bytes = ephemeral_public.to_encoded_point(false);
    let ephemeral_public_vec = ephemeral_public_bytes.as_bytes();

    // Combine: ephemeral_public || ciphertext || nonce
    let mut result = Vec::with_capacity(
        ephemeral_public_vec.len() + ciphertext.len() + nonce.len()
    );
    result.extend_from_slice(ephemeral_public_vec);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&nonce);

    Ok(result)
}

/// Decrypt data using ECIES
///
/// # Arguments
///
/// * `ciphertext` - The encrypted data (ephemeral_public_key || ciphertext || nonce)
/// * `private_key` - The recipient's ECIES private key
///
/// # Returns
///
/// The decrypted plaintext
///
/// # Example
///
/// ```rust
/// use elecrypto_core::asymmetric::{ecies_generate_keypair, ecies_encrypt, ecies_decrypt};
///
/// let (public_key, private_key) = ecies_generate_keypair().unwrap();
/// let plaintext = b"Secret message";
///
/// let ciphertext = ecies_encrypt(plaintext, &public_key).unwrap();
/// let decrypted = ecies_decrypt(&ciphertext, &private_key).unwrap();
///
/// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
/// ```
pub fn ecies_decrypt(ciphertext: &[u8], private_key: &EciesPrivateKey) -> Result<Zeroizing<Vec<u8>>> {
    // Parse components
    if ciphertext.len() < P256_PUBLIC_KEY_SIZE + 16 + 12 {
        return Err(Error::InvalidInput("Ciphertext too short".to_string()));
    }

    let ephemeral_public_bytes = &ciphertext[..P256_PUBLIC_KEY_SIZE];
    let nonce = &ciphertext[ciphertext.len() - 12..];
    let encrypted_data = &ciphertext[P256_PUBLIC_KEY_SIZE..ciphertext.len() - 12];

    // Decode ephemeral public key
    let ephemeral_public_point = EncodedPoint::from_bytes(ephemeral_public_bytes)
        .map_err(|e| Error::DecodingFailed(format!("Failed to decode ephemeral public key: {}", e)))?;

    let ephemeral_public = P256PublicKey::from_encoded_point(&ephemeral_public_point)
        .into_option()
        .ok_or_else(|| Error::DecodingFailed("Invalid ephemeral public key".to_string()))?;

    // Reconstruct private key
    let private_scalar = p256::SecretKey::from_bytes(private_key.0.as_slice().into())
        .map_err(|e| Error::DecodingFailed(format!("Failed to decode private key: {}", e)))?;

    // Perform ECDH
    let shared_secret = p256::ecdh::diffie_hellman(
        private_scalar.to_nonzero_scalar(),
        ephemeral_public.as_affine()
    );

    // Derive decryption key using HKDF
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes().as_ref());
    let mut derived_key = Zeroizing::new(vec![0u8; AES_KEY_SIZE]);
    hkdf.expand(b"ecies-aes-key", &mut derived_key)
        .map_err(|e| Error::KeyDerivationFailed(format!("HKDF expansion failed: {}", e)))?;

    // Decrypt using AES-256-GCM
    let plaintext = aes_gcm_decrypt(encrypted_data, &derived_key, nonce, None)?;

    Ok(plaintext)
}

/// Convert ECIES public key to bytes
pub fn ecies_public_key_to_bytes(public_key: &EciesPublicKey) -> Vec<u8> {
    public_key.0.to_encoded_point(false).as_bytes().to_vec()
}

/// Convert ECIES private key to bytes
pub fn ecies_private_key_to_bytes(private_key: &EciesPrivateKey) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(private_key.0.to_vec())
}

/// Parse ECIES public key from bytes
pub fn ecies_public_key_from_bytes(bytes: &[u8]) -> Result<EciesPublicKey> {
    if bytes.len() != P256_PUBLIC_KEY_SIZE {
        return Err(Error::InvalidInput(format!(
            "Invalid public key length: expected {}, got {}",
            P256_PUBLIC_KEY_SIZE, bytes.len()
        )));
    }

    let point = EncodedPoint::from_bytes(bytes)
        .map_err(|e| Error::DecodingFailed(format!("Failed to decode public key: {}", e)))?;

    let public_key = P256PublicKey::from_encoded_point(&point)
        .into_option()
        .ok_or_else(|| Error::DecodingFailed("Invalid public key point".to_string()))?;

    Ok(EciesPublicKey(public_key))
}

/// Parse ECIES private key from bytes
pub fn ecies_private_key_from_bytes(bytes: &[u8]) -> Result<EciesPrivateKey> {
    if bytes.len() != P256_PRIVATE_KEY_SIZE {
        return Err(Error::InvalidInput(format!(
            "Invalid private key length: expected {}, got {}",
            P256_PRIVATE_KEY_SIZE, bytes.len()
        )));
    }

    // Validate that it's a valid private key
    let _ = p256::SecretKey::from_bytes(bytes.into())
        .map_err(|e| Error::DecodingFailed(format!("Invalid private key: {}", e)))?;

    Ok(EciesPrivateKey(Zeroizing::new(bytes.to_vec())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecies_key_generation() {
        let result = ecies_generate_keypair();
        assert!(result.is_ok());
    }

    #[test]
    fn test_ecies_encrypt_decrypt() {
        let (public_key, private_key) = ecies_generate_keypair().unwrap();
        let plaintext = b"Hello, ECIES!";

        let ciphertext = ecies_encrypt(plaintext, &public_key).unwrap();
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        let decrypted = ecies_decrypt(&ciphertext, &private_key).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_ecies_different_ciphertexts() {
        let (public_key, _) = ecies_generate_keypair().unwrap();
        let plaintext = b"Same message";

        let ciphertext1 = ecies_encrypt(plaintext, &public_key).unwrap();
        let ciphertext2 = ecies_encrypt(plaintext, &public_key).unwrap();

        // ECIES uses ephemeral keys, so same plaintext produces different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_ecies_key_serialization() {
        let (public_key, private_key) = ecies_generate_keypair().unwrap();

        let pub_bytes = ecies_public_key_to_bytes(&public_key);
        let priv_bytes = ecies_private_key_to_bytes(&private_key);

        let loaded_pub = ecies_public_key_from_bytes(&pub_bytes).unwrap();
        let loaded_priv = ecies_private_key_from_bytes(&priv_bytes).unwrap();

        // Test that loaded keys work
        let plaintext = b"Test serialization";
        let ciphertext = ecies_encrypt(plaintext, &loaded_pub).unwrap();
        let decrypted = ecies_decrypt(&ciphertext, &loaded_priv).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_ecies_empty_plaintext() {
        let (public_key, private_key) = ecies_generate_keypair().unwrap();
        let plaintext = b"";

        let ciphertext = ecies_encrypt(plaintext, &public_key).unwrap();
        let decrypted = ecies_decrypt(&ciphertext, &private_key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_ecies_large_plaintext() {
        let (public_key, private_key) = ecies_generate_keypair().unwrap();
        let plaintext = vec![42u8; 10000];

        let ciphertext = ecies_encrypt(&plaintext, &public_key).unwrap();
        let decrypted = ecies_decrypt(&ciphertext, &private_key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_ecies_wrong_key_fails() {
        let (public_key1, _) = ecies_generate_keypair().unwrap();
        let (_, private_key2) = ecies_generate_keypair().unwrap();

        let plaintext = b"Secret";
        let ciphertext = ecies_encrypt(plaintext, &public_key1).unwrap();

        // Decrypting with wrong private key should fail (authentication error)
        let result = ecies_decrypt(&ciphertext, &private_key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecies_modified_ciphertext_fails() {
        let (public_key, private_key) = ecies_generate_keypair().unwrap();
        let plaintext = b"Secret";

        let mut ciphertext = ecies_encrypt(plaintext, &public_key).unwrap();

        // Modify the ciphertext (not the ephemeral key or nonce)
        if ciphertext.len() > P256_PUBLIC_KEY_SIZE + 12 {
            ciphertext[P256_PUBLIC_KEY_SIZE] ^= 0xFF;
        }

        // Should fail authentication
        let result = ecies_decrypt(&ciphertext, &private_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecies_public_key_size() {
        let (public_key, _) = ecies_generate_keypair().unwrap();
        let bytes = ecies_public_key_to_bytes(&public_key);

        assert_eq!(bytes.len(), P256_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_ecies_private_key_size() {
        let (_, private_key) = ecies_generate_keypair().unwrap();
        let bytes = ecies_private_key_to_bytes(&private_key);

        assert_eq!(bytes.len(), P256_PRIVATE_KEY_SIZE);
    }
}
