//! RSA-OAEP encryption
//!
//! RSA encryption using Optimal Asymmetric Encryption Padding (OAEP)
//! with SHA-256 hash function.

use rsa::{
    RsaPrivateKey as RsaPrivKey, RsaPublicKey as RsaPubKey,
    pkcs8::{EncodePublicKey, EncodePrivateKey, DecodePublicKey, DecodePrivateKey},
};
use rsa::Oaep;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// RSA key sizes
#[derive(Debug, Clone, Copy)]
pub enum RsaKeySize {
    /// 2048-bit RSA key (secure for most applications)
    Rsa2048 = 2048,
    /// 3072-bit RSA key (high security)
    Rsa3072 = 3072,
    /// 4096-bit RSA key (maximum security)
    Rsa4096 = 4096,
}

/// RSA public key wrapper
#[derive(Clone)]
pub struct RsaPublicKey(RsaPubKey);

/// RSA private key wrapper
pub struct RsaPrivateKey(RsaPrivKey);

/// Generate RSA key pair
///
/// # Arguments
///
/// * `key_size` - The size of the RSA key (2048, 3072, or 4096 bits)
///
/// # Returns
///
/// A tuple of (public_key, private_key) both in DER format
///
/// # Example
///
/// ```rust
/// use elecrypto_core::asymmetric::{rsa_generate_keypair, RsaKeySize};
///
/// let (public_key, private_key) = rsa_generate_keypair(RsaKeySize::Rsa2048).unwrap();
/// ```
pub fn rsa_generate_keypair(key_size: RsaKeySize) -> Result<(RsaPublicKey, RsaPrivateKey)> {
    // Use system RNG for key generation
    let mut rng = rand::thread_rng();

    let bits = key_size as usize;
    let private_key = RsaPrivKey::new(&mut rng, bits)
        .map_err(|e| Error::KeyGenerationFailed(format!("RSA key generation failed: {}", e)))?;

    let public_key = private_key.to_public_key();

    Ok((RsaPublicKey(public_key), RsaPrivateKey(private_key)))
}

/// Encrypt data using RSA-OAEP with SHA-256
///
/// # Arguments
///
/// * `plaintext` - The data to encrypt (must be smaller than key size - padding)
/// * `public_key` - The RSA public key
///
/// # Returns
///
/// The encrypted ciphertext
///
/// # Example
///
/// ```rust
/// use elecrypto_core::asymmetric::{rsa_generate_keypair, rsa_encrypt, RsaKeySize};
///
/// let (public_key, _) = rsa_generate_keypair(RsaKeySize::Rsa2048).unwrap();
/// let plaintext = b"Secret message";
/// let ciphertext = rsa_encrypt(plaintext, &public_key).unwrap();
/// ```
pub fn rsa_encrypt(plaintext: &[u8], public_key: &RsaPublicKey) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let padding = Oaep::new::<Sha256>();

    let ciphertext = public_key.0
        .encrypt(&mut rng, padding, plaintext)
        .map_err(|e| Error::EncryptionFailed(format!("RSA encryption failed: {}", e)))?;

    Ok(ciphertext)
}

/// Decrypt data using RSA-OAEP with SHA-256
///
/// # Arguments
///
/// * `ciphertext` - The encrypted data
/// * `private_key` - The RSA private key
///
/// # Returns
///
/// The decrypted plaintext
///
/// # Example
///
/// ```rust
/// use elecrypto_core::asymmetric::{rsa_generate_keypair, rsa_encrypt, rsa_decrypt, RsaKeySize};
///
/// let (public_key, private_key) = rsa_generate_keypair(RsaKeySize::Rsa2048).unwrap();
/// let plaintext = b"Secret message";
///
/// let ciphertext = rsa_encrypt(plaintext, &public_key).unwrap();
/// let decrypted = rsa_decrypt(&ciphertext, &private_key).unwrap();
///
/// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
/// ```
pub fn rsa_decrypt(ciphertext: &[u8], private_key: &RsaPrivateKey) -> Result<Zeroizing<Vec<u8>>> {
    let padding = Oaep::new::<Sha256>();

    let plaintext = private_key.0
        .decrypt(padding, ciphertext)
        .map_err(|e| Error::DecryptionFailed(format!("RSA decryption failed: {}", e)))?;

    Ok(Zeroizing::new(plaintext))
}

/// Convert RSA public key to DER format
pub fn rsa_public_key_to_der(public_key: &RsaPublicKey) -> Result<Vec<u8>> {
    public_key.0
        .to_public_key_der()
        .map(|der| der.to_vec())
        .map_err(|e| Error::EncodingFailed(format!("Failed to encode public key: {}", e)))
}

/// Convert RSA private key to DER format
pub fn rsa_private_key_to_der(private_key: &RsaPrivateKey) -> Result<Zeroizing<Vec<u8>>> {
    private_key.0
        .to_pkcs8_der()
        .map(|der| Zeroizing::new(der.to_bytes().to_vec()))
        .map_err(|e| Error::EncodingFailed(format!("Failed to encode private key: {}", e)))
}

/// Parse RSA public key from DER format
pub fn rsa_public_key_from_der(der: &[u8]) -> Result<RsaPublicKey> {
    RsaPubKey::from_public_key_der(der)
        .map(RsaPublicKey)
        .map_err(|e| Error::DecodingFailed(format!("Failed to decode public key: {}", e)))
}

/// Parse RSA private key from DER format
pub fn rsa_private_key_from_der(der: &[u8]) -> Result<RsaPrivateKey> {
    RsaPrivKey::from_pkcs8_der(der)
        .map(RsaPrivateKey)
        .map_err(|e| Error::DecodingFailed(format!("Failed to decode private key: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_key_generation() {
        let result = rsa_generate_keypair(RsaKeySize::Rsa2048);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rsa_encrypt_decrypt() {
        let (public_key, private_key) = rsa_generate_keypair(RsaKeySize::Rsa2048).unwrap();
        let plaintext = b"Hello, RSA-OAEP!";

        let ciphertext = rsa_encrypt(plaintext, &public_key).unwrap();
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        let decrypted = rsa_decrypt(&ciphertext, &private_key).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_rsa_different_ciphertexts() {
        let (public_key, _) = rsa_generate_keypair(RsaKeySize::Rsa2048).unwrap();
        let plaintext = b"Same message";

        let ciphertext1 = rsa_encrypt(plaintext, &public_key).unwrap();
        let ciphertext2 = rsa_encrypt(plaintext, &public_key).unwrap();

        // OAEP uses random padding, so same plaintext produces different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_rsa_key_serialization() {
        let (public_key, private_key) = rsa_generate_keypair(RsaKeySize::Rsa2048).unwrap();

        let pub_der = rsa_public_key_to_der(&public_key).unwrap();
        let priv_der = rsa_private_key_to_der(&private_key).unwrap();

        let loaded_pub = rsa_public_key_from_der(&pub_der).unwrap();
        let loaded_priv = rsa_private_key_from_der(&priv_der).unwrap();

        // Test that loaded keys work
        let plaintext = b"Test serialization";
        let ciphertext = rsa_encrypt(plaintext, &loaded_pub).unwrap();
        let decrypted = rsa_decrypt(&ciphertext, &loaded_priv).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_rsa_large_plaintext() {
        let (public_key, private_key) = rsa_generate_keypair(RsaKeySize::Rsa2048).unwrap();
        // For RSA-2048 with OAEP-SHA256, max plaintext is about 190 bytes
        let plaintext = vec![42u8; 100];

        let ciphertext = rsa_encrypt(&plaintext, &public_key).unwrap();
        let decrypted = rsa_decrypt(&ciphertext, &private_key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_rsa_empty_plaintext() {
        let (public_key, private_key) = rsa_generate_keypair(RsaKeySize::Rsa2048).unwrap();
        let plaintext = b"";

        let ciphertext = rsa_encrypt(plaintext, &public_key).unwrap();
        let decrypted = rsa_decrypt(&ciphertext, &private_key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_rsa_wrong_key_fails() {
        let (public_key1, _) = rsa_generate_keypair(RsaKeySize::Rsa2048).unwrap();
        let (_, private_key2) = rsa_generate_keypair(RsaKeySize::Rsa2048).unwrap();

        let plaintext = b"Secret";
        let ciphertext = rsa_encrypt(plaintext, &public_key1).unwrap();

        // Decrypting with wrong private key should fail
        let result = rsa_decrypt(&ciphertext, &private_key2);
        assert!(result.is_err());
    }
}
