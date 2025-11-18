//! Ed25519 digital signatures

use ed25519_dalek::{
    Signer, Verifier,
    SigningKey, VerifyingKey, Signature,
};
use zeroize::Zeroizing;

use crate::{Error, Result};
use crate::random::random_bytes;

/// Ed25519 public key size in bytes
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 private key size in bytes (seed)
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Generate Ed25519 key pair
///
/// # Returns
///
/// Tuple of (public_key, private_key)
/// - public_key: 32 bytes
/// - private_key: 32 bytes (secret seed)
///
/// # Example
///
/// ```rust
/// use elecrypto_core::signing::ed25519_generate_keypair;
///
/// let (public_key, private_key) = ed25519_generate_keypair();
/// assert_eq!(public_key.len(), 32);
/// assert_eq!(private_key.len(), 32);
/// ```
pub fn ed25519_generate_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let seed = random_bytes(ED25519_PRIVATE_KEY_SIZE);
    let signing_key = SigningKey::from_bytes(&seed.as_slice().try_into().unwrap());
    let verifying_key = signing_key.verifying_key();

    let public_key = verifying_key.to_bytes().to_vec();
    let private_key = Zeroizing::new(seed.to_vec());

    (public_key, private_key)
}

/// Sign a message with Ed25519
///
/// # Arguments
///
/// * `message` - Message to sign
/// * `private_key` - 32-byte private key (secret seed)
///
/// # Returns
///
/// 64-byte signature
///
/// # Errors
///
/// Returns `Error::InvalidPrivateKey` if private key is invalid
/// Returns `Error::SigningFailed` if signing fails
///
/// # Example
///
/// ```rust
/// use elecrypto_core::signing::{ed25519_generate_keypair, ed25519_sign};
///
/// let (public_key, private_key) = ed25519_generate_keypair();
/// let message = b"Important message";
///
/// let signature = ed25519_sign(message, &private_key).unwrap();
/// assert_eq!(signature.len(), 64);
/// ```
pub fn ed25519_sign(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    // Validate private key length
    if private_key.len() != ED25519_PRIVATE_KEY_SIZE {
        return Err(Error::InvalidPrivateKey(format!(
            "Expected {} bytes, got {}",
            ED25519_PRIVATE_KEY_SIZE,
            private_key.len()
        )));
    }

    // Create signing key
    let key_bytes: [u8; 32] = private_key
        .try_into()
        .map_err(|_| Error::InvalidPrivateKey("Invalid key format".to_string()))?;

    let signing_key = SigningKey::from_bytes(&key_bytes);

    // Sign message
    let signature = signing_key.sign(message);

    Ok(signature.to_bytes().to_vec())
}

/// Verify Ed25519 signature
///
/// # Arguments
///
/// * `message` - Original message
/// * `signature` - 64-byte signature
/// * `public_key` - 32-byte public key
///
/// # Returns
///
/// `true` if signature is valid, `false` otherwise
///
/// # Errors
///
/// Returns `Error::InvalidPublicKey` if public key is invalid
/// Returns `Error::InvalidSignature` if signature format is invalid
///
/// # Example
///
/// ```rust
/// use elecrypto_core::signing::{ed25519_generate_keypair, ed25519_sign, ed25519_verify};
///
/// let (public_key, private_key) = ed25519_generate_keypair();
/// let message = b"Important message";
///
/// let signature = ed25519_sign(message, &private_key).unwrap();
/// let valid = ed25519_verify(message, &signature, &public_key).unwrap();
///
/// assert!(valid);
/// ```
pub fn ed25519_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    // Validate public key length
    if public_key.len() != ED25519_PUBLIC_KEY_SIZE {
        return Err(Error::InvalidPublicKey(format!(
            "Expected {} bytes, got {}",
            ED25519_PUBLIC_KEY_SIZE,
            public_key.len()
        )));
    }

    // Validate signature length
    if signature.len() != ED25519_SIGNATURE_SIZE {
        return Err(Error::InvalidSignature(format!(
            "Expected {} bytes, got {}",
            ED25519_SIGNATURE_SIZE,
            signature.len()
        )));
    }

    // Parse public key
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| Error::InvalidPublicKey("Invalid key format".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| Error::InvalidPublicKey(format!("Failed to parse public key: {}", e)))?;

    // Parse signature
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| Error::InvalidSignature("Invalid signature format".to_string()))?;

    let sig = Signature::from_bytes(&sig_bytes);

    // Verify signature
    Ok(verifying_key.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (public_key, private_key) = ed25519_generate_keypair();

        assert_eq!(public_key.len(), ED25519_PUBLIC_KEY_SIZE);
        assert_eq!(private_key.len(), ED25519_PRIVATE_KEY_SIZE);

        // Keys should be different each time
        let (public_key2, private_key2) = ed25519_generate_keypair();
        assert_ne!(public_key, public_key2);
        assert_ne!(private_key.as_slice(), private_key2.as_slice());
    }

    #[test]
    fn test_sign_and_verify() {
        let (public_key, private_key) = ed25519_generate_keypair();
        let message = b"Test message";

        let signature = ed25519_sign(message, &private_key).unwrap();
        assert_eq!(signature.len(), ED25519_SIGNATURE_SIZE);

        let valid = ed25519_verify(message, &signature, &public_key).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_message() {
        let (public_key, private_key) = ed25519_generate_keypair();
        let message = b"Original message";

        let signature = ed25519_sign(message, &private_key).unwrap();

        // Try to verify different message
        let wrong_message = b"Different message";
        let valid = ed25519_verify(wrong_message, &signature, &public_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_wrong_public_key() {
        let (_, private_key) = ed25519_generate_keypair();
        let (wrong_public_key, _) = ed25519_generate_keypair();
        let message = b"Test message";

        let signature = ed25519_sign(message, &private_key).unwrap();

        let valid = ed25519_verify(message, &signature, &wrong_public_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_modified_signature() {
        let (public_key, private_key) = ed25519_generate_keypair();
        let message = b"Test message";

        let mut signature = ed25519_sign(message, &private_key).unwrap();

        // Modify signature
        signature[0] ^= 0xFF;

        let valid = ed25519_verify(message, &signature, &public_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_invalid_private_key_length() {
        let short_key = vec![0u8; 16];
        let message = b"Test";

        let result = ed25519_sign(message, &short_key);
        assert!(matches!(result, Err(Error::InvalidPrivateKey(_))));
    }

    #[test]
    fn test_invalid_public_key_length() {
        let (_, private_key) = ed25519_generate_keypair();
        let message = b"Test";
        let short_key = vec![0u8; 16];

        let signature = ed25519_sign(message, &private_key).unwrap();
        let result = ed25519_verify(message, &signature, &short_key);

        assert!(matches!(result, Err(Error::InvalidPublicKey(_))));
    }

    #[test]
    fn test_invalid_signature_length() {
        let (public_key, _) = ed25519_generate_keypair();
        let message = b"Test";
        let short_sig = vec![0u8; 32];

        let result = ed25519_verify(message, &short_sig, &public_key);
        assert!(matches!(result, Err(Error::InvalidSignature(_))));
    }

    #[test]
    fn test_empty_message() {
        let (public_key, private_key) = ed25519_generate_keypair();
        let message = b"";

        let signature = ed25519_sign(message, &private_key).unwrap();
        let valid = ed25519_verify(message, &signature, &public_key).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_large_message() {
        let (public_key, private_key) = ed25519_generate_keypair();
        let message = vec![42u8; 1024 * 1024]; // 1 MB

        let signature = ed25519_sign(&message, &private_key).unwrap();
        let valid = ed25519_verify(&message, &signature, &public_key).unwrap();

        assert!(valid);
    }
}
