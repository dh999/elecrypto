//! AES-256-GCM authenticated encryption

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

use crate::{Error, Result};
use crate::random::random_bytes;

/// AES-256 key size in bytes
pub const AES_KEY_SIZE: usize = 32;

/// AES-GCM nonce size in bytes
pub const AES_NONCE_SIZE: usize = 12;

/// Generate a random AES-256 key
///
/// # Returns
///
/// A 32-byte random key suitable for AES-256-GCM
///
/// # Example
///
/// ```rust
/// use elecrypto_core::symmetric::aes_generate_key;
///
/// let key = aes_generate_key();
/// assert_eq!(key.len(), 32);
/// ```
pub fn aes_generate_key() -> Zeroizing<Vec<u8>> {
    random_bytes(AES_KEY_SIZE)
}

/// Encrypt data using AES-256-GCM
///
/// # Arguments
///
/// * `plaintext` - The data to encrypt
/// * `key` - 32-byte encryption key
/// * `nonce` - Optional 12-byte nonce (generated if None)
/// * `associated_data` - Optional additional authenticated data
///
/// # Returns
///
/// A tuple of (ciphertext, nonce). The ciphertext includes the authentication tag.
///
/// # Errors
///
/// Returns `Error::InvalidKeyLength` if key is not 32 bytes.
/// Returns `Error::InvalidNonceLength` if provided nonce is not 12 bytes.
/// Returns `Error::EncryptionFailed` if encryption fails.
///
/// # Example
///
/// ```rust
/// use elecrypto_core::symmetric::{aes_generate_key, aes_gcm_encrypt};
///
/// let key = aes_generate_key();
/// let plaintext = b"Secret message";
///
/// let (ciphertext, nonce) = aes_gcm_encrypt(plaintext, &key, None, None).unwrap();
/// assert!(ciphertext.len() > plaintext.len()); // Includes auth tag
/// ```
pub fn aes_gcm_encrypt(
    plaintext: &[u8],
    key: &[u8],
    nonce: Option<&[u8]>,
    associated_data: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Validate key length
    if key.len() != AES_KEY_SIZE {
        return Err(Error::InvalidKeyLength {
            expected: AES_KEY_SIZE,
            actual: key.len(),
        });
    }

    // Generate or validate nonce
    let nonce_bytes = match nonce {
        Some(n) => {
            if n.len() != AES_NONCE_SIZE {
                return Err(Error::InvalidNonceLength {
                    expected: AES_NONCE_SIZE,
                    actual: n.len(),
                });
            }
            n.to_vec()
        }
        None => random_bytes(AES_NONCE_SIZE).to_vec(),
    };

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::EncryptionFailed(format!("Failed to create cipher: {}", e)))?;

    let nonce_array = Nonce::from_slice(&nonce_bytes);

    // Prepare payload
    let payload = match associated_data {
        Some(aad) => Payload {
            msg: plaintext,
            aad,
        },
        None => Payload {
            msg: plaintext,
            aad: b"",
        },
    };

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce_array, payload)
        .map_err(|e| Error::EncryptionFailed(format!("Encryption failed: {}", e)))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt data using AES-256-GCM
///
/// # Arguments
///
/// * `ciphertext` - The encrypted data (includes authentication tag)
/// * `key` - 32-byte decryption key
/// * `nonce` - 12-byte nonce used for encryption
/// * `associated_data` - Optional additional authenticated data (must match encryption)
///
/// # Returns
///
/// The decrypted plaintext.
///
/// # Errors
///
/// Returns `Error::InvalidKeyLength` if key is not 32 bytes.
/// Returns `Error::InvalidNonceLength` if nonce is not 12 bytes.
/// Returns `Error::AuthenticationFailed` if authentication tag is invalid.
/// Returns `Error::DecryptionFailed` if decryption fails.
///
/// # Example
///
/// ```rust
/// use elecrypto_core::symmetric::{aes_generate_key, aes_gcm_encrypt, aes_gcm_decrypt};
///
/// let key = aes_generate_key();
/// let plaintext = b"Secret message";
///
/// let (ciphertext, nonce) = aes_gcm_encrypt(plaintext, &key, None, None).unwrap();
/// let decrypted = aes_gcm_decrypt(&ciphertext, &key, &nonce, None).unwrap();
///
/// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
/// ```
pub fn aes_gcm_decrypt(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>> {
    // Validate key length
    if key.len() != AES_KEY_SIZE {
        return Err(Error::InvalidKeyLength {
            expected: AES_KEY_SIZE,
            actual: key.len(),
        });
    }

    // Validate nonce length
    if nonce.len() != AES_NONCE_SIZE {
        return Err(Error::InvalidNonceLength {
            expected: AES_NONCE_SIZE,
            actual: nonce.len(),
        });
    }

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::DecryptionFailed(format!("Failed to create cipher: {}", e)))?;

    let nonce_array = Nonce::from_slice(nonce);

    // Prepare payload
    let payload = match associated_data {
        Some(aad) => Payload {
            msg: ciphertext,
            aad,
        },
        None => Payload {
            msg: ciphertext,
            aad: b"",
        },
    };

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce_array, payload)
        .map_err(|_e| {
            // For AES-GCM, any decryption error is an authentication failure
            // since it's an authenticated encryption scheme
            Error::AuthenticationFailed
        })?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = aes_generate_key();
        assert_eq!(key.len(), AES_KEY_SIZE);

        // Keys should be different
        let key2 = aes_generate_key();
        assert_ne!(key.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = aes_generate_key();
        let plaintext = b"Hello, World!";

        let (ciphertext, nonce) = aes_gcm_encrypt(plaintext, &key, None, None).unwrap();
        let decrypted = aes_gcm_decrypt(&ciphertext, &key, &nonce, None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_with_custom_nonce() {
        let key = aes_generate_key();
        let plaintext = b"Test message";
        let custom_nonce = random_bytes(AES_NONCE_SIZE);

        let (ciphertext, returned_nonce) =
            aes_gcm_encrypt(plaintext, &key, Some(&custom_nonce), None).unwrap();

        assert_eq!(custom_nonce.as_slice(), returned_nonce.as_slice());

        let decrypted = aes_gcm_decrypt(&ciphertext, &key, &returned_nonce, None).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_with_associated_data() {
        let key = aes_generate_key();
        let plaintext = b"Secret data";
        let aad = b"user_id:12345";

        let (ciphertext, nonce) = aes_gcm_encrypt(plaintext, &key, None, Some(aad)).unwrap();
        let decrypted = aes_gcm_decrypt(&ciphertext, &key, &nonce, Some(aad)).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_authentication_failure_with_wrong_aad() {
        let key = aes_generate_key();
        let plaintext = b"Secret data";
        let aad = b"user_id:12345";

        let (ciphertext, nonce) = aes_gcm_encrypt(plaintext, &key, None, Some(aad)).unwrap();

        // Try to decrypt with different AAD
        let wrong_aad = b"user_id:99999";
        let result = aes_gcm_decrypt(&ciphertext, &key, &nonce, Some(wrong_aad));

        assert!(matches!(result, Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn test_authentication_failure_with_modified_ciphertext() {
        let key = aes_generate_key();
        let plaintext = b"Secret data";

        let (mut ciphertext, nonce) = aes_gcm_encrypt(plaintext, &key, None, None).unwrap();

        // Modify ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = aes_gcm_decrypt(&ciphertext, &key, &nonce, None);
        assert!(matches!(result, Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = vec![0u8; 16]; // AES-128 key
        let plaintext = b"Test";

        let result = aes_gcm_encrypt(plaintext, &short_key, None, None);
        assert!(matches!(result, Err(Error::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = aes_generate_key();
        let plaintext = b"Test";
        let short_nonce = vec![0u8; 8];

        let result = aes_gcm_encrypt(plaintext, &key, Some(&short_nonce), None);
        assert!(matches!(result, Err(Error::InvalidNonceLength { .. })));
    }

    #[test]
    fn test_empty_plaintext() {
        let key = aes_generate_key();
        let plaintext = b"";

        let (ciphertext, nonce) = aes_gcm_encrypt(plaintext, &key, None, None).unwrap();
        let decrypted = aes_gcm_decrypt(&ciphertext, &key, &nonce, None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_large_plaintext() {
        let key = aes_generate_key();
        let plaintext = vec![42u8; 1024 * 1024]; // 1 MB

        let (ciphertext, nonce) = aes_gcm_encrypt(&plaintext, &key, None, None).unwrap();
        let decrypted = aes_gcm_decrypt(&ciphertext, &key, &nonce, None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
