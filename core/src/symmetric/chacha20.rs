//! ChaCha20-Poly1305 authenticated encryption

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use zeroize::Zeroizing;

use crate::{Error, Result};
use crate::random::random_bytes;

/// ChaCha20-Poly1305 key size in bytes
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size in bytes
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// Generate a random ChaCha20-Poly1305 key
///
/// # Returns
///
/// A 32-byte random key suitable for ChaCha20-Poly1305
///
/// # Example
///
/// ```rust
/// use elecrypto_core::symmetric::chacha20_generate_key;
///
/// let key = chacha20_generate_key();
/// assert_eq!(key.len(), 32);
/// ```
pub fn chacha20_generate_key() -> Zeroizing<Vec<u8>> {
    random_bytes(CHACHA20_KEY_SIZE)
}

/// Encrypt data using ChaCha20-Poly1305
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
/// use elecrypto_core::symmetric::{chacha20_generate_key, chacha20_poly1305_encrypt};
///
/// let key = chacha20_generate_key();
/// let plaintext = b"Secret message";
///
/// let (ciphertext, nonce) = chacha20_poly1305_encrypt(plaintext, &key, None, None).unwrap();
/// assert!(ciphertext.len() > plaintext.len()); // Includes auth tag
/// ```
pub fn chacha20_poly1305_encrypt(
    plaintext: &[u8],
    key: &[u8],
    nonce: Option<&[u8]>,
    associated_data: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Validate key length
    if key.len() != CHACHA20_KEY_SIZE {
        return Err(Error::InvalidKeyLength {
            expected: CHACHA20_KEY_SIZE,
            actual: key.len(),
        });
    }

    // Generate or validate nonce
    let nonce_bytes = match nonce {
        Some(n) => {
            if n.len() != CHACHA20_NONCE_SIZE {
                return Err(Error::InvalidNonceLength {
                    expected: CHACHA20_NONCE_SIZE,
                    actual: n.len(),
                });
            }
            n.to_vec()
        }
        None => random_bytes(CHACHA20_NONCE_SIZE).to_vec(),
    };

    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(key)
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

/// Decrypt data using ChaCha20-Poly1305
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
/// use elecrypto_core::symmetric::{
///     chacha20_generate_key,
///     chacha20_poly1305_encrypt,
///     chacha20_poly1305_decrypt
/// };
///
/// let key = chacha20_generate_key();
/// let plaintext = b"Secret message";
///
/// let (ciphertext, nonce) = chacha20_poly1305_encrypt(plaintext, &key, None, None).unwrap();
/// let decrypted = chacha20_poly1305_decrypt(&ciphertext, &key, &nonce, None).unwrap();
///
/// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
/// ```
pub fn chacha20_poly1305_decrypt(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>> {
    // Validate key length
    if key.len() != CHACHA20_KEY_SIZE {
        return Err(Error::InvalidKeyLength {
            expected: CHACHA20_KEY_SIZE,
            actual: key.len(),
        });
    }

    // Validate nonce length
    if nonce.len() != CHACHA20_NONCE_SIZE {
        return Err(Error::InvalidNonceLength {
            expected: CHACHA20_NONCE_SIZE,
            actual: nonce.len(),
        });
    }

    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(key)
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
        .map_err(|e| {
            // Authentication failure is the most common error
            if e.to_string().contains("verification") || e.to_string().contains("tag") {
                Error::AuthenticationFailed
            } else {
                Error::DecryptionFailed(format!("Decryption failed: {}", e))
            }
        })?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = chacha20_generate_key();
        assert_eq!(key.len(), CHACHA20_KEY_SIZE);

        // Keys should be different
        let key2 = chacha20_generate_key();
        assert_ne!(key.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = chacha20_generate_key();
        let plaintext = b"Hello, World!";

        let (ciphertext, nonce) = chacha20_poly1305_encrypt(plaintext, &key, None, None).unwrap();
        let decrypted = chacha20_poly1305_decrypt(&ciphertext, &key, &nonce, None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_with_custom_nonce() {
        let key = chacha20_generate_key();
        let plaintext = b"Test message";
        let custom_nonce = random_bytes(CHACHA20_NONCE_SIZE);

        let (ciphertext, returned_nonce) =
            chacha20_poly1305_encrypt(plaintext, &key, Some(&custom_nonce), None).unwrap();

        assert_eq!(custom_nonce.as_slice(), returned_nonce.as_slice());

        let decrypted = chacha20_poly1305_decrypt(&ciphertext, &key, &returned_nonce, None).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_with_associated_data() {
        let key = chacha20_generate_key();
        let plaintext = b"Secret data";
        let aad = b"user_id:12345";

        let (ciphertext, nonce) = chacha20_poly1305_encrypt(plaintext, &key, None, Some(aad)).unwrap();
        let decrypted = chacha20_poly1305_decrypt(&ciphertext, &key, &nonce, Some(aad)).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_authentication_failure_with_wrong_aad() {
        let key = chacha20_generate_key();
        let plaintext = b"Secret data";
        let aad = b"user_id:12345";

        let (ciphertext, nonce) = chacha20_poly1305_encrypt(plaintext, &key, None, Some(aad)).unwrap();

        // Try to decrypt with different AAD
        let wrong_aad = b"user_id:99999";
        let result = chacha20_poly1305_decrypt(&ciphertext, &key, &nonce, Some(wrong_aad));

        assert!(matches!(result, Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn test_authentication_failure_with_modified_ciphertext() {
        let key = chacha20_generate_key();
        let plaintext = b"Secret data";

        let (mut ciphertext, nonce) = chacha20_poly1305_encrypt(plaintext, &key, None, None).unwrap();

        // Modify ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = chacha20_poly1305_decrypt(&ciphertext, &key, &nonce, None);
        assert!(matches!(result, Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = vec![0u8; 16];
        let plaintext = b"Test";

        let result = chacha20_poly1305_encrypt(plaintext, &short_key, None, None);
        assert!(matches!(result, Err(Error::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = chacha20_generate_key();
        let plaintext = b"Test";
        let short_nonce = vec![0u8; 8];

        let result = chacha20_poly1305_encrypt(plaintext, &key, Some(&short_nonce), None);
        assert!(matches!(result, Err(Error::InvalidNonceLength { .. })));
    }

    #[test]
    fn test_empty_plaintext() {
        let key = chacha20_generate_key();
        let plaintext = b"";

        let (ciphertext, nonce) = chacha20_poly1305_encrypt(plaintext, &key, None, None).unwrap();
        let decrypted = chacha20_poly1305_decrypt(&ciphertext, &key, &nonce, None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_large_plaintext() {
        let key = chacha20_generate_key();
        let plaintext = vec![42u8; 1024 * 1024]; // 1 MB

        let (ciphertext, nonce) = chacha20_poly1305_encrypt(&plaintext, &key, None, None).unwrap();
        let decrypted = chacha20_poly1305_decrypt(&ciphertext, &key, &nonce, None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
