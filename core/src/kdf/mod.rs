//! Key Derivation Functions (KDF)
//!
//! Provides secure key derivation for passwords and key material:
//! - PBKDF2 (legacy compatibility)
//! - Argon2id (recommended for passwords)
//! - HKDF (for key expansion)

use pbkdf2::pbkdf2_hmac;
use argon2::{Argon2, Algorithm, Version, Params};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};
use crate::random::random_bytes;

/// Default PBKDF2 iterations (OWASP recommendation for HMAC-SHA256)
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000;

/// Minimum PBKDF2 iterations
pub const MIN_PBKDF2_ITERATIONS: u32 = 100_000;

/// Default Argon2 memory cost in KiB (64 MB)
pub const DEFAULT_ARGON2_MEMORY: u32 = 65536;

/// Default Argon2 time cost (iterations)
pub const DEFAULT_ARGON2_TIME: u32 = 3;

/// Default Argon2 parallelism
pub const DEFAULT_ARGON2_PARALLELISM: u32 = 4;

/// Default salt size in bytes
pub const DEFAULT_SALT_SIZE: usize = 16;

/// Derive key using PBKDF2-HMAC-SHA256
///
/// # Arguments
///
/// * `password` - Password to derive key from
/// * `salt` - Optional salt (16 bytes generated if None)
/// * `iterations` - Number of iterations (default: 600,000)
/// * `key_length` - Desired key length in bytes (default: 32)
///
/// # Returns
///
/// Tuple of (derived_key, salt)
///
/// # Errors
///
/// Returns `Error::InvalidIterations` if iterations < 100,000
///
/// # Example
///
/// ```rust
/// use elecrypto_core::kdf::pbkdf2;
///
/// let password = b"my_secure_password";
/// let (key, salt) = pbkdf2(password, None, None, None).unwrap();
///
/// // Later, verify password with same salt
/// let (check_key, _) = pbkdf2(password, Some(&salt), None, None).unwrap();
/// assert_eq!(key.as_slice(), check_key.as_slice());
/// ```
pub fn pbkdf2(
    password: &[u8],
    salt: Option<&[u8]>,
    iterations: Option<u32>,
    key_length: Option<usize>,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let iterations = iterations.unwrap_or(DEFAULT_PBKDF2_ITERATIONS);
    let key_length = key_length.unwrap_or(32);

    // Validate iterations
    if iterations < MIN_PBKDF2_ITERATIONS {
        return Err(Error::InvalidIterations {
            min: MIN_PBKDF2_ITERATIONS,
            actual: iterations,
        });
    }

    // Generate or use provided salt
    let salt_bytes = match salt {
        Some(s) => s.to_vec(),
        None => random_bytes(DEFAULT_SALT_SIZE).to_vec(),
    };

    // Derive key
    let mut key = vec![0u8; key_length];
    pbkdf2_hmac::<Sha256>(password, &salt_bytes, iterations, &mut key);

    Ok((Zeroizing::new(key), salt_bytes))
}

/// Derive key using Argon2id (recommended for passwords)
///
/// # Arguments
///
/// * `password` - Password to derive key from
/// * `salt` - Optional salt (16 bytes generated if None)
/// * `memory_cost` - Memory cost in KiB (default: 64 MB)
/// * `time_cost` - Time cost/iterations (default: 3)
/// * `parallelism` - Parallelism factor (default: 4)
/// * `key_length` - Desired key length in bytes (default: 32)
///
/// # Returns
///
/// Tuple of (derived_key, salt)
///
/// # Errors
///
/// Returns `Error::InvalidInput` if parameters are invalid
///
/// # Example
///
/// ```rust
/// use elecrypto_core::kdf::argon2id;
///
/// let password = b"my_secure_password";
/// let (key, salt) = argon2id(password, None, None, None, None, None).unwrap();
///
/// // Later, verify password with same salt
/// let (check_key, _) = argon2id(password, Some(&salt), None, None, None, None).unwrap();
/// assert_eq!(key.as_slice(), check_key.as_slice());
/// ```
pub fn argon2id(
    password: &[u8],
    salt: Option<&[u8]>,
    memory_cost: Option<u32>,
    time_cost: Option<u32>,
    parallelism: Option<u32>,
    key_length: Option<usize>,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let memory_cost = memory_cost.unwrap_or(DEFAULT_ARGON2_MEMORY);
    let time_cost = time_cost.unwrap_or(DEFAULT_ARGON2_TIME);
    let parallelism = parallelism.unwrap_or(DEFAULT_ARGON2_PARALLELISM);
    let key_length = key_length.unwrap_or(32);

    // Generate or use provided salt
    let salt_bytes = match salt {
        Some(s) => s.to_vec(),
        None => random_bytes(DEFAULT_SALT_SIZE).to_vec(),
    };

    // Create Argon2 parameters
    let params = Params::new(memory_cost, time_cost, parallelism, Some(key_length))
        .map_err(|e| Error::InvalidInput(format!("Invalid Argon2 parameters: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Derive key
    let mut key = vec![0u8; key_length];
    argon2
        .hash_password_into(password, &salt_bytes, &mut key)
        .map_err(|e| Error::InternalError(format!("Argon2 hash failed: {}", e)))?;

    Ok((Zeroizing::new(key), salt_bytes))
}

/// Derive key using HKDF (HMAC-based Key Derivation Function)
///
/// Used for expanding existing key material, not for passwords.
///
/// # Arguments
///
/// * `input_key_material` - Input key material (IKM)
/// * `salt` - Optional salt
/// * `info` - Optional context/application info
/// * `key_length` - Desired output length (default: 32)
///
/// # Returns
///
/// Derived key
///
/// # Example
///
/// ```rust
/// use elecrypto_core::kdf::hkdf_derive;
///
/// let ikm = b"input_key_material";
/// let info = b"application_context";
/// let key = hkdf_derive(ikm, None, Some(info), None).unwrap();
/// assert_eq!(key.len(), 32);
/// ```
pub fn hkdf_derive(
    input_key_material: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    key_length: Option<usize>,
) -> Result<Zeroizing<Vec<u8>>> {
    let key_length = key_length.unwrap_or(32);
    let salt = salt.unwrap_or(b"");
    let info = info.unwrap_or(b"");

    let hk = Hkdf::<Sha256>::new(Some(salt), input_key_material);
    let mut okm = vec![0u8; key_length];

    hk.expand(info, &mut okm)
        .map_err(|e| Error::InvalidInput(format!("HKDF expand failed: {}", e)))?;

    Ok(Zeroizing::new(okm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_basic() {
        let password = b"test_password";
        let (key, salt) = pbkdf2(password, None, None, None).unwrap();

        assert_eq!(key.len(), 32);
        assert_eq!(salt.len(), DEFAULT_SALT_SIZE);

        // Same password and salt should produce same key
        let (key2, _) = pbkdf2(password, Some(&salt), None, None).unwrap();
        assert_eq!(key.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_pbkdf2_different_passwords() {
        let salt = random_bytes(DEFAULT_SALT_SIZE);

        let (key1, _) = pbkdf2(b"password1", Some(&salt), None, None).unwrap();
        let (key2, _) = pbkdf2(b"password2", Some(&salt), None, None).unwrap();

        assert_ne!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_pbkdf2_different_salts() {
        let password = b"test_password";

        let (key1, salt1) = pbkdf2(password, None, None, None).unwrap();
        let (key2, salt2) = pbkdf2(password, None, None, None).unwrap();

        assert_ne!(salt1, salt2);
        assert_ne!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_pbkdf2_custom_length() {
        let password = b"test_password";
        let (key, _) = pbkdf2(password, None, None, Some(64)).unwrap();

        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_pbkdf2_low_iterations() {
        let password = b"test_password";
        let result = pbkdf2(password, None, Some(1000), None);

        assert!(matches!(result, Err(Error::InvalidIterations { .. })));
    }

    #[test]
    fn test_argon2id_basic() {
        let password = b"test_password";
        let (key, salt) = argon2id(password, None, None, None, None, None).unwrap();

        assert_eq!(key.len(), 32);
        assert_eq!(salt.len(), DEFAULT_SALT_SIZE);

        // Same password and salt should produce same key
        let (key2, _) = argon2id(password, Some(&salt), None, None, None, None).unwrap();
        assert_eq!(key.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_argon2id_different_passwords() {
        let salt = random_bytes(DEFAULT_SALT_SIZE);

        let (key1, _) = argon2id(b"password1", Some(&salt), None, None, None, None).unwrap();
        let (key2, _) = argon2id(b"password2", Some(&salt), None, None, None, None).unwrap();

        assert_ne!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_argon2id_custom_params() {
        let password = b"test_password";
        // Lower memory for faster tests
        let (key, _) = argon2id(password, None, Some(4096), Some(2), Some(1), Some(64)).unwrap();

        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_hkdf_basic() {
        let ikm = b"input_key_material";
        let key = hkdf_derive(ikm, None, None, None).unwrap();

        assert_eq!(key.len(), 32);

        // Same IKM should produce same key
        let key2 = hkdf_derive(ikm, None, None, None).unwrap();
        assert_eq!(key.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_hkdf_with_salt_and_info() {
        let ikm = b"input_key_material";
        let salt = b"salt_value";
        let info = b"application_context";

        let key1 = hkdf_derive(ikm, Some(salt), Some(info), None).unwrap();
        let key2 = hkdf_derive(ikm, Some(salt), Some(info), None).unwrap();

        assert_eq!(key1.as_slice(), key2.as_slice());

        // Different info should produce different key
        let key3 = hkdf_derive(ikm, Some(salt), Some(b"different_context"), None).unwrap();
        assert_ne!(key1.as_slice(), key3.as_slice());
    }

    #[test]
    fn test_hkdf_custom_length() {
        let ikm = b"input_key_material";
        let key = hkdf_derive(ikm, None, None, Some(64)).unwrap();

        assert_eq!(key.len(), 64);
    }
}
