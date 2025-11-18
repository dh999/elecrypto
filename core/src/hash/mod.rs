//! Cryptographic hash functions
//!
//! Provides implementations of modern hash functions:
//! - SHA-256, SHA-512
//! - SHA3-256, SHA3-512
//! - BLAKE3

use sha2::{Sha256, Sha512, Digest};
use sha3::{Sha3_256, Sha3_512};

/// Compute SHA-256 hash
///
/// # Arguments
///
/// * `data` - Data to hash
///
/// # Returns
///
/// 32-byte hash value
///
/// # Example
///
/// ```rust
/// use elecrypto_core::hash::sha256;
///
/// let data = b"Hello, World!";
/// let hash = sha256(data);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-512 hash
///
/// # Arguments
///
/// * `data` - Data to hash
///
/// # Returns
///
/// 64-byte hash value
///
/// # Example
///
/// ```rust
/// use elecrypto_core::hash::sha512;
///
/// let data = b"Hello, World!";
/// let hash = sha512(data);
/// assert_eq!(hash.len(), 64);
/// ```
pub fn sha512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA3-256 hash
///
/// # Arguments
///
/// * `data` - Data to hash
///
/// # Returns
///
/// 32-byte hash value
///
/// # Example
///
/// ```rust
/// use elecrypto_core::hash::sha3_256;
///
/// let data = b"Hello, World!";
/// let hash = sha3_256(data);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha3_256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA3-512 hash
///
/// # Arguments
///
/// * `data` - Data to hash
///
/// # Returns
///
/// 64-byte hash value
///
/// # Example
///
/// ```rust
/// use elecrypto_core::hash::sha3_512;
///
/// let data = b"Hello, World!";
/// let hash = sha3_512(data);
/// assert_eq!(hash.len(), 64);
/// ```
pub fn sha3_512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute BLAKE3 hash
///
/// # Arguments
///
/// * `data` - Data to hash
/// * `output_length` - Desired hash length (default: 32 bytes)
///
/// # Returns
///
/// Hash value of specified length
///
/// # Example
///
/// ```rust
/// use elecrypto_core::hash::blake3_hash;
///
/// let data = b"Hello, World!";
/// let hash = blake3_hash(data, 32);
/// assert_eq!(hash.len(), 32);
///
/// // BLAKE3 supports arbitrary output lengths
/// let hash64 = blake3_hash(data, 64);
/// assert_eq!(hash64.len(), 64);
/// ```
pub fn blake3_hash(data: &[u8], output_length: usize) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    let mut output = vec![0u8; output_length];
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"Hello, World!";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);

        // Same input should produce same hash
        let hash2 = sha256(data);
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let hash3 = sha256(b"Different data");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_sha512() {
        let data = b"Hello, World!";
        let hash = sha512(data);
        assert_eq!(hash.len(), 64);

        // Same input should produce same hash
        let hash2 = sha512(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sha3_256() {
        let data = b"Hello, World!";
        let hash = sha3_256(data);
        assert_eq!(hash.len(), 32);

        // SHA3 should produce different hash than SHA2
        let sha2_hash = sha256(data);
        assert_ne!(hash, sha2_hash);
    }

    #[test]
    fn test_sha3_512() {
        let data = b"Hello, World!";
        let hash = sha3_512(data);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_blake3() {
        let data = b"Hello, World!";
        let hash = blake3_hash(data, 32);
        assert_eq!(hash.len(), 32);

        // BLAKE3 supports arbitrary output lengths
        let hash64 = blake3_hash(data, 64);
        assert_eq!(hash64.len(), 64);

        let hash128 = blake3_hash(data, 128);
        assert_eq!(hash128.len(), 128);
    }

    #[test]
    fn test_empty_input() {
        let empty = b"";

        assert_eq!(sha256(empty).len(), 32);
        assert_eq!(sha512(empty).len(), 64);
        assert_eq!(sha3_256(empty).len(), 32);
        assert_eq!(sha3_512(empty).len(), 64);
        assert_eq!(blake3_hash(empty, 32).len(), 32);
    }

    #[test]
    fn test_large_input() {
        let large = vec![42u8; 1024 * 1024]; // 1 MB

        let hash = sha256(&large);
        assert_eq!(hash.len(), 32);
    }
}
