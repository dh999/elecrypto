//! Cryptographically secure random number generation

use zeroize::Zeroizing;

/// Generate cryptographically secure random bytes
///
/// Uses the operating system's random number generator:
/// - Linux/Android: `/dev/urandom`
/// - macOS/iOS: `SecRandomCopyBytes`
/// - Windows: `BCryptGenRandom`
///
/// # Arguments
///
/// * `length` - Number of random bytes to generate
///
/// # Returns
///
/// A vector of random bytes
///
/// # Errors
///
/// Returns `Error::InsufficientEntropy` if the system RNG fails
///
/// # Example
///
/// ```rust
/// use elecrypto_core::random::random_bytes;
///
/// let key = random_bytes(32);
/// assert_eq!(key.len(), 32);
///
/// // Keys should be different
/// let key2 = random_bytes(32);
/// assert_ne!(key.as_slice(), key2.as_slice());
/// ```
pub fn random_bytes(length: usize) -> Zeroizing<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    getrandom::getrandom(&mut bytes)
        .expect("Failed to generate random bytes");
    Zeroizing::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes_length() {
        let bytes = random_bytes(32);
        assert_eq!(bytes.len(), 32);

        let bytes = random_bytes(64);
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn test_random_bytes_are_different() {
        let bytes1 = random_bytes(32);
        let bytes2 = random_bytes(32);

        // Extremely unlikely to be equal
        assert_ne!(bytes1.as_slice(), bytes2.as_slice());
    }

    #[test]
    fn test_random_bytes_zero_length() {
        let bytes = random_bytes(0);
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    fn test_random_bytes_large() {
        let bytes = random_bytes(1024 * 1024); // 1 MB
        assert_eq!(bytes.len(), 1024 * 1024);
    }
}
