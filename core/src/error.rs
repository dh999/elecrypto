//! Error types for Elecrypto

use thiserror::Error;

/// Result type alias for Elecrypto operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid input parameters
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes
        expected: usize,
        /// Actual key length in bytes
        actual: usize,
    },

    /// Invalid nonce length
    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected nonce length in bytes
        expected: usize,
        /// Actual nonce length in bytes
        actual: usize,
    },

    /// Authentication failed (message was tampered with)
    #[error("Authentication failed: message authentication tag is invalid")]
    AuthenticationFailed,

    /// Encryption operation failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Signing operation failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid private key
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Invalid signature format
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Insufficient entropy for random number generation
    #[error("Insufficient entropy")]
    InsufficientEntropy,

    /// Invalid iteration count for KDF
    #[error("Invalid iterations: must be at least {min}, got {actual}")]
    InvalidIterations {
        /// Minimum iterations required
        min: u32,
        /// Actual iterations provided
        actual: u32,
    },

    /// Plaintext too large for encryption
    #[error("Plaintext too large: maximum {max} bytes, got {actual} bytes")]
    PlaintextTooLarge {
        /// Maximum allowed size
        max: usize,
        /// Actual size
        actual: usize,
    },

    /// Internal library error
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl Error {
    /// Returns error code for FFI compatibility
    pub fn code(&self) -> i32 {
        match self {
            Error::InvalidInput(_) => -1,
            Error::InvalidKeyLength { .. } => -2,
            Error::InvalidNonceLength { .. } => -3,
            Error::AuthenticationFailed => -4,
            Error::EncryptionFailed(_) => -5,
            Error::DecryptionFailed(_) => -6,
            Error::KeyGenerationFailed(_) => -7,
            Error::SigningFailed(_) => -8,
            Error::VerificationFailed(_) => -9,
            Error::InvalidPublicKey(_) => -10,
            Error::InvalidPrivateKey(_) => -11,
            Error::InvalidSignature(_) => -12,
            Error::UnsupportedAlgorithm(_) => -13,
            Error::InsufficientEntropy => -14,
            Error::InvalidIterations { .. } => -15,
            Error::PlaintextTooLarge { .. } => -16,
            Error::InternalError(_) => -99,
        }
    }

    /// Returns a short error message suitable for FFI
    pub fn message(&self) -> String {
        self.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes_are_unique() {
        let errors = vec![
            Error::InvalidInput("test".into()),
            Error::InvalidKeyLength { expected: 32, actual: 16 },
            Error::InvalidNonceLength { expected: 12, actual: 16 },
            Error::AuthenticationFailed,
            Error::EncryptionFailed("test".into()),
            Error::DecryptionFailed("test".into()),
            Error::KeyGenerationFailed("test".into()),
            Error::SigningFailed("test".into()),
            Error::VerificationFailed("test".into()),
            Error::InvalidPublicKey("test".into()),
            Error::InvalidPrivateKey("test".into()),
            Error::InvalidSignature("test".into()),
            Error::UnsupportedAlgorithm("test".into()),
            Error::InsufficientEntropy,
            Error::InvalidIterations { min: 1000, actual: 100 },
            Error::PlaintextTooLarge { max: 1024, actual: 2048 },
            Error::InternalError("test".into()),
        ];

        let mut codes: Vec<i32> = errors.iter().map(|e| e.code()).collect();
        codes.sort();
        codes.dedup();

        // All codes should be negative
        assert!(codes.iter().all(|&c| c < 0));

        // All codes should be unique
        assert_eq!(codes.len(), errors.len());
    }

    #[test]
    fn test_error_messages() {
        let err = Error::InvalidKeyLength { expected: 32, actual: 16 };
        assert!(err.message().contains("32"));
        assert!(err.message().contains("16"));
    }
}
