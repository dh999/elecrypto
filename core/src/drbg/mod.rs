//! Deterministic Random Bit Generators (DRBG)
//!
//! NIST SP 800-90A compliant DRBGs for cryptographically secure
//! pseudorandom number generation.

pub mod hmac_drbg;
pub mod hash_drbg;
pub mod ctr_drbg;

pub use hmac_drbg::HmacDrbg;
pub use hash_drbg::HashDrbg;
pub use ctr_drbg::CtrDrbg;

use crate::Result;

/// Common trait for all DRBG implementations
pub trait Drbg {
    /// Instantiate the DRBG with entropy and optional personalization string
    fn instantiate(entropy: &[u8], nonce: &[u8], personalization: Option<&[u8]>) -> Result<Self>
    where
        Self: Sized;

    /// Reseed the DRBG with additional entropy
    fn reseed(&mut self, entropy: &[u8], additional: Option<&[u8]>) -> Result<()>;

    /// Generate pseudorandom bytes
    fn generate(&mut self, output: &mut [u8], additional: Option<&[u8]>) -> Result<()>;

    /// Get security strength in bits
    fn security_strength(&self) -> usize;
}

/// Security strength levels (bits)
pub const SECURITY_STRENGTH_128: usize = 128;
pub const SECURITY_STRENGTH_192: usize = 192;
pub const SECURITY_STRENGTH_256: usize = 256;

/// Maximum number of bytes per request
pub const MAX_BYTES_PER_REQUEST: usize = 65536; // 2^16

/// Maximum reseed interval (number of generate calls)
pub const RESEED_INTERVAL: u64 = 10000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_strengths() {
        assert_eq!(SECURITY_STRENGTH_128, 128);
        assert_eq!(SECURITY_STRENGTH_256, 256);
    }
}
