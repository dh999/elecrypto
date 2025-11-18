//! SOLMAE (MQ-Sign) - 다변수 기반 서명 (KPQC)
//!
//! SOLMAE는 다변수 다항식 기반 (Multivariate Quadratic) 디지털 서명입니다.
//!
//! ## 특징
//!
//! - 매우 빠른 서명 생성
//! - 다변수 암호 기반
//! - 작은 서명 크기
//!
//! ## 보안 수준
//!
//! KPQC Security Levels: 128, 192-bit
//!
//! ## 상태
//!
//! ⚠️ **구현 예정**: SOLMAE Rust 크레이트가 안정화되는 대로 구현됩니다.

use zeroize::Zeroizing;
use crate::{Error, Result};

/// Generate SOLMAE keypair
///
/// **Status**: To be implemented
pub fn solmae_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    unimplemented!("SOLMAE implementation pending")
}

/// Sign a message with SOLMAE
///
/// **Status**: To be implemented
pub fn solmae_sign(_message: &[u8], _secret_key: &[u8]) -> Result<Vec<u8>> {
    Err(Error::UnsupportedAlgorithm(
        "SOLMAE not yet implemented".to_string(),
    ))
}

/// Verify SOLMAE signature
///
/// **Status**: To be implemented
pub fn solmae_verify(_message: &[u8], _signature: &[u8], _public_key: &[u8]) -> Result<bool> {
    Err(Error::UnsupportedAlgorithm(
        "SOLMAE not yet implemented".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn test_solmae_not_implemented() {
        let _ = solmae_keypair();
    }
}
