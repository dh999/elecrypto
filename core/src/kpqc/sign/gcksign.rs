//! GCKSign - 그룹 서명 지원 (KPQC)
//!
//! GCKSign은 그룹 서명 기능을 지원하는 양자내성 서명 알고리즘입니다.
//!
//! ## 특징
//!
//! - 그룹 서명 지원
//! - 익명성 보장
//! - 격자 기반
//!
//! ## 보안 수준
//!
//! KPQC Security Level: 128-bit
//!
//! ## 상태
//!
//! ⚠️ **구현 예정**: GCKSign Rust 크레이트가 안정화되는 대로 구현됩니다.

use zeroize::Zeroizing;
use crate::{Error, Result};

/// Generate GCKSign keypair
///
/// **Status**: To be implemented
pub fn gcksign_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    unimplemented!("GCKSign implementation pending")
}

/// Sign a message with GCKSign
///
/// **Status**: To be implemented
pub fn gcksign_sign(_message: &[u8], _secret_key: &[u8]) -> Result<Vec<u8>> {
    Err(Error::UnsupportedAlgorithm(
        "GCKSign not yet implemented".to_string(),
    ))
}

/// Verify GCKSign signature
///
/// **Status**: To be implemented
pub fn gcksign_verify(_message: &[u8], _signature: &[u8], _public_key: &[u8]) -> Result<bool> {
    Err(Error::UnsupportedAlgorithm(
        "GCKSign not yet implemented".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn test_gcksign_not_implemented() {
        let _ = gcksign_keypair();
    }
}
