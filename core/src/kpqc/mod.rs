//! Korean Post-Quantum Cryptography (KPQC)
//!
//! KPQC 알고리즘은 한국인터넷진흥원(KISA)과 국가보안기술연구소(NSR)가
//! 주도하는 한국형 양자내성 암호 표준화 프로젝트입니다.
//!
//! ## 선정 알고리즘 (2022-2023)
//!
//! ### KEM (Key Encapsulation Mechanism)
//! - **NTRU+**: NTRU 기반, 빠른 성능
//! - **SMAUG**: 한국 독자 개발, 메모리 효율적
//! - **TiGER**: 격자 기반, 고속 연산
//! - **PALOMA**: 동형암호 친화적
//!
//! ### 디지털 서명
//! - **AIMer**: 대수적 기법, 작은 서명
//! - **HAETAE**: 격자 기반, Dilithium 개선형
//! - **SOLMAE (MQ-Sign)**: 다변수 기반, 빠른 서명
//! - **GCKSign**: 그룹 서명 지원
//!
//! ## NIST-KPQC 공통 알고리즘
//!
//! 다음 알고리즘들은 NIST와 KPQC 모두에 선정되었습니다:
//! - Kyber (ML-KEM) → `crate::pqc::kyber` 모듈 참조
//! - Dilithium (ML-DSA) → `crate::pqc::dilithium` 모듈 참조
//! - Falcon (FN-DSA) → `crate::pqc::falcon` 모듈 참조
//! - SPHINCS+ (SLH-DSA) → `crate::pqc::sphincsplus` 모듈 참조
//!
//! ## 상태
//!
//! ⚠️ **주의**: KPQC 알고리즘들은 현재 구현 진행 중입니다.
//! 일부 알고리즘은 Rust 크레이트가 아직 준비되지 않았습니다.

pub mod kem;
pub mod sign;

// Re-export KEM algorithms
pub use kem::{
    // NTRU+
    ntruplus_keypair,
    ntruplus_encapsulate,
    ntruplus_decapsulate,

    // SMAUG
    smaug_keypair,
    smaug_encapsulate,
    smaug_decapsulate,

    // TiGER
    tiger_keypair,
    tiger_encapsulate,
    tiger_decapsulate,

    // PALOMA
    paloma_keypair,
    paloma_encapsulate,
    paloma_decapsulate,
};

// Re-export signature algorithms
pub use sign::{
    // AIMer
    aimer_keypair,
    aimer_sign,
    aimer_verify,

    // HAETAE
    haetae_keypair,
    haetae_sign,
    haetae_verify,

    // SOLMAE (MQ-Sign)
    solmae_keypair,
    solmae_sign,
    solmae_verify,

    // GCKSign
    gcksign_keypair,
    gcksign_sign,
    gcksign_verify,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kpqc_placeholder() {
        // KPQC 알고리즘 테스트는 구현 완료 후 추가됩니다
        assert!(true);
    }
}
