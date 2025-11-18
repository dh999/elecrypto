//! Post-Quantum Cryptography (PQC) - NIST Standards
//!
//! This module provides quantum-resistant cryptographic algorithms
//! standardized by NIST in 2022-2024.
//!
//! ## Key Encapsulation Mechanisms (KEM)
//! - **ML-KEM (Kyber)**: Module-Lattice-Based KEM
//!
//! ## Digital Signatures
//! - **ML-DSA (Dilithium)**: Module-Lattice-Based Signature
//! - **FN-DSA (Falcon)**: Fast Fourier Transform over NTRU-Lattice Signature
//! - **SLH-DSA (SPHINCS+)**: Stateless Hash-Based Signature
//!
//! ## Security Levels
//!
//! NIST defines security levels equivalent to AES key sizes:
//! - **Level 1**: Equivalent to AES-128 (~2^128 operations)
//! - **Level 3**: Equivalent to AES-192 (~2^192 operations)
//! - **Level 5**: Equivalent to AES-256 (~2^256 operations)
//!
//! ## Why Post-Quantum Cryptography?
//!
//! Traditional public-key algorithms (RSA, ECC) are vulnerable to
//! quantum computers using Shor's algorithm. PQC algorithms are
//! designed to resist both classical and quantum attacks.

mod kyber;
mod dilithium;
mod falcon;
mod sphincsplus;

// Re-export KEM (Key Encapsulation)
pub use kyber::{
    kyber512_keypair, kyber512_encapsulate, kyber512_decapsulate,
    kyber768_keypair, kyber768_encapsulate, kyber768_decapsulate,
    kyber1024_keypair, kyber1024_encapsulate, kyber1024_decapsulate,
};

// Re-export signatures
pub use dilithium::{
    dilithium2_keypair, dilithium2_sign, dilithium2_verify,
    dilithium3_keypair, dilithium3_sign, dilithium3_verify,
    dilithium5_keypair, dilithium5_sign, dilithium5_verify,
};

pub use falcon::{
    falcon512_keypair, falcon512_sign, falcon512_verify,
    falcon1024_keypair, falcon1024_sign, falcon1024_verify,
};

pub use sphincsplus::{
    sphincsplus_shake_128f_keypair,
    sphincsplus_shake_128f_sign,
    sphincsplus_shake_128f_verify,
    sphincsplus_shake_256f_keypair,
    sphincsplus_shake_256f_sign,
    sphincsplus_shake_256f_verify,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber768_kem() {
        let (public_key, secret_key) = kyber768_keypair();
        let (ciphertext, shared_secret1) = kyber768_encapsulate(&public_key).unwrap();
        let shared_secret2 = kyber768_decapsulate(&ciphertext, &secret_key).unwrap();
        assert_eq!(shared_secret1, shared_secret2);
    }

    #[test]
    fn test_dilithium3_signature() {
        let (public_key, secret_key) = dilithium3_keypair();
        let message = b"Test message for PQC";
        let signature = dilithium3_sign(message, &secret_key).unwrap();
        let valid = dilithium3_verify(message, &signature, &public_key).unwrap();
        assert!(valid);
    }
}
