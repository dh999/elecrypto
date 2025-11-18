//! Digital signatures
//!
//! Provides digital signature algorithms:
//! - Ed25519 (EdDSA)
//! - ECDSA (planned)
//! - RSA-PSS (planned)

mod ed25519;

pub use ed25519::{
    ed25519_generate_keypair,
    ed25519_sign,
    ed25519_verify,
    ED25519_PUBLIC_KEY_SIZE,
    ED25519_PRIVATE_KEY_SIZE,
    ED25519_SIGNATURE_SIZE,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_roundtrip() {
        let (public_key, private_key) = ed25519_generate_keypair();
        let message = b"Test message";

        let signature = ed25519_sign(message, &private_key).unwrap();
        let valid = ed25519_verify(message, &signature, &public_key).unwrap();

        assert!(valid);
    }
}
