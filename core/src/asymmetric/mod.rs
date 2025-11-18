//! Asymmetric encryption
//!
//! Provides public-key encryption:
//! - RSA-OAEP (RSA with Optimal Asymmetric Encryption Padding)
//! - ECIES (Elliptic Curve Integrated Encryption Scheme)

pub mod rsa_oaep;
pub mod ecies;

pub use rsa_oaep::{
    RsaKeySize, RsaPublicKey, RsaPrivateKey,
    rsa_generate_keypair, rsa_encrypt, rsa_decrypt,
    rsa_public_key_to_der, rsa_private_key_to_der,
    rsa_public_key_from_der, rsa_private_key_from_der,
};

pub use ecies::{
    EciesPublicKey, EciesPrivateKey,
    ecies_generate_keypair, ecies_encrypt, ecies_decrypt,
    ecies_public_key_to_bytes, ecies_private_key_to_bytes,
    ecies_public_key_from_bytes, ecies_private_key_from_bytes,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_roundtrip() {
        let (public_key, private_key) = rsa_generate_keypair(RsaKeySize::Rsa2048).unwrap();
        let plaintext = b"Hello, RSA-OAEP!";

        let ciphertext = rsa_encrypt(plaintext, &public_key).unwrap();
        let decrypted = rsa_decrypt(&ciphertext, &private_key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_ecies_roundtrip() {
        let (public_key, private_key) = ecies_generate_keypair().unwrap();
        let plaintext = b"Hello, ECIES!";

        let ciphertext = ecies_encrypt(plaintext, &public_key).unwrap();
        let decrypted = ecies_decrypt(&ciphertext, &private_key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
