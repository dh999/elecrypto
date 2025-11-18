//! HMAC-DRBG implementation (NIST SP 800-90A)
//!
//! HMAC-based Deterministic Random Bit Generator using SHA-256

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};
use super::{Drbg, RESEED_INTERVAL, MAX_BYTES_PER_REQUEST, SECURITY_STRENGTH_256};

type HmacSha256 = Hmac<Sha256>;

const OUTLEN: usize = 32; // SHA-256 output length

/// HMAC-DRBG with SHA-256
pub struct HmacDrbg {
    /// Internal state V
    v: Zeroizing<Vec<u8>>,
    /// Key K
    k: Zeroizing<Vec<u8>>,
    /// Reseed counter
    reseed_counter: u64,
    /// Security strength in bits
    security_strength: usize,
}

impl HmacDrbg {
    /// Update function (10.1.2.2)
    fn update(&mut self, provided_data: Option<&[u8]>) -> Result<()> {
        // K = HMAC(K, V || 0x00 || provided_data)
        let mut mac = HmacSha256::new_from_slice(&self.k)
            .map_err(|_| Error::InvalidInput("Invalid HMAC key".to_string()))?;

        mac.update(&self.v);
        mac.update(&[0x00]);
        if let Some(data) = provided_data {
            mac.update(data);
        }

        let result = mac.finalize();
        self.k.copy_from_slice(&result.into_bytes());

        // V = HMAC(K, V)
        let mut mac = HmacSha256::new_from_slice(&self.k)
            .map_err(|_| Error::InvalidInput("Invalid HMAC key".to_string()))?;
        mac.update(&self.v);
        let result = mac.finalize();
        self.v.copy_from_slice(&result.into_bytes());

        // If provided_data, do another iteration with 0x01
        if provided_data.is_some() {
            // K = HMAC(K, V || 0x01 || provided_data)
            let mut mac = HmacSha256::new_from_slice(&self.k)
                .map_err(|_| Error::InvalidInput("Invalid HMAC key".to_string()))?;

            mac.update(&self.v);
            mac.update(&[0x01]);
            mac.update(provided_data.unwrap());

            let result = mac.finalize();
            self.k.copy_from_slice(&result.into_bytes());

            // V = HMAC(K, V)
            let mut mac = HmacSha256::new_from_slice(&self.k)
                .map_err(|_| Error::InvalidInput("Invalid HMAC key".to_string()))?;
            mac.update(&self.v);
            let result = mac.finalize();
            self.v.copy_from_slice(&result.into_bytes());
        }

        Ok(())
    }
}

impl Drbg for HmacDrbg {
    fn instantiate(entropy: &[u8], nonce: &[u8], personalization: Option<&[u8]>) -> Result<Self> {
        // Minimum entropy requirement (security_strength bits)
        if entropy.len() < 32 {
            return Err(Error::InvalidInput("Insufficient entropy".to_string()));
        }

        if nonce.len() < 16 {
            return Err(Error::InvalidInput("Nonce too short (min 16 bytes)".to_string()));
        }

        // Initialize V and K
        let v = Zeroizing::new(vec![0x01; OUTLEN]);
        let k = Zeroizing::new(vec![0x00; OUTLEN]);

        let mut drbg = HmacDrbg {
            v,
            k,
            reseed_counter: 1,
            security_strength: SECURITY_STRENGTH_256,
        };

        // Combine seed material
        let mut seed_material = Vec::with_capacity(
            entropy.len() + nonce.len() + personalization.map_or(0, |p| p.len())
        );
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(nonce);
        if let Some(p) = personalization {
            seed_material.extend_from_slice(p);
        }

        // Update with seed material
        drbg.update(Some(&seed_material))?;

        Ok(drbg)
    }

    fn reseed(&mut self, entropy: &[u8], additional: Option<&[u8]>) -> Result<()> {
        if entropy.len() < 32 {
            return Err(Error::InvalidInput("Insufficient entropy for reseed".to_string()));
        }

        // Combine entropy and additional input
        let mut seed_material = entropy.to_vec();
        if let Some(add) = additional {
            seed_material.extend_from_slice(add);
        }

        self.update(Some(&seed_material))?;
        self.reseed_counter = 1;

        Ok(())
    }

    fn generate(&mut self, output: &mut [u8], additional: Option<&[u8]>) -> Result<()> {
        if output.len() > MAX_BYTES_PER_REQUEST {
            return Err(Error::InvalidInput(format!(
                "Request too large (max {} bytes)",
                MAX_BYTES_PER_REQUEST
            )));
        }

        // Check reseed counter
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(Error::InvalidInput("Reseed required".to_string()));
        }

        // Update with additional input if provided
        if let Some(add) = additional {
            self.update(Some(add))?;
        }

        // Generate output
        let mut generated = 0;
        while generated < output.len() {
            // V = HMAC(K, V)
            let mut mac = HmacSha256::new_from_slice(&self.k)
                .map_err(|_| Error::InvalidInput("Invalid HMAC key".to_string()))?;
            mac.update(&self.v);
            let result = mac.finalize();
            self.v.copy_from_slice(&result.into_bytes());

            // Copy to output
            let remaining = output.len() - generated;
            let to_copy = remaining.min(OUTLEN);
            output[generated..generated + to_copy].copy_from_slice(&self.v[..to_copy]);
            generated += to_copy;
        }

        // Update with additional input
        self.update(additional)?;

        self.reseed_counter += 1;

        Ok(())
    }

    fn security_strength(&self) -> usize {
        self.security_strength
    }
}

impl Drop for HmacDrbg {
    fn drop(&mut self) {
        // Zeroizing handles clearing V and K
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_drbg_instantiate() {
        let entropy = vec![0x42; 32];
        let nonce = vec![0x33; 16];

        let drbg = HmacDrbg::instantiate(&entropy, &nonce, None);
        assert!(drbg.is_ok());
    }

    #[test]
    fn test_hmac_drbg_generate() {
        let entropy = vec![0x42; 32];
        let nonce = vec![0x33; 16];

        let mut drbg = HmacDrbg::instantiate(&entropy, &nonce, None).unwrap();
        let mut output = vec![0u8; 64];

        let result = drbg.generate(&mut output, None);
        assert!(result.is_ok());

        // Output should not be all zeros
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hmac_drbg_reseed() {
        let entropy = vec![0x42; 32];
        let nonce = vec![0x33; 16];

        let mut drbg = HmacDrbg::instantiate(&entropy, &nonce, None).unwrap();

        let new_entropy = vec![0x88; 32];
        let result = drbg.reseed(&new_entropy, None);
        assert!(result.is_ok());

        assert_eq!(drbg.reseed_counter, 1);
    }

    #[test]
    fn test_hmac_drbg_deterministic() {
        let entropy = vec![0x42; 32];
        let nonce = vec![0x33; 16];

        let mut drbg1 = HmacDrbg::instantiate(&entropy, &nonce, None).unwrap();
        let mut drbg2 = HmacDrbg::instantiate(&entropy, &nonce, None).unwrap();

        let mut output1 = vec![0u8; 32];
        let mut output2 = vec![0u8; 32];

        drbg1.generate(&mut output1, None).unwrap();
        drbg2.generate(&mut output2, None).unwrap();

        // Same entropy and nonce should produce same output
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_hmac_drbg_with_personalization() {
        let entropy = vec![0x42; 32];
        let nonce = vec![0x33; 16];
        let personalization = b"test personalization";

        let drbg = HmacDrbg::instantiate(&entropy, &nonce, Some(personalization));
        assert!(drbg.is_ok());
    }

    #[test]
    fn test_hmac_drbg_insufficient_entropy() {
        let entropy = vec![0x42; 16]; // Too short
        let nonce = vec![0x33; 16];

        let drbg = HmacDrbg::instantiate(&entropy, &nonce, None);
        assert!(drbg.is_err());
    }
}
