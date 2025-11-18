//! Hash-DRBG implementation (NIST SP 800-90A)
//!
//! Hash-based Deterministic Random Bit Generator using SHA-256

use sha2::{Sha256, Digest};
use zeroize::Zeroizing;

use crate::{Error, Result};
use super::{Drbg, RESEED_INTERVAL, MAX_BYTES_PER_REQUEST, SECURITY_STRENGTH_256};

const OUTLEN: usize = 32; // SHA-256 output length
const SEEDLEN: usize = 55; // seedlen for SHA-256 (440 bits)

/// Hash-DRBG with SHA-256
pub struct HashDrbg {
    /// Internal state V
    v: Zeroizing<Vec<u8>>,
    /// Constant C
    c: Zeroizing<Vec<u8>>,
    /// Reseed counter
    reseed_counter: u64,
    /// Security strength in bits
    security_strength: usize,
}

impl HashDrbg {
    /// Hash derivation function (10.4.1)
    fn hash_df(input: &[u8], requested_bytes: usize) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(requested_bytes);
        let mut counter = 1u8;

        while output.len() < requested_bytes {
            let mut hasher = Sha256::new();
            hasher.update(&[counter]);
            hasher.update(&(requested_bytes * 8).to_be_bytes()[4..]); // 32-bit length in bits
            hasher.update(input);

            let hash = hasher.finalize();
            output.extend_from_slice(&hash);
            counter = counter.wrapping_add(1);
        }

        output.truncate(requested_bytes);
        Ok(output)
    }

    /// Hashgen function (10.1.1.4)
    fn hashgen(&self, requested_bytes: usize) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(requested_bytes);
        let mut data = self.v.to_vec();

        while output.len() < requested_bytes {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let hash = hasher.finalize();

            output.extend_from_slice(&hash);

            // Increment data as big-endian integer
            let mut carry = 1u16;
            for i in (0..data.len()).rev() {
                let sum = data[i] as u16 + carry;
                data[i] = sum as u8;
                carry = sum >> 8;
                if carry == 0 {
                    break;
                }
            }
        }

        output.truncate(requested_bytes);
        Ok(output)
    }

    /// Add two byte arrays as big-endian integers
    fn add_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut result = vec![0u8; a.len().max(b.len())];
        let mut carry = 0u16;

        for i in (0..result.len()).rev() {
            let a_val = if i < a.len() && (a.len() - i - 1) < a.len() {
                a[a.len() - result.len() + i] as u16
            } else {
                0
            };

            let b_val = if i < b.len() && (b.len() - i - 1) < b.len() {
                b[b.len() - result.len() + i] as u16
            } else {
                0
            };

            let sum = a_val + b_val + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }

        result
    }
}

impl Drbg for HashDrbg {
    fn instantiate(entropy: &[u8], nonce: &[u8], personalization: Option<&[u8]>) -> Result<Self> {
        if entropy.len() < 32 {
            return Err(Error::InvalidInput("Insufficient entropy".to_string()));
        }

        if nonce.len() < 16 {
            return Err(Error::InvalidInput("Nonce too short (min 16 bytes)".to_string()));
        }

        // Combine seed material
        let mut seed_material = Vec::new();
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(nonce);
        if let Some(p) = personalization {
            seed_material.extend_from_slice(p);
        }

        // V = Hash_df(seed_material, seedlen)
        let v = Zeroizing::new(Self::hash_df(&seed_material, SEEDLEN)?);

        // C = Hash_df(0x00 || V, seedlen)
        let mut c_input = vec![0x00];
        c_input.extend_from_slice(&v);
        let c = Zeroizing::new(Self::hash_df(&c_input, SEEDLEN)?);

        Ok(HashDrbg {
            v,
            c,
            reseed_counter: 1,
            security_strength: SECURITY_STRENGTH_256,
        })
    }

    fn reseed(&mut self, entropy: &[u8], additional: Option<&[u8]>) -> Result<()> {
        if entropy.len() < 32 {
            return Err(Error::InvalidInput("Insufficient entropy for reseed".to_string()));
        }

        // Combine seed material: 0x01 || V || entropy || additional
        let mut seed_material = vec![0x01];
        seed_material.extend_from_slice(&self.v);
        seed_material.extend_from_slice(entropy);
        if let Some(add) = additional {
            seed_material.extend_from_slice(add);
        }

        // V = Hash_df(seed_material, seedlen)
        self.v = Zeroizing::new(Self::hash_df(&seed_material, SEEDLEN)?);

        // C = Hash_df(0x00 || V, seedlen)
        let mut c_input = vec![0x00];
        c_input.extend_from_slice(&self.v);
        self.c = Zeroizing::new(Self::hash_df(&c_input, SEEDLEN)?);

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

        if self.reseed_counter > RESEED_INTERVAL {
            return Err(Error::InvalidInput("Reseed required".to_string()));
        }

        // If additional input provided, update V
        if let Some(add) = additional {
            // w = Hash(0x02 || V || additional_input)
            let mut hasher = Sha256::new();
            hasher.update(&[0x02]);
            hasher.update(&*self.v);
            hasher.update(add);
            let w = hasher.finalize();

            // V = (V + w) mod 2^seedlen
            let w_extended = {
                let mut temp = vec![0u8; SEEDLEN];
                let start = SEEDLEN.saturating_sub(w.len());
                temp[start..].copy_from_slice(&w);
                temp
            };
            let new_v = Self::add_bytes(&self.v, &w_extended);
            self.v.copy_from_slice(&new_v[new_v.len() - SEEDLEN..]);
        }

        // Generate output using Hashgen
        let generated = self.hashgen(output.len())?;
        output.copy_from_slice(&generated);

        // H = Hash(0x03 || V)
        let mut hasher = Sha256::new();
        hasher.update(&[0x03]);
        hasher.update(&*self.v);
        let h = hasher.finalize();

        // V = (V + H + C + reseed_counter) mod 2^seedlen
        let h_extended = {
            let mut temp = vec![0u8; SEEDLEN];
            let start = SEEDLEN.saturating_sub(h.len());
            temp[start..].copy_from_slice(&h);
            temp
        };

        let counter_bytes = {
            let mut temp = vec![0u8; SEEDLEN];
            let bytes = self.reseed_counter.to_be_bytes();
            let start = SEEDLEN.saturating_sub(bytes.len());
            temp[start..].copy_from_slice(&bytes);
            temp
        };

        let temp1 = Self::add_bytes(&self.v, &h_extended);
        let temp2 = Self::add_bytes(&temp1, &self.c);
        let new_v = Self::add_bytes(&temp2, &counter_bytes);
        self.v.copy_from_slice(&new_v[new_v.len() - SEEDLEN..]);

        self.reseed_counter += 1;

        Ok(())
    }

    fn security_strength(&self) -> usize {
        self.security_strength
    }
}

impl Drop for HashDrbg {
    fn drop(&mut self) {
        // Zeroizing handles clearing V and C
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_drbg_instantiate() {
        let entropy = vec![0x42; 32];
        let nonce = vec![0x33; 16];

        let drbg = HashDrbg::instantiate(&entropy, &nonce, None);
        assert!(drbg.is_ok());
    }

    #[test]
    fn test_hash_drbg_generate() {
        let entropy = vec![0x42; 32];
        let nonce = vec![0x33; 16];

        let mut drbg = HashDrbg::instantiate(&entropy, &nonce, None).unwrap();
        let mut output = vec![0u8; 64];

        let result = drbg.generate(&mut output, None);
        assert!(result.is_ok());

        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hash_drbg_reseed() {
        let entropy = vec![0x42; 32];
        let nonce = vec![0x33; 16];

        let mut drbg = HashDrbg::instantiate(&entropy, &nonce, None).unwrap();

        let new_entropy = vec![0x88; 32];
        let result = drbg.reseed(&new_entropy, None);
        assert!(result.is_ok());

        assert_eq!(drbg.reseed_counter, 1);
    }

    #[test]
    fn test_hash_df() {
        let input = b"test input data";
        let output = HashDrbg::hash_df(input, 32);

        assert!(output.is_ok());
        assert_eq!(output.unwrap().len(), 32);
    }
}
