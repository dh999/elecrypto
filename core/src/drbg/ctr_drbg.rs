//! CTR-DRBG implementation (NIST SP 800-90A)
//!
//! Counter mode Deterministic Random Bit Generator using AES-256

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use zeroize::Zeroizing;

use crate::{Error, Result};
use super::{Drbg, RESEED_INTERVAL, MAX_BYTES_PER_REQUEST, SECURITY_STRENGTH_256};

const KEYLEN: usize = 32; // AES-256 key length
const BLOCKLEN: usize = 16; // AES block length
const SEEDLEN: usize = KEYLEN + BLOCKLEN; // 48 bytes

/// CTR-DRBG with AES-256
pub struct CtrDrbg {
    /// AES key
    key: Zeroizing<Vec<u8>>,
    /// Counter V
    v: Zeroizing<Vec<u8>>,
    /// Reseed counter
    reseed_counter: u64,
    /// Security strength in bits
    security_strength: usize,
}

impl CtrDrbg {
    /// Block cipher DF (derivation function) - 10.4.2
    fn block_cipher_df(input: &[u8], requested_bytes: usize) -> Result<Vec<u8>> {
        if requested_bytes > 512 {
            return Err(Error::InvalidInput("Requested bytes too large for BCC".to_string()));
        }

        // Use a simplified version for now
        // Full implementation would use BCC (Block Cipher Chaining)
        let mut output = Vec::with_capacity(requested_bytes);

        // Simple padding and derivation
        let mut temp = input.to_vec();
        temp.extend_from_slice(&requested_bytes.to_be_bytes());

        // Pad to block size
        while temp.len() % BLOCKLEN != 0 {
            temp.push(0x80);
            while temp.len() % BLOCKLEN != 0 && temp.len() < temp.capacity() {
                temp.push(0x00);
            }
        }

        // Generate key for encryption
        let key_material = vec![0u8; KEYLEN];
        let cipher = Aes256::new(GenericArray::from_slice(&key_material));

        // Encrypt blocks
        let mut pos = 0;
        while output.len() < requested_bytes && pos + BLOCKLEN <= temp.len() {
            let mut block = GenericArray::clone_from_slice(&temp[pos..pos + BLOCKLEN]);
            cipher.encrypt_block(&mut block);
            output.extend_from_slice(&block);
            pos += BLOCKLEN;
        }

        // If still need more, generate additional blocks
        let mut counter = 0u128;
        while output.len() < requested_bytes {
            let mut block = GenericArray::from(counter.to_be_bytes());
            cipher.encrypt_block(&mut block);
            output.extend_from_slice(&block);
            counter += 1;
        }

        output.truncate(requested_bytes);
        Ok(output)
    }

    /// Increment counter V
    fn increment_counter(v: &mut [u8]) {
        let mut carry = 1u16;
        for i in (0..v.len()).rev() {
            let sum = v[i] as u16 + carry;
            v[i] = sum as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }
    }

    /// Update function (10.2.1.2)
    fn update(&mut self, provided_data: Option<&[u8]>) -> Result<()> {
        let mut temp = Vec::with_capacity(SEEDLEN);

        // Generate seedlen bits using BCC
        let cipher = Aes256::new(GenericArray::from_slice(&self.key));

        while temp.len() < SEEDLEN {
            // Increment V
            Self::increment_counter(&mut self.v);

            // Encrypt V
            let mut block = GenericArray::clone_from_slice(&self.v[..BLOCKLEN]);
            cipher.encrypt_block(&mut block);
            temp.extend_from_slice(&block);
        }

        temp.truncate(SEEDLEN);

        // If provided_data exists, XOR it
        if let Some(data) = provided_data {
            let data_len = data.len().min(SEEDLEN);
            for i in 0..data_len {
                temp[i] ^= data[i];
            }
        }

        // Update Key and V
        self.key.copy_from_slice(&temp[..KEYLEN]);
        self.v.copy_from_slice(&temp[KEYLEN..SEEDLEN]);

        Ok(())
    }
}

impl Drbg for CtrDrbg {
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

        // Derive seed from seed_material
        let seed = Self::block_cipher_df(&seed_material, SEEDLEN)?;

        // Initialize Key and V to zero
        let key = Zeroizing::new(vec![0u8; KEYLEN]);
        let v = Zeroizing::new(vec![0u8; BLOCKLEN]);

        let mut drbg = CtrDrbg {
            key,
            v,
            reseed_counter: 1,
            security_strength: SECURITY_STRENGTH_256,
        };

        // Update with seed
        drbg.update(Some(&seed))?;

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

        // Derive seed
        let seed = Self::block_cipher_df(&seed_material, SEEDLEN)?;

        // Update
        self.update(Some(&seed))?;
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

        // If additional input, update first
        if let Some(add) = additional {
            let add_data = Self::block_cipher_df(add, SEEDLEN)?;
            self.update(Some(&add_data))?;
        } else {
            self.update(None)?;
        }

        // Generate output blocks
        let cipher = Aes256::new(GenericArray::from_slice(&self.key));
        let mut generated = 0;

        while generated < output.len() {
            // Increment V
            Self::increment_counter(&mut self.v);

            // Encrypt V
            let mut block = GenericArray::clone_from_slice(&self.v[..BLOCKLEN]);
            cipher.encrypt_block(&mut block);

            // Copy to output
            let remaining = output.len() - generated;
            let to_copy = remaining.min(BLOCKLEN);
            output[generated..generated + to_copy].copy_from_slice(&block[..to_copy]);
            generated += to_copy;
        }

        // Update for backtracking resistance
        self.update(Some(&additional.unwrap_or(&[])))?;

        self.reseed_counter += 1;

        Ok(())
    }

    fn security_strength(&self) -> usize {
        self.security_strength
    }
}

impl Drop for CtrDrbg {
    fn drop(&mut self) {
        // Zeroizing handles clearing key and V
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctr_drbg_instantiate() {
        let entropy = vec![0x42; 32];
        let nonce = vec![0x33; 16];

        let drbg = CtrDrbg::instantiate(&entropy, &nonce, None);
        assert!(drbg.is_ok());
    }

    #[test]
    fn test_ctr_drbg_generate() {
        let entropy = vec![0x42; 32];
        let nonce = vec![0x33; 16];

        let mut drbg = CtrDrbg::instantiate(&entropy, &nonce, None).unwrap();
        let mut output = vec![0u8; 64];

        let result = drbg.generate(&mut output, None);
        assert!(result.is_ok());

        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_ctr_drbg_reseed() {
        let entropy = vec![0x42; 32];
        let nonce = vec![0x33; 16];

        let mut drbg = CtrDrbg::instantiate(&entropy, &nonce, None).unwrap();

        let new_entropy = vec![0x88; 32];
        let result = drbg.reseed(&new_entropy, None);
        assert!(result.is_ok());

        assert_eq!(drbg.reseed_counter, 1);
    }

    #[test]
    fn test_ctr_drbg_increment() {
        let mut v = vec![0xFF, 0xFF];
        CtrDrbg::increment_counter(&mut v);
        assert_eq!(v, vec![0x00, 0x00]);

        let mut v = vec![0x00, 0xFF];
        CtrDrbg::increment_counter(&mut v);
        assert_eq!(v, vec![0x01, 0x00]);
    }
}
