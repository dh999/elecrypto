/**
 * Deterministic Random Bit Generator (DRBG) functions for Elecrypto
 *
 * NIST SP 800-90A compliant random number generation.
 */

import { lib, checkResult } from './lib';

/**
 * Generate random bytes using HMAC-DRBG (NIST SP 800-90A)
 *
 * Uses HMAC-SHA256 as the underlying PRF.
 *
 * @param seed Initial entropy (at least 32 bytes recommended)
 * @param outputLen Number of random bytes to generate
 * @returns Random bytes
 */
export function hmacDrbgGenerate(seed: Buffer, outputLen: number): Buffer {
  if (seed.length < 1) {
    throw new Error('Seed cannot be empty');
  }
  if (outputLen < 1) {
    throw new Error('Output length must be at least 1');
  }

  const output = Buffer.alloc(outputLen);

  const result = lib.elecrypto_hmac_drbg_generate(
    seed,
    seed.length,
    output,
    outputLen
  );

  checkResult(result);

  return output;
}

/**
 * Generate random bytes using CTR-DRBG (NIST SP 800-90A)
 *
 * Uses AES-256-CTR as the underlying block cipher.
 *
 * @param seed Initial entropy (at least 48 bytes: 32 for key + 16 for counter)
 * @param outputLen Number of random bytes to generate
 * @returns Random bytes
 */
export function ctrDrbgGenerate(seed: Buffer, outputLen: number): Buffer {
  if (seed.length < 48) {
    throw new Error('Seed must be at least 48 bytes for CTR-DRBG');
  }
  if (outputLen < 1) {
    throw new Error('Output length must be at least 1');
  }

  const output = Buffer.alloc(outputLen);

  const result = lib.elecrypto_ctr_drbg_generate(
    seed,
    seed.length,
    output,
    outputLen
  );

  checkResult(result);

  return output;
}
