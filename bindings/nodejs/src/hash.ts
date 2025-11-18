/**
 * Hash functions for Elecrypto
 */

import { lib, checkResult } from './lib';

/**
 * Compute SHA-256 hash
 */
export function sha256(data: Buffer): Buffer {
  const output = Buffer.alloc(32);
  checkResult(lib.elecrypto_sha256(data, data.length, output));
  return output;
}

/**
 * Compute SHA-512 hash
 */
export function sha512(data: Buffer): Buffer {
  const output = Buffer.alloc(64);
  checkResult(lib.elecrypto_sha512(data, data.length, output));
  return output;
}

/**
 * Compute SHA3-256 hash
 */
export function sha3_256(data: Buffer): Buffer {
  const output = Buffer.alloc(32);
  checkResult(lib.elecrypto_sha3_256(data, data.length, output));
  return output;
}

/**
 * Compute BLAKE3 hash with custom output length
 */
export function blake3(data: Buffer, outputLength: number = 32): Buffer {
  const output = Buffer.alloc(outputLength);
  checkResult(lib.elecrypto_blake3(data, data.length, output, outputLength));
  return output;
}
