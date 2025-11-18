/**
 * Random number generation for Elecrypto
 */

import { lib, checkResult } from './lib';

/**
 * Generate cryptographically secure random bytes
 */
export function randomBytes(length: number): Buffer {
  if (length < 0) {
    throw new Error('Length must be non-negative');
  }

  const output = Buffer.alloc(length);
  checkResult(lib.elecrypto_random_bytes(output, length));
  return output;
}
