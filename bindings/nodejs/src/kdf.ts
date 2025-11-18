/**
 * Key Derivation Functions for Elecrypto
 */

import { lib, checkResult } from './lib';

export interface Argon2idResult {
  derivedKey: Buffer;
  salt: Buffer;
}

/**
 * Derive key using PBKDF2-HMAC-SHA256
 */
export function pbkdf2(
  password: Buffer,
  salt: Buffer,
  iterations: number = 600000,
  keyLength: number = 32
): Buffer {
  const output = Buffer.alloc(keyLength);

  checkResult(lib.elecrypto_pbkdf2(
    password,
    password.length,
    salt,
    salt.length,
    iterations,
    output,
    keyLength
  ));

  return output;
}

/**
 * Derive key using Argon2id (recommended for passwords)
 */
export function argon2id(
  password: Buffer,
  salt?: Buffer,
  memoryCost: number = 65536,
  timeCost: number = 3,
  parallelism: number = 4,
  keyLength: number = 32
): Argon2idResult {
  if (salt && salt.length !== 16) {
    throw new Error('Salt must be 16 bytes if provided');
  }

  const output = Buffer.alloc(keyLength);
  const saltOut = Buffer.alloc(16);
  const saltPtr = salt || Buffer.alloc(0);

  checkResult(lib.elecrypto_argon2id(
    password,
    password.length,
    salt ? saltPtr : null,
    memoryCost,
    timeCost,
    parallelism,
    output,
    keyLength,
    saltOut
  ));

  return {
    derivedKey: output,
    salt: saltOut
  };
}

/**
 * Derive key using HKDF (HMAC-based Key Derivation Function)
 */
export function hkdf(
  inputKeyMaterial: Buffer,
  salt?: Buffer,
  info?: Buffer,
  keyLength: number = 32
): Buffer {
  const output = Buffer.alloc(keyLength);

  const saltPtr = salt || Buffer.alloc(0);
  const saltLen = salt ? salt.length : 0;

  const infoPtr = info || Buffer.alloc(0);
  const infoLen = info ? info.length : 0;

  checkResult(lib.elecrypto_hkdf(
    inputKeyMaterial,
    inputKeyMaterial.length,
    salt ? saltPtr : null,
    saltLen,
    info ? infoPtr : null,
    infoLen,
    output,
    keyLength
  ));

  return output;
}
