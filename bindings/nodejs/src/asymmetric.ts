/**
 * Asymmetric encryption functions for Elecrypto
 *
 * Includes RSA-OAEP and ECIES implementations.
 */

import * as ref from 'ref-napi';
import {
  lib,
  checkResult,
  RSA2048_PUBLIC_KEY_SIZE,
  RSA2048_PRIVATE_KEY_SIZE,
  ECIES_PUBLIC_KEY_SIZE,
  ECIES_PRIVATE_KEY_SIZE,
} from './lib';

export interface RsaKeypair {
  publicKey: Buffer;
  privateKey: Buffer;
}

export interface EciesKeypair {
  publicKey: Buffer;
  privateKey: Buffer;
}

// RSA-OAEP Functions

/**
 * Generate an RSA-2048 key pair
 */
export function rsaGenerateKeypair(): RsaKeypair {
  const publicKey = Buffer.alloc(RSA2048_PUBLIC_KEY_SIZE);
  const privateKey = Buffer.alloc(RSA2048_PRIVATE_KEY_SIZE);

  const result = lib.elecrypto_rsa_generate_keypair_2048(publicKey, privateKey);
  checkResult(result);

  return { publicKey, privateKey };
}

/**
 * Encrypt data using RSA-OAEP with SHA-256
 *
 * @param plaintext Data to encrypt (max ~190 bytes for RSA-2048)
 * @param publicKey RSA public key in DER format
 * @returns Encrypted ciphertext
 */
export function rsaEncrypt(plaintext: Buffer, publicKey: Buffer): Buffer {
  const maxCiphertextLen = 256;
  const ciphertext = Buffer.alloc(maxCiphertextLen);
  const ciphertextLen = ref.alloc('uint', 0);

  const result = lib.elecrypto_rsa_encrypt(
    plaintext,
    plaintext.length,
    publicKey,
    publicKey.length,
    ciphertext,
    ciphertextLen
  );

  checkResult(result);

  return ciphertext.slice(0, ciphertextLen.deref());
}

/**
 * Decrypt data using RSA-OAEP with SHA-256
 *
 * @param ciphertext Encrypted data
 * @param privateKey RSA private key in DER format
 * @returns Decrypted plaintext
 */
export function rsaDecrypt(ciphertext: Buffer, privateKey: Buffer): Buffer {
  const maxPlaintextLen = 256;
  const plaintext = Buffer.alloc(maxPlaintextLen);
  const plaintextLen = ref.alloc('uint', 0);

  const result = lib.elecrypto_rsa_decrypt(
    ciphertext,
    ciphertext.length,
    privateKey,
    privateKey.length,
    plaintext,
    plaintextLen
  );

  checkResult(result);

  return plaintext.slice(0, plaintextLen.deref());
}

// ECIES Functions

/**
 * Generate an ECIES (P-256) key pair
 */
export function eciesGenerateKeypair(): EciesKeypair {
  const publicKey = Buffer.alloc(ECIES_PUBLIC_KEY_SIZE);
  const privateKey = Buffer.alloc(ECIES_PRIVATE_KEY_SIZE);

  const result = lib.elecrypto_ecies_generate_keypair(publicKey, privateKey);
  checkResult(result);

  return { publicKey, privateKey };
}

/**
 * Encrypt data using ECIES (P-256 ECDH + HKDF-SHA256 + AES-256-GCM)
 *
 * @param plaintext Data to encrypt
 * @param publicKey ECIES public key (65 bytes)
 * @returns Encrypted ciphertext
 */
export function eciesEncrypt(plaintext: Buffer, publicKey: Buffer): Buffer {
  if (publicKey.length !== ECIES_PUBLIC_KEY_SIZE) {
    throw new Error(`Public key must be ${ECIES_PUBLIC_KEY_SIZE} bytes`);
  }

  // ECIES ciphertext = ephemeral_pubkey (65) + nonce (12) + ciphertext + tag (16)
  const maxCiphertextLen = 65 + 12 + plaintext.length + 16;
  const ciphertext = Buffer.alloc(maxCiphertextLen);
  const ciphertextLen = ref.alloc('uint', 0);

  const result = lib.elecrypto_ecies_encrypt(
    plaintext,
    plaintext.length,
    publicKey,
    ciphertext,
    ciphertextLen
  );

  checkResult(result);

  return ciphertext.slice(0, ciphertextLen.deref());
}

/**
 * Decrypt data using ECIES
 *
 * @param ciphertext Encrypted data from eciesEncrypt
 * @param privateKey ECIES private key (32 bytes)
 * @returns Decrypted plaintext
 */
export function eciesDecrypt(ciphertext: Buffer, privateKey: Buffer): Buffer {
  if (privateKey.length !== ECIES_PRIVATE_KEY_SIZE) {
    throw new Error(`Private key must be ${ECIES_PRIVATE_KEY_SIZE} bytes`);
  }

  const maxPlaintextLen = Math.max(1, ciphertext.length - 65 - 12 - 16);
  const plaintext = Buffer.alloc(maxPlaintextLen);
  const plaintextLen = ref.alloc('uint', 0);

  const result = lib.elecrypto_ecies_decrypt(
    ciphertext,
    ciphertext.length,
    privateKey,
    plaintext,
    plaintextLen
  );

  checkResult(result);

  return plaintext.slice(0, plaintextLen.deref());
}
