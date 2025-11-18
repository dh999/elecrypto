/**
 * Symmetric encryption functions for Elecrypto
 */

import { lib, checkResult, AES_KEY_SIZE, AES_NONCE_SIZE, AES_TAG_SIZE, CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE } from './lib';

export interface EncryptResult {
  ciphertext: Buffer;
  nonce: Buffer;
}

/**
 * Generate a random AES-256 key
 */
export function aesGenerateKey(): Buffer {
  const key = Buffer.alloc(AES_KEY_SIZE);
  checkResult(lib.elecrypto_aes_generate_key(key));
  return key;
}

/**
 * Encrypt data using AES-256-GCM
 */
export function aesGcmEncrypt(plaintext: Buffer, key: Buffer, nonce?: Buffer): EncryptResult {
  if (key.length !== AES_KEY_SIZE) {
    throw new Error(`Key must be ${AES_KEY_SIZE} bytes, got ${key.length}`);
  }

  if (nonce && nonce.length !== AES_NONCE_SIZE) {
    throw new Error(`Nonce must be ${AES_NONCE_SIZE} bytes, got ${nonce.length}`);
  }

  const ciphertext = Buffer.alloc(plaintext.length + AES_TAG_SIZE);
  const nonceOut = Buffer.alloc(AES_NONCE_SIZE);
  const noncePtr = nonce || Buffer.alloc(0);

  checkResult(lib.elecrypto_aes_gcm_encrypt(
    plaintext,
    plaintext.length,
    key,
    nonce ? noncePtr : null,
    ciphertext,
    nonceOut
  ));

  return { ciphertext, nonce: nonceOut };
}

/**
 * Decrypt data using AES-256-GCM
 */
export function aesGcmDecrypt(ciphertext: Buffer, key: Buffer, nonce: Buffer): Buffer {
  if (key.length !== AES_KEY_SIZE) {
    throw new Error(`Key must be ${AES_KEY_SIZE} bytes, got ${key.length}`);
  }

  if (nonce.length !== AES_NONCE_SIZE) {
    throw new Error(`Nonce must be ${AES_NONCE_SIZE} bytes, got ${nonce.length}`);
  }

  const plaintextLen = ciphertext.length - AES_TAG_SIZE;
  if (plaintextLen < 0) {
    throw new Error('Ciphertext too short');
  }

  const plaintext = Buffer.alloc(plaintextLen);

  checkResult(lib.elecrypto_aes_gcm_decrypt(
    ciphertext,
    ciphertext.length,
    key,
    nonce,
    plaintext
  ));

  return plaintext;
}

/**
 * Generate a random ChaCha20-Poly1305 key
 */
export function chacha20GenerateKey(): Buffer {
  const key = Buffer.alloc(CHACHA20_KEY_SIZE);
  checkResult(lib.elecrypto_chacha20_generate_key(key));
  return key;
}

/**
 * Encrypt data using ChaCha20-Poly1305
 */
export function chacha20Poly1305Encrypt(plaintext: Buffer, key: Buffer, nonce?: Buffer): EncryptResult {
  if (key.length !== CHACHA20_KEY_SIZE) {
    throw new Error(`Key must be ${CHACHA20_KEY_SIZE} bytes, got ${key.length}`);
  }

  if (nonce && nonce.length !== CHACHA20_NONCE_SIZE) {
    throw new Error(`Nonce must be ${CHACHA20_NONCE_SIZE} bytes, got ${nonce.length}`);
  }

  const ciphertext = Buffer.alloc(plaintext.length + 16);
  const nonceOut = Buffer.alloc(CHACHA20_NONCE_SIZE);
  const noncePtr = nonce || Buffer.alloc(0);

  checkResult(lib.elecrypto_chacha20_poly1305_encrypt(
    plaintext,
    plaintext.length,
    key,
    nonce ? noncePtr : null,
    ciphertext,
    nonceOut
  ));

  return { ciphertext, nonce: nonceOut };
}

/**
 * Decrypt data using ChaCha20-Poly1305
 */
export function chacha20Poly1305Decrypt(ciphertext: Buffer, key: Buffer, nonce: Buffer): Buffer {
  if (key.length !== CHACHA20_KEY_SIZE) {
    throw new Error(`Key must be ${CHACHA20_KEY_SIZE} bytes, got ${key.length}`);
  }

  if (nonce.length !== CHACHA20_NONCE_SIZE) {
    throw new Error(`Nonce must be ${CHACHA20_NONCE_SIZE} bytes, got ${nonce.length}`);
  }

  const plaintextLen = ciphertext.length - 16;
  if (plaintextLen < 0) {
    throw new Error('Ciphertext too short');
  }

  const plaintext = Buffer.alloc(plaintextLen);

  checkResult(lib.elecrypto_chacha20_poly1305_decrypt(
    ciphertext,
    ciphertext.length,
    key,
    nonce,
    plaintext
  ));

  return plaintext;
}
