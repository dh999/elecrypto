/**
 * Post-Quantum Cryptography functions for Elecrypto
 *
 * NIST standard post-quantum algorithms:
 * - Kyber (ML-KEM): Key Encapsulation Mechanism
 * - Dilithium (ML-DSA): Digital Signatures
 */

import {
  lib,
  checkResult,
  KYBER512_PUBLIC_KEY_SIZE,
  KYBER512_SECRET_KEY_SIZE,
  KYBER512_CIPHERTEXT_SIZE,
  KYBER512_SHARED_SECRET_SIZE,
  DILITHIUM2_PUBLIC_KEY_SIZE,
  DILITHIUM2_SECRET_KEY_SIZE,
  DILITHIUM2_SIGNATURE_SIZE,
} from './lib';

export interface Kyber512Keypair {
  publicKey: Buffer;
  secretKey: Buffer;
}

export interface Kyber512EncapsulationResult {
  ciphertext: Buffer;
  sharedSecret: Buffer;
}

export interface Dilithium2Keypair {
  publicKey: Buffer;
  secretKey: Buffer;
}

// Kyber (ML-KEM) Key Encapsulation

/**
 * Generate a Kyber-512 key pair for key encapsulation
 */
export function kyber512GenerateKeypair(): Kyber512Keypair {
  const publicKey = Buffer.alloc(KYBER512_PUBLIC_KEY_SIZE);
  const secretKey = Buffer.alloc(KYBER512_SECRET_KEY_SIZE);

  const result = lib.elecrypto_kyber512_generate_keypair(publicKey, secretKey);
  checkResult(result);

  return { publicKey, secretKey };
}

/**
 * Encapsulate a shared secret using Kyber-512
 *
 * @param publicKey Kyber-512 public key (800 bytes)
 * @returns Ciphertext and shared secret
 */
export function kyber512Encapsulate(publicKey: Buffer): Kyber512EncapsulationResult {
  if (publicKey.length !== KYBER512_PUBLIC_KEY_SIZE) {
    throw new Error(`Public key must be ${KYBER512_PUBLIC_KEY_SIZE} bytes`);
  }

  const ciphertext = Buffer.alloc(KYBER512_CIPHERTEXT_SIZE);
  const sharedSecret = Buffer.alloc(KYBER512_SHARED_SECRET_SIZE);

  const result = lib.elecrypto_kyber512_encapsulate(
    publicKey,
    ciphertext,
    sharedSecret
  );

  checkResult(result);

  return { ciphertext, sharedSecret };
}

/**
 * Decapsulate a shared secret using Kyber-512
 *
 * @param ciphertext Kyber-512 ciphertext (768 bytes)
 * @param secretKey Kyber-512 secret key (1632 bytes)
 * @returns Shared secret (32 bytes)
 */
export function kyber512Decapsulate(ciphertext: Buffer, secretKey: Buffer): Buffer {
  if (ciphertext.length !== KYBER512_CIPHERTEXT_SIZE) {
    throw new Error(`Ciphertext must be ${KYBER512_CIPHERTEXT_SIZE} bytes`);
  }
  if (secretKey.length !== KYBER512_SECRET_KEY_SIZE) {
    throw new Error(`Secret key must be ${KYBER512_SECRET_KEY_SIZE} bytes`);
  }

  const sharedSecret = Buffer.alloc(KYBER512_SHARED_SECRET_SIZE);

  const result = lib.elecrypto_kyber512_decapsulate(
    ciphertext,
    secretKey,
    sharedSecret
  );

  checkResult(result);

  return sharedSecret;
}

// Dilithium (ML-DSA) Digital Signatures

/**
 * Generate a Dilithium2 key pair for digital signatures
 */
export function dilithium2GenerateKeypair(): Dilithium2Keypair {
  const publicKey = Buffer.alloc(DILITHIUM2_PUBLIC_KEY_SIZE);
  const secretKey = Buffer.alloc(DILITHIUM2_SECRET_KEY_SIZE);

  const result = lib.elecrypto_dilithium2_generate_keypair(publicKey, secretKey);
  checkResult(result);

  return { publicKey, secretKey };
}

/**
 * Sign a message using Dilithium2
 *
 * @param message Message to sign
 * @param secretKey Dilithium2 secret key (2560 bytes)
 * @returns Signature (2420 bytes)
 */
export function dilithium2Sign(message: Buffer, secretKey: Buffer): Buffer {
  if (secretKey.length !== DILITHIUM2_SECRET_KEY_SIZE) {
    throw new Error(`Secret key must be ${DILITHIUM2_SECRET_KEY_SIZE} bytes`);
  }

  const signature = Buffer.alloc(DILITHIUM2_SIGNATURE_SIZE);

  const result = lib.elecrypto_dilithium2_sign(
    message,
    message.length,
    secretKey,
    signature
  );

  checkResult(result);

  return signature;
}

/**
 * Verify a Dilithium2 signature
 *
 * @param message Original message
 * @param signature Signature to verify (2420 bytes)
 * @param publicKey Dilithium2 public key (1312 bytes)
 * @returns true if signature is valid
 */
export function dilithium2Verify(message: Buffer, signature: Buffer, publicKey: Buffer): boolean {
  if (signature.length !== DILITHIUM2_SIGNATURE_SIZE) {
    throw new Error(`Signature must be ${DILITHIUM2_SIGNATURE_SIZE} bytes`);
  }
  if (publicKey.length !== DILITHIUM2_PUBLIC_KEY_SIZE) {
    throw new Error(`Public key must be ${DILITHIUM2_PUBLIC_KEY_SIZE} bytes`);
  }

  const result = lib.elecrypto_dilithium2_verify(
    message,
    message.length,
    signature,
    publicKey
  );

  checkResult(result);

  return true;
}
