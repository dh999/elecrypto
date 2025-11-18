/**
 * Digital signature functions for Elecrypto
 */

import { lib, checkResult, ED25519_PUBLIC_KEY_SIZE, ED25519_SECRET_KEY_SIZE, ED25519_SIGNATURE_SIZE } from './lib';

export interface Ed25519Keypair {
  publicKey: Buffer;
  secretKey: Buffer;
}

/**
 * Generate Ed25519 keypair
 */
export function ed25519GenerateKeypair(): Ed25519Keypair {
  const publicKey = Buffer.alloc(ED25519_PUBLIC_KEY_SIZE);
  const secretKey = Buffer.alloc(ED25519_SECRET_KEY_SIZE);

  checkResult(lib.elecrypto_ed25519_generate_keypair(publicKey, secretKey));

  return { publicKey, secretKey };
}

/**
 * Sign a message with Ed25519
 */
export function ed25519Sign(message: Buffer, secretKey: Buffer): Buffer {
  if (secretKey.length !== ED25519_SECRET_KEY_SIZE) {
    throw new Error(`Secret key must be ${ED25519_SECRET_KEY_SIZE} bytes, got ${secretKey.length}`);
  }

  const signature = Buffer.alloc(ED25519_SIGNATURE_SIZE);

  checkResult(lib.elecrypto_ed25519_sign(
    message,
    message.length,
    secretKey,
    signature
  ));

  return signature;
}

/**
 * Verify an Ed25519 signature
 */
export function ed25519Verify(message: Buffer, signature: Buffer, publicKey: Buffer): boolean {
  if (signature.length !== ED25519_SIGNATURE_SIZE) {
    throw new Error(`Signature must be ${ED25519_SIGNATURE_SIZE} bytes, got ${signature.length}`);
  }

  if (publicKey.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new Error(`Public key must be ${ED25519_PUBLIC_KEY_SIZE} bytes, got ${publicKey.length}`);
  }

  const result = lib.elecrypto_ed25519_verify(
    message,
    message.length,
    signature,
    publicKey
  );

  if (result < 0) {
    checkResult(result); // Will throw error
  }

  return result === 1;
}
