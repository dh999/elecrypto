/**
 * Elecrypto Node.js Bindings - C Library Loader
 */

import * as ffi from 'ffi-napi';
import * as ref from 'ref-napi';
import * as path from 'path';
import * as fs from 'fs';

// Define types
const voidPtr = ref.refType(ref.types.void);
const uint8Ptr = ref.refType(ref.types.uint8);
const uint8Array = ref.types.uint8;

// Error codes
export const ELECRYPTO_SUCCESS = 0;
export const ELECRYPTO_ERROR_INVALID_INPUT = -1;
export const ELECRYPTO_ERROR_INVALID_KEY_LENGTH = -2;
export const ELECRYPTO_ERROR_INVALID_NONCE_LENGTH = -3;
export const ELECRYPTO_ERROR_AUTHENTICATION_FAILED = -4;
export const ELECRYPTO_ERROR_ENCRYPTION_FAILED = -5;
export const ELECRYPTO_ERROR_DECRYPTION_FAILED = -6;
export const ELECRYPTO_ERROR_SIGNING_FAILED = -7;
export const ELECRYPTO_ERROR_VERIFICATION_FAILED = -8;

// Constants
export const AES_KEY_SIZE = 32;
export const AES_NONCE_SIZE = 12;
export const AES_TAG_SIZE = 16;
export const CHACHA20_KEY_SIZE = 32;
export const CHACHA20_NONCE_SIZE = 12;
export const ED25519_PUBLIC_KEY_SIZE = 32;
export const ED25519_SECRET_KEY_SIZE = 32;
export const ED25519_SIGNATURE_SIZE = 64;

// Find the shared library
function findLibrary(): string {
  const libName = process.platform === 'win32'
    ? 'elecrypto_core.dll'
    : process.platform === 'darwin'
    ? 'libelecrypto_core.dylib'
    : 'libelecrypto_core.so';

  const searchPaths = [
    // Development path
    path.join(__dirname, '..', '..', '..', 'core', 'target', 'release', libName),
    // Installed path
    path.join(process.cwd(), 'native', libName),
    libName,
  ];

  for (const libPath of searchPaths) {
    if (fs.existsSync(libPath)) {
      return libPath;
    }
  }

  // Fallback to just the name and let the system find it
  return libName;
}

// Load the library
const libPath = findLibrary();

export const lib = ffi.Library(libPath, {
  // Random
  'elecrypto_random_bytes': ['int', [uint8Ptr, 'uint']],

  // Hash functions
  'elecrypto_sha256': ['int', [uint8Ptr, 'uint', uint8Ptr]],
  'elecrypto_sha512': ['int', [uint8Ptr, 'uint', uint8Ptr]],
  'elecrypto_sha3_256': ['int', [uint8Ptr, 'uint', uint8Ptr]],
  'elecrypto_blake3': ['int', [uint8Ptr, 'uint', uint8Ptr, 'uint']],

  // AES-GCM
  'elecrypto_aes_generate_key': ['int', [uint8Ptr]],
  'elecrypto_aes_gcm_encrypt': ['int', [uint8Ptr, 'uint', uint8Ptr, uint8Ptr, uint8Ptr, uint8Ptr]],
  'elecrypto_aes_gcm_decrypt': ['int', [uint8Ptr, 'uint', uint8Ptr, uint8Ptr, uint8Ptr]],

  // ChaCha20-Poly1305
  'elecrypto_chacha20_generate_key': ['int', [uint8Ptr]],
  'elecrypto_chacha20_poly1305_encrypt': ['int', [uint8Ptr, 'uint', uint8Ptr, uint8Ptr, uint8Ptr, uint8Ptr]],
  'elecrypto_chacha20_poly1305_decrypt': ['int', [uint8Ptr, 'uint', uint8Ptr, uint8Ptr, uint8Ptr]],

  // Ed25519
  'elecrypto_ed25519_generate_keypair': ['int', [uint8Ptr, uint8Ptr]],
  'elecrypto_ed25519_sign': ['int', [uint8Ptr, 'uint', uint8Ptr, uint8Ptr]],
  'elecrypto_ed25519_verify': ['int', [uint8Ptr, 'uint', uint8Ptr, uint8Ptr]],

  // KDF
  'elecrypto_pbkdf2': ['int', [uint8Ptr, 'uint', uint8Ptr, 'uint', 'uint', uint8Ptr, 'uint']],
  'elecrypto_argon2id': ['int', [uint8Ptr, 'uint', uint8Ptr, 'uint', 'uint', 'uint', uint8Ptr, 'uint', uint8Ptr]],
  'elecrypto_hkdf': ['int', [uint8Ptr, 'uint', uint8Ptr, 'uint', uint8Ptr, 'uint', uint8Ptr, 'uint']],
});

// Error class
export class ElecryptoError extends Error {
  code: number;

  constructor(code: number, message?: string) {
    const errorMessages: { [key: number]: string } = {
      [ELECRYPTO_ERROR_INVALID_INPUT]: 'Invalid input',
      [ELECRYPTO_ERROR_INVALID_KEY_LENGTH]: 'Invalid key length',
      [ELECRYPTO_ERROR_INVALID_NONCE_LENGTH]: 'Invalid nonce length',
      [ELECRYPTO_ERROR_AUTHENTICATION_FAILED]: 'Authentication failed',
      [ELECRYPTO_ERROR_ENCRYPTION_FAILED]: 'Encryption failed',
      [ELECRYPTO_ERROR_DECRYPTION_FAILED]: 'Decryption failed',
      [ELECRYPTO_ERROR_SIGNING_FAILED]: 'Signing failed',
      [ELECRYPTO_ERROR_VERIFICATION_FAILED]: 'Verification failed',
    };

    super(message || errorMessages[code] || `Unknown error code: ${code}`);
    this.code = code;
    this.name = 'ElecryptoError';
  }
}

export function checkResult(result: number): void {
  if (result < 0) {
    throw new ElecryptoError(result);
  }
}
