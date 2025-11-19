/**
 * Elecrypto Node.js/TypeScript Bindings
 *
 * Cross-platform cryptographic library with post-quantum support
 */

export { ElecryptoError } from './lib';

// Symmetric encryption
export {
  aesGenerateKey,
  aesGcmEncrypt,
  aesGcmDecrypt,
  chacha20GenerateKey,
  chacha20Poly1305Encrypt,
  chacha20Poly1305Decrypt,
  EncryptResult
} from './symmetric';

// Hash functions
export {
  sha256,
  sha512,
  sha3_256,
  blake3
} from './hash';

// Random number generation
export { randomBytes } from './random';

// Digital signatures
export {
  ed25519GenerateKeypair,
  ed25519Sign,
  ed25519Verify,
  Ed25519Keypair
} from './signing';

// Key derivation
export {
  pbkdf2,
  argon2id,
  hkdf,
  Argon2idResult
} from './kdf';

// Asymmetric encryption
export {
  rsaGenerateKeypair,
  rsaEncrypt,
  rsaDecrypt,
  eciesGenerateKeypair,
  eciesEncrypt,
  eciesDecrypt,
  RsaKeypair,
  EciesKeypair
} from './asymmetric';

// DRBG
export {
  hmacDrbgGenerate,
  ctrDrbgGenerate
} from './drbg';

// Post-Quantum Cryptography
export {
  kyber512GenerateKeypair,
  kyber512Encapsulate,
  kyber512Decapsulate,
  dilithium2GenerateKeypair,
  dilithium2Sign,
  dilithium2Verify,
  Kyber512Keypair,
  Kyber512EncapsulationResult,
  Dilithium2Keypair
} from './pqc';
