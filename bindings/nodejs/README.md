# Elecrypto Node.js/TypeScript Bindings

Node.js and TypeScript bindings for the Elecrypto cryptographic library.

## Features

- **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Hash Functions**: SHA-256, SHA-512, SHA3-256, BLAKE3
- **Digital Signatures**: Ed25519
- **Key Derivation**: PBKDF2, Argon2id, HKDF
- **Random Number Generation**: CSPRNG
- **TypeScript Support**: Full type definitions included

## Installation

### From Source

1. First, build the Rust core library:
```bash
cd ../../core
cargo build --release
```

2. Install dependencies and build:
```bash
cd ../bindings/nodejs
npm install
npm run build
```

### Requirements

- Node.js 14.0.0 or higher
- Rust compiled elecrypto-core library

## Usage

### TypeScript

```typescript
import * as elecrypto from 'elecrypto';

// Hash function
const hash = elecrypto.sha256(Buffer.from('Hello, World!'));
console.log(hash.toString('hex'));

// AES-256-GCM encryption
const key = elecrypto.aesGenerateKey();
const { ciphertext, nonce } = elecrypto.aesGcmEncrypt(
  Buffer.from('Secret message'),
  key
);
const plaintext = elecrypto.aesGcmDecrypt(ciphertext, key, nonce);

// Ed25519 signatures
const { publicKey, secretKey } = elecrypto.ed25519GenerateKeypair();
const signature = elecrypto.ed25519Sign(Buffer.from('Message'), secretKey);
const isValid = elecrypto.ed25519Verify(Buffer.from('Message'), signature, publicKey);
```

### JavaScript

```javascript
const elecrypto = require('elecrypto');

// Generate random bytes
const random = elecrypto.randomBytes(32);

// ChaCha20-Poly1305 encryption
const key = elecrypto.chacha20GenerateKey();
const { ciphertext, nonce } = elecrypto.chacha20Poly1305Encrypt(
  Buffer.from('Secret!'),
  key
);

// Argon2id password hashing
const { derivedKey, salt } = elecrypto.argon2id(
  Buffer.from('password'),
  undefined,
  65536,  // 64 MB
  3,      // iterations
  4       // parallelism
);
```

## API Reference

### Symmetric Encryption

- `aesGenerateKey(): Buffer` - Generate AES-256 key (32 bytes)
- `aesGcmEncrypt(plaintext, key, nonce?): { ciphertext, nonce }` - Encrypt with AES-GCM
- `aesGcmDecrypt(ciphertext, key, nonce): Buffer` - Decrypt with AES-GCM
- `chacha20GenerateKey(): Buffer` - Generate ChaCha20 key (32 bytes)
- `chacha20Poly1305Encrypt(plaintext, key, nonce?): { ciphertext, nonce }` - Encrypt with ChaCha20
- `chacha20Poly1305Decrypt(ciphertext, key, nonce): Buffer` - Decrypt with ChaCha20

### Hash Functions

- `sha256(data: Buffer): Buffer` - SHA-256 hash (32 bytes)
- `sha512(data: Buffer): Buffer` - SHA-512 hash (64 bytes)
- `sha3_256(data: Buffer): Buffer` - SHA3-256 hash (32 bytes)
- `blake3(data: Buffer, outputLength?: number): Buffer` - BLAKE3 hash

### Digital Signatures

- `ed25519GenerateKeypair(): { publicKey, secretKey }` - Generate Ed25519 keypair
- `ed25519Sign(message: Buffer, secretKey: Buffer): Buffer` - Sign message
- `ed25519Verify(message: Buffer, signature: Buffer, publicKey: Buffer): boolean` - Verify signature

### Key Derivation

- `pbkdf2(password, salt, iterations?, keyLength?): Buffer` - PBKDF2 derivation
- `argon2id(password, salt?, memoryCost?, timeCost?, parallelism?, keyLength?): { derivedKey, salt }` - Argon2id derivation
- `hkdf(inputKeyMaterial, salt?, info?, keyLength?): Buffer` - HKDF derivation

### Random

- `randomBytes(length: number): Buffer` - Generate random bytes

## Examples

See the `examples/` directory for usage examples:

```bash
npm run build
node examples/example-basic.js
```

## Error Handling

All functions throw `ElecryptoError` on failure:

```typescript
import { ElecryptoError } from 'elecrypto';

try {
  const hash = elecrypto.sha256(data);
} catch (error) {
  if (error instanceof ElecryptoError) {
    console.error(`Crypto error: ${error.message} (code: ${error.code})`);
  }
}
```

## License

MIT License
