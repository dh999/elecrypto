# Elecrypto API Specification

## Version 1.0

This document defines the common API interface for Elecrypto across all supported languages and platforms.

## Design Principles

1. **Language Idiomatic**: Each binding follows its language conventions
2. **Consistent Naming**: Core operation names are identical across languages
3. **Secure by Default**: Uses authenticated encryption, safe parameters
4. **Clear Error Handling**: Explicit error types and messages

## API Overview

```
Elecrypto API
├── Symmetric Encryption
│   ├── AES-GCM
│   └── ChaCha20-Poly1305
├── Asymmetric Encryption
│   ├── RSA
│   └── ECIES
├── Hash Functions
│   ├── SHA-256/512
│   ├── SHA-3
│   └── BLAKE3
├── Key Derivation
│   ├── PBKDF2
│   ├── Argon2
│   └── HKDF
├── Digital Signatures
│   ├── Ed25519
│   ├── ECDSA
│   └── RSA-PSS
├── Post-Quantum Crypto (NIST)
│   ├── ML-KEM (Kyber)
│   ├── ML-DSA (Dilithium)
│   ├── FN-DSA (Falcon)
│   └── SLH-DSA (SPHINCS+)
├── Post-Quantum Crypto (KPQC)
│   ├── KEM: NTRU+, SMAUG, TiGER, PALOMA
│   └── Signatures: AIMer, HAETAE, SOLMAE, GCKSign
└── Random
    └── CSPRNG
```

---

## 1. Symmetric Encryption

### 1.1 AES-256-GCM (Authenticated Encryption)

#### Encrypt
```
Function: aes_gcm_encrypt
Input:
  - plaintext: bytes
  - key: bytes (32 bytes for AES-256)
  - nonce: bytes (12 bytes, optional - generated if not provided)
  - associated_data: bytes (optional, default: empty)
Output:
  - ciphertext: bytes (includes authentication tag)
  - nonce: bytes (12 bytes)
Errors:
  - InvalidKeyLength
  - EncryptionFailed
```

#### Decrypt
```
Function: aes_gcm_decrypt
Input:
  - ciphertext: bytes (includes authentication tag)
  - key: bytes (32 bytes)
  - nonce: bytes (12 bytes)
  - associated_data: bytes (optional, default: empty)
Output:
  - plaintext: bytes
Errors:
  - InvalidKeyLength
  - InvalidNonceLength
  - AuthenticationFailed
  - DecryptionFailed
```

#### Generate Key
```
Function: aes_generate_key
Input: (none)
Output:
  - key: bytes (32 bytes)
```

### 1.2 ChaCha20-Poly1305

#### Encrypt
```
Function: chacha20_poly1305_encrypt
Input:
  - plaintext: bytes
  - key: bytes (32 bytes)
  - nonce: bytes (12 bytes, optional - generated if not provided)
  - associated_data: bytes (optional)
Output:
  - ciphertext: bytes (includes authentication tag)
  - nonce: bytes (12 bytes)
Errors:
  - InvalidKeyLength
  - EncryptionFailed
```

#### Decrypt
```
Function: chacha20_poly1305_decrypt
Input:
  - ciphertext: bytes (includes authentication tag)
  - key: bytes (32 bytes)
  - nonce: bytes (12 bytes)
  - associated_data: bytes (optional)
Output:
  - plaintext: bytes
Errors:
  - InvalidKeyLength
  - InvalidNonceLength
  - AuthenticationFailed
  - DecryptionFailed
```

#### Generate Key
```
Function: chacha20_generate_key
Input: (none)
Output:
  - key: bytes (32 bytes)
```

---

## 2. Hash Functions

### 2.1 SHA-256
```
Function: sha256
Input:
  - data: bytes
Output:
  - hash: bytes (32 bytes)
```

### 2.2 SHA-512
```
Function: sha512
Input:
  - data: bytes
Output:
  - hash: bytes (64 bytes)
```

### 2.3 SHA3-256
```
Function: sha3_256
Input:
  - data: bytes
Output:
  - hash: bytes (32 bytes)
```

### 2.4 BLAKE3
```
Function: blake3
Input:
  - data: bytes
  - output_length: integer (optional, default: 32)
Output:
  - hash: bytes (output_length bytes)
```

---

## 3. Key Derivation Functions (KDF)

### 3.1 PBKDF2
```
Function: pbkdf2
Input:
  - password: bytes
  - salt: bytes (optional - generated if not provided)
  - iterations: integer (default: 600000)
  - key_length: integer (default: 32)
  - hash_algorithm: string (default: "sha256")
Output:
  - derived_key: bytes (key_length bytes)
  - salt: bytes
Errors:
  - InvalidIterations
  - InvalidKeyLength
  - UnsupportedHashAlgorithm
```

### 3.2 Argon2id (Recommended for passwords)
```
Function: argon2id
Input:
  - password: bytes
  - salt: bytes (optional - 16 bytes generated if not provided)
  - memory_cost: integer (default: 65536 KiB = 64 MB)
  - time_cost: integer (default: 3 iterations)
  - parallelism: integer (default: 4 threads)
  - key_length: integer (default: 32)
Output:
  - derived_key: bytes (key_length bytes)
  - salt: bytes (16 bytes)
Errors:
  - InvalidParameters
  - InsufficientMemory
```

### 3.3 HKDF (HMAC-based Key Derivation)
```
Function: hkdf
Input:
  - input_key_material: bytes
  - salt: bytes (optional)
  - info: bytes (optional)
  - key_length: integer (default: 32)
  - hash_algorithm: string (default: "sha256")
Output:
  - derived_key: bytes (key_length bytes)
Errors:
  - InvalidKeyLength
  - UnsupportedHashAlgorithm
```

---

## 4. Asymmetric Encryption

### 4.1 RSA

#### Generate Key Pair
```
Function: rsa_generate_keypair
Input:
  - key_size: integer (2048, 3072, or 4096)
Output:
  - public_key: bytes (DER or PEM format)
  - private_key: bytes (DER or PEM format)
Errors:
  - InvalidKeySize
  - KeyGenerationFailed
```

#### Encrypt (RSA-OAEP)
```
Function: rsa_encrypt
Input:
  - plaintext: bytes
  - public_key: bytes
  - hash_algorithm: string (default: "sha256")
Output:
  - ciphertext: bytes
Errors:
  - InvalidPublicKey
  - PlaintextTooLarge
  - EncryptionFailed
```

#### Decrypt (RSA-OAEP)
```
Function: rsa_decrypt
Input:
  - ciphertext: bytes
  - private_key: bytes
  - hash_algorithm: string (default: "sha256")
Output:
  - plaintext: bytes
Errors:
  - InvalidPrivateKey
  - DecryptionFailed
```

### 4.2 ECIES (Elliptic Curve Integrated Encryption Scheme)

#### Generate Key Pair
```
Function: ecies_generate_keypair
Input:
  - curve: string ("p256" or "p384")
Output:
  - public_key: bytes
  - private_key: bytes
Errors:
  - UnsupportedCurve
  - KeyGenerationFailed
```

#### Encrypt
```
Function: ecies_encrypt
Input:
  - plaintext: bytes
  - public_key: bytes
Output:
  - ciphertext: bytes
Errors:
  - InvalidPublicKey
  - EncryptionFailed
```

#### Decrypt
```
Function: ecies_decrypt
Input:
  - ciphertext: bytes
  - private_key: bytes
Output:
  - plaintext: bytes
Errors:
  - InvalidPrivateKey
  - DecryptionFailed
```

---

## 5. Digital Signatures

### 5.1 Ed25519 (Recommended)

#### Generate Key Pair
```
Function: ed25519_generate_keypair
Input: (none)
Output:
  - public_key: bytes (32 bytes)
  - private_key: bytes (64 bytes)
```

#### Sign
```
Function: ed25519_sign
Input:
  - message: bytes
  - private_key: bytes (64 bytes)
Output:
  - signature: bytes (64 bytes)
Errors:
  - InvalidPrivateKey
  - SigningFailed
```

#### Verify
```
Function: ed25519_verify
Input:
  - message: bytes
  - signature: bytes (64 bytes)
  - public_key: bytes (32 bytes)
Output:
  - valid: boolean
Errors:
  - InvalidPublicKey
  - InvalidSignature
```

### 5.2 ECDSA

#### Generate Key Pair
```
Function: ecdsa_generate_keypair
Input:
  - curve: string ("p256" or "p384")
Output:
  - public_key: bytes
  - private_key: bytes
Errors:
  - UnsupportedCurve
  - KeyGenerationFailed
```

#### Sign
```
Function: ecdsa_sign
Input:
  - message: bytes
  - private_key: bytes
  - hash_algorithm: string (default: "sha256")
Output:
  - signature: bytes
Errors:
  - InvalidPrivateKey
  - SigningFailed
```

#### Verify
```
Function: ecdsa_verify
Input:
  - message: bytes
  - signature: bytes
  - public_key: bytes
  - hash_algorithm: string (default: "sha256")
Output:
  - valid: boolean
Errors:
  - InvalidPublicKey
  - InvalidSignature
```

### 5.3 RSA-PSS

#### Sign
```
Function: rsa_pss_sign
Input:
  - message: bytes
  - private_key: bytes
  - hash_algorithm: string (default: "sha256")
Output:
  - signature: bytes
Errors:
  - InvalidPrivateKey
  - SigningFailed
```

#### Verify
```
Function: rsa_pss_verify
Input:
  - message: bytes
  - signature: bytes
  - public_key: bytes
  - hash_algorithm: string (default: "sha256")
Output:
  - valid: boolean
Errors:
  - InvalidPublicKey
  - InvalidSignature
```

---

## 6. Random Number Generation

### 6.1 Generate Random Bytes
```
Function: random_bytes
Input:
  - length: integer
Output:
  - random_data: bytes (length bytes)
Errors:
  - InvalidLength
  - InsufficientEntropy
```

---
## 7. Post-Quantum Cryptography (PQC)

### Overview

Post-quantum cryptographic algorithms standardized by NIST to resist quantum computer attacks.

**NIST Standard Names:**
- ML-KEM (Kyber): Module-Lattice-Based Key-Encapsulation Mechanism
- ML-DSA (Dilithium): Module-Lattice-Based Digital Signature Algorithm
- FN-DSA (Falcon): Fast Fourier Transform over NTRU-Lattice Digital Signature Algorithm
- SLH-DSA (SPHINCS+): Stateless Hash-Based Digital Signature Algorithm

### 7.1 ML-KEM (Kyber) - Key Encapsulation

#### 7.1.1 Generate Kyber Keypair

```
Function: kyber512_keypair / kyber768_keypair / kyber1024_keypair
Input: (none)
Output:
  - public_key: bytes (Kyber512: 800, Kyber768: 1184, Kyber1024: 1568)
  - secret_key: bytes (Kyber512: 1632, Kyber768: 2400, Kyber1024: 3168)
Errors:
  - KeyGenerationFailed
```

**Security Levels:**
- Kyber512: NIST Level 1 (~AES-128)
- Kyber768: NIST Level 3 (~AES-192) - **Recommended**
- Kyber1024: NIST Level 5 (~AES-256)

#### 7.1.2 Encapsulate (Create Shared Secret)

```
Function: kyber512_encapsulate / kyber768_encapsulate / kyber1024_encapsulate
Input:
  - public_key: bytes
Output:
  - ciphertext: bytes (Kyber512: 768, Kyber768: 1088, Kyber1024: 1568)
  - shared_secret: bytes (32 bytes for all variants)
Errors:
  - InvalidPublicKey
  - EncryptionFailed
```

#### 7.1.3 Decapsulate (Recover Shared Secret)

```
Function: kyber512_decapsulate / kyber768_decapsulate / kyber1024_decapsulate
Input:
  - ciphertext: bytes
  - secret_key: bytes
Output:
  - shared_secret: bytes (32 bytes)
Errors:
  - InvalidPrivateKey
  - InvalidInput
  - DecryptionFailed
```

### 7.2 ML-DSA (Dilithium) - Digital Signatures

#### 7.2.1 Generate Dilithium Keypair

```
Function: dilithium2_keypair / dilithium3_keypair / dilithium5_keypair
Input: (none)
Output:
  - public_key: bytes (Dilithium2: 1312, Dilithium3: 1952, Dilithium5: 2592)
  - secret_key: bytes (Dilithium2: 2528, Dilithium3: 4000, Dilithium5: 4864)
Errors:
  - KeyGenerationFailed
```

**Security Levels:**
- Dilithium2: NIST Level 2 (~AES-128)
- Dilithium3: NIST Level 3 (~AES-192) - **Recommended**
- Dilithium5: NIST Level 5 (~AES-256)

#### 7.2.2 Sign Message

```
Function: dilithium2_sign / dilithium3_sign / dilithium5_sign
Input:
  - message: bytes
  - secret_key: bytes
Output:
  - signature: bytes (includes message + signature)
Errors:
  - InvalidPrivateKey
  - SigningFailed
```

#### 7.2.3 Verify Signature

```
Function: dilithium2_verify / dilithium3_verify / dilithium5_verify
Input:
  - message: bytes
  - signature: bytes
  - public_key: bytes
Output:
  - valid: boolean
Errors:
  - InvalidPublicKey
  - InvalidSignature
```

### 7.3 FN-DSA (Falcon) - Compact Signatures

#### 7.3.1 Generate Falcon Keypair

```
Function: falcon512_keypair / falcon1024_keypair
Input: (none)
Output:
  - public_key: bytes (Falcon512: 897, Falcon1024: 1793)
  - secret_key: bytes (Falcon512: 1281, Falcon1024: 2305)
Errors:
  - KeyGenerationFailed
```

**Features:**
- **Smallest signatures** among NIST PQC algorithms
- Fast verification
- Falcon512: NIST Level 1
- Falcon1024: NIST Level 5

#### 7.3.2 Sign Message

```
Function: falcon512_sign / falcon1024_sign
Input:
  - message: bytes
  - secret_key: bytes
Output:
  - signature: bytes (compact size!)
Errors:
  - InvalidPrivateKey
  - SigningFailed
```

#### 7.3.3 Verify Signature

```
Function: falcon512_verify / falcon1024_verify
Input:
  - message: bytes
  - signature: bytes
  - public_key: bytes
Output:
  - valid: boolean
Errors:
  - InvalidPublicKey
  - InvalidSignature
```

### 7.4 SLH-DSA (SPHINCS+) - Hash-Based Signatures

#### 7.4.1 Generate SPHINCS+ Keypair

```
Function: sphincsplus_shake_128f_keypair / sphincsplus_shake_256f_keypair
Input: (none)
Output:
  - public_key: bytes
  - secret_key: bytes
Errors:
  - KeyGenerationFailed
```

**Features:**
- **Stateless** (no state to manage)
- Based only on hash functions (conservative security)
- SHAKE-128f: NIST Level 1, fast variant
- SHAKE-256f: NIST Level 5, fast variant

#### 7.4.2 Sign Message

```
Function: sphincsplus_shake_128f_sign / sphincsplus_shake_256f_sign
Input:
  - message: bytes
  - secret_key: bytes
Output:
  - signature: bytes
Errors:
  - InvalidPrivateKey
  - SigningFailed
```

#### 7.4.3 Verify Signature

```
Function: sphincsplus_shake_128f_verify / sphincsplus_shake_256f_verify
Input:
  - message: bytes
  - signature: bytes
  - public_key: bytes
Output:
  - valid: boolean
Errors:
  - InvalidPublicKey
  - InvalidSignature
```

---

## 8. Korean Post-Quantum Cryptography (KPQC)

### Overview

Korean post-quantum cryptographic algorithms standardized by KISA (Korea Internet & Security Agency) and NSR (National Security Research Institute).

**Status**: API defined, implementations pending stable Rust crates.

**KPQC Standards:**
- NTRU+, SMAUG, TiGER, PALOMA: Key Encapsulation Mechanisms
- AIMer, HAETAE, SOLMAE, GCKSign: Digital Signature Algorithms

### 8.1 NTRU+ - Key Encapsulation (NTRU-based)

#### 8.1.1 Generate NTRU+ Keypair

```
Function: ntruplus_keypair
Input: (none)
Output:
  - public_key: bytes
  - secret_key: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - KeyGenerationFailed
```

**Features:**
- Fast performance
- Based on NTRU lattice problems
- Optimized for Korean standards

#### 8.1.2 Encapsulate (Create Shared Secret)

```
Function: ntruplus_encapsulate
Input:
  - public_key: bytes
Output:
  - ciphertext: bytes
  - shared_secret: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPublicKey
  - EncryptionFailed
```

#### 8.1.3 Decapsulate (Recover Shared Secret)

```
Function: ntruplus_decapsulate
Input:
  - ciphertext: bytes
  - secret_key: bytes
Output:
  - shared_secret: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPrivateKey
  - DecryptionFailed
```

### 8.2 SMAUG - Key Encapsulation (Korean Indigenous)

#### 8.2.1 Generate SMAUG Keypair

```
Function: smaug_keypair
Input: (none)
Output:
  - public_key: bytes
  - secret_key: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - KeyGenerationFailed
```

**Features:**
- Memory efficient design
- Korean indigenous development
- Optimized for resource-constrained environments

#### 8.2.2 Encapsulate

```
Function: smaug_encapsulate
Input:
  - public_key: bytes
Output:
  - ciphertext: bytes
  - shared_secret: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPublicKey
  - EncryptionFailed
```

#### 8.2.3 Decapsulate

```
Function: smaug_decapsulate
Input:
  - ciphertext: bytes
  - secret_key: bytes
Output:
  - shared_secret: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPrivateKey
  - DecryptionFailed
```

### 8.3 TiGER - Key Encapsulation (High-Performance Lattice)

#### 8.3.1 Generate TiGER Keypair

```
Function: tiger_keypair
Input: (none)
Output:
  - public_key: bytes
  - secret_key: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - KeyGenerationFailed
```

**Features:**
- Lattice-based design
- High-speed operations
- Optimized for modern processors

#### 8.3.2 Encapsulate

```
Function: tiger_encapsulate
Input:
  - public_key: bytes
Output:
  - ciphertext: bytes
  - shared_secret: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPublicKey
  - EncryptionFailed
```

#### 8.3.3 Decapsulate

```
Function: tiger_decapsulate
Input:
  - ciphertext: bytes
  - secret_key: bytes
Output:
  - shared_secret: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPrivateKey
  - DecryptionFailed
```

### 8.4 PALOMA - Key Encapsulation (FHE-Friendly)

#### 8.4.1 Generate PALOMA Keypair

```
Function: paloma_keypair
Input: (none)
Output:
  - public_key: bytes
  - secret_key: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - KeyGenerationFailed
```

**Features:**
- Homomorphic encryption friendly
- Designed for privacy-preserving applications
- Supports advanced cryptographic protocols

#### 8.4.2 Encapsulate

```
Function: paloma_encapsulate
Input:
  - public_key: bytes
Output:
  - ciphertext: bytes
  - shared_secret: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPublicKey
  - EncryptionFailed
```

#### 8.4.3 Decapsulate

```
Function: paloma_decapsulate
Input:
  - ciphertext: bytes
  - secret_key: bytes
Output:
  - shared_secret: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPrivateKey
  - DecryptionFailed
```

### 8.5 AIMer - Digital Signatures (Algebraic)

#### 8.5.1 Generate AIMer Keypair

```
Function: aimer_keypair
Input: (none)
Output:
  - public_key: bytes
  - secret_key: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - KeyGenerationFailed
```

**Features:**
- Algebraic techniques
- Compact signature size
- Fast verification

#### 8.5.2 Sign Message

```
Function: aimer_sign
Input:
  - message: bytes
  - secret_key: bytes
Output:
  - signature: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPrivateKey
  - SigningFailed
```

#### 8.5.3 Verify Signature

```
Function: aimer_verify
Input:
  - message: bytes
  - signature: bytes
  - public_key: bytes
Output:
  - valid: boolean
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPublicKey
  - InvalidSignature
```

### 8.6 HAETAE - Digital Signatures (Dilithium Variant)

#### 8.6.1 Generate HAETAE Keypair

```
Function: haetae_keypair
Input: (none)
Output:
  - public_key: bytes
  - secret_key: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - KeyGenerationFailed
```

**Features:**
- Lattice-based design
- Improved variant of Dilithium
- Enhanced performance characteristics

#### 8.6.2 Sign Message

```
Function: haetae_sign
Input:
  - message: bytes
  - secret_key: bytes
Output:
  - signature: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPrivateKey
  - SigningFailed
```

#### 8.6.3 Verify Signature

```
Function: haetae_verify
Input:
  - message: bytes
  - signature: bytes
  - public_key: bytes
Output:
  - valid: boolean
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPublicKey
  - InvalidSignature
```

### 8.7 SOLMAE (MQ-Sign) - Digital Signatures (Multivariate)

#### 8.7.1 Generate SOLMAE Keypair

```
Function: solmae_keypair
Input: (none)
Output:
  - public_key: bytes
  - secret_key: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - KeyGenerationFailed
```

**Features:**
- Multivariate quadratic equations
- Fast signing operations
- Compact implementation

#### 8.7.2 Sign Message

```
Function: solmae_sign
Input:
  - message: bytes
  - secret_key: bytes
Output:
  - signature: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPrivateKey
  - SigningFailed
```

#### 8.7.3 Verify Signature

```
Function: solmae_verify
Input:
  - message: bytes
  - signature: bytes
  - public_key: bytes
Output:
  - valid: boolean
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPublicKey
  - InvalidSignature
```

### 8.8 GCKSign - Digital Signatures (Group Signatures)

#### 8.8.1 Generate GCKSign Keypair

```
Function: gcksign_keypair
Input: (none)
Output:
  - public_key: bytes
  - secret_key: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - KeyGenerationFailed
```

**Features:**
- Group signature support
- Privacy-preserving signatures
- Advanced cryptographic protocols

#### 8.8.2 Sign Message

```
Function: gcksign_sign
Input:
  - message: bytes
  - secret_key: bytes
Output:
  - signature: bytes
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPrivateKey
  - SigningFailed
```

#### 8.8.3 Verify Signature

```
Function: gcksign_verify
Input:
  - message: bytes
  - signature: bytes
  - public_key: bytes
Output:
  - valid: boolean
Errors:
  - UnsupportedAlgorithm (pending implementation)
  - InvalidPublicKey
  - InvalidSignature
```

---

## Error Handling

### Error Types

All functions may return one of the following error categories:

| Error Code | Description |
|-----------|-------------|
| `InvalidInput` | Invalid input parameters |
| `InvalidKeyLength` | Key length does not match requirements |
| `InvalidNonceLength` | Nonce length does not match requirements |
| `AuthenticationFailed` | Message authentication failed |
| `EncryptionFailed` | Encryption operation failed |
| `DecryptionFailed` | Decryption operation failed |
| `KeyGenerationFailed` | Key pair generation failed |
| `SigningFailed` | Signature generation failed |
| `VerificationFailed` | Signature verification computation failed |
| `UnsupportedAlgorithm` | Algorithm not supported |
| `InsufficientEntropy` | Not enough entropy available |
| `InternalError` | Internal library error |

### Error Handling by Language

**Rust**: `Result<T, ElecryptoError>`

**Python**: Exceptions (`ElecryptoError` base class)

**Java/Kotlin**: Exceptions (`ElecryptoException` base class)

**Go**: Multiple return values `(result, error)`

**Node.js/TypeScript**: Exceptions (Error objects) or Promise rejections

**Swift**: `throws` / `Result<T, ElecryptoError>`

**C**: Error codes (negative integers) with `errno`-style interface

---

## Usage Examples (Pseudo-code)

### Example 1: Encrypt and Decrypt with AES-GCM

```python
# Python example
from elecrypto import aes_generate_key, aes_gcm_encrypt, aes_gcm_decrypt

# Generate a key
key = aes_generate_key()

# Encrypt
plaintext = b"Hello, World!"
ciphertext, nonce = aes_gcm_encrypt(plaintext, key)

# Decrypt
decrypted = aes_gcm_decrypt(ciphertext, key, nonce)
assert decrypted == plaintext
```

### Example 2: Password Hashing with Argon2

```javascript
// JavaScript/TypeScript example
import { argon2id } from 'elecrypto';

// Hash password
const password = Buffer.from('my_secure_password');
const { derivedKey, salt } = argon2id(password);

// Store derivedKey and salt in database
// Later, verify by deriving key again with same salt
const { derivedKey: checkKey } = argon2id(password, salt);
// Compare derivedKey === checkKey
```

### Example 3: Digital Signature with Ed25519

```rust
// Rust example
use elecrypto::{ed25519_generate_keypair, ed25519_sign, ed25519_verify};

// Generate keypair
let (public_key, private_key) = ed25519_generate_keypair();

// Sign message
let message = b"Important message";
let signature = ed25519_sign(message, &private_key)?;

// Verify signature
let valid = ed25519_verify(message, &signature, &public_key)?;
assert!(valid);
```

### Example 4: RSA Encryption

```java
// Java example
import com.elecrypto.*;

// Generate RSA keypair
RsaKeyPair keyPair = Elecrypto.rsaGenerateKeypair(2048);

// Encrypt
byte[] plaintext = "Secret data".getBytes();
byte[] ciphertext = Elecrypto.rsaEncrypt(plaintext, keyPair.publicKey);

// Decrypt
byte[] decrypted = Elecrypto.rsaDecrypt(ciphertext, keyPair.privateKey);
```

---

## Language-Specific Adaptations

### Python
- Use `bytes` for all binary data
- Return tuples for multiple outputs: `(ciphertext, nonce)`
- Raise exceptions for errors
- Follow PEP 8 naming: `aes_gcm_encrypt`

### Java/Kotlin
- Use `byte[]` for binary data
- Return objects for multiple outputs: `EncryptResult` class
- Throw checked exceptions
- CamelCase methods: `aesGcmEncrypt`

### Go
- Use `[]byte` for binary data
- Multiple return values: `(ciphertext, nonce, error)`
- Return `error` interface
- Lowercase packages, exported PascalCase: `AesGcmEncrypt`

### Node.js/TypeScript
- Use `Buffer` for binary data
- Return objects: `{ ciphertext: Buffer, nonce: Buffer }`
- Throw Error objects
- CamelCase: `aesGcmEncrypt`
- TypeScript type definitions included

### Swift
- Use `Data` for binary data
- Return tuples or structs
- Use `throws` for errors
- CamelCase: `aesGcmEncrypt`

### Rust
- Use `&[u8]` for input, `Vec<u8>` for output
- Return `Result<T, ElecryptoError>`
- Snake_case: `aes_gcm_encrypt`

### C
- Use `unsigned char*` and `size_t`
- Out-parameters for outputs
- Return error codes (0 = success, negative = error)
- Snake_case: `elecrypto_aes_gcm_encrypt`
- Caller manages memory allocation

---

## Versioning

Elecrypto follows Semantic Versioning (SemVer):
- MAJOR: Incompatible API changes
- MINOR: Backwards-compatible functionality additions
- PATCH: Backwards-compatible bug fixes

---

## Security Notes

1. **Key Management**: Never hardcode keys in source code
2. **Nonce Reuse**: Never reuse a nonce with the same key (for AES-GCM, ChaCha20)
3. **Random Number Generation**: Always use `random_bytes()` for keys, nonces, salts
4. **Authenticated Encryption**: Prefer AES-GCM or ChaCha20-Poly1305 over unauthenticated modes
5. **Password Hashing**: Use Argon2id with appropriate parameters, not plain hashes
6. **Constant Time**: Library uses constant-time comparisons to prevent timing attacks
7. **Memory Clearing**: Sensitive data is automatically zeroed after use

---

## Future Considerations

Potential additions for future versions:
- X25519 key exchange
- AES-SIV (nonce-misuse resistant)
- Post-quantum algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium)
- Hardware security module (HSM) support
- Streaming encryption APIs
