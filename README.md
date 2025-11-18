# Elecrypto

> **Universal Cryptographic Library for All Platforms**

Elecrypto is a high-performance, cross-platform cryptographic library designed to provide consistent, secure encryption functionality across all major programming languages and platforms.

## Features

- **Cross-Platform**: Windows, macOS, Linux, iOS, Android
- **Multi-Language**: C, Java, Python, Rust, Go, Node.js/TypeScript, Swift, Kotlin
- **Modern Algorithms**: AES-GCM, ChaCha20-Poly1305, Ed25519, Argon2, and more
- **Secure by Default**: Authenticated encryption, constant-time operations, automatic memory clearing
- **High Performance**: Written in Rust with zero-cost abstractions
- **Easy to Use**: Consistent API across all languages
- **Well Tested**: Comprehensive test suite with standard test vectors

## Supported Algorithms

### Symmetric Encryption
- AES-256-GCM (Authenticated)
- ChaCha20-Poly1305 (Authenticated)

### Asymmetric Encryption
- RSA-OAEP (2048, 3072, 4096-bit)
- ECIES (P-256, P-384)

### Hash Functions
- SHA-256, SHA-512
- SHA-3 (256, 512)
- BLAKE3

### Key Derivation
- PBKDF2
- Argon2id (Recommended for passwords)
- HKDF

### Digital Signatures
- Ed25519 (Recommended)
- ECDSA (P-256, P-384)
- RSA-PSS

### Random Number Generation
- CSPRNG (Platform-native entropy)


### Post-Quantum Cryptography (NIST Standards)

**Key Encapsulation:**
- ML-KEM (Kyber512/768/1024) - Quantum-resistant key exchange

**Digital Signatures:**
- ML-DSA (Dilithium2/3/5) - Lattice-based signatures
- FN-DSA (Falcon512/1024) - Compact signatures
- SLH-DSA (SPHINCS+) - Stateless hash-based signatures

## Quick Start

### Korean Post-Quantum Cryptography (KPQC)

**KEM (Key Encapsulation):**
- NTRU+ - NTRU 기반, 빠른 성능 ⏳
- SMAUG - 한국 독자 개발, 메모리 효율적 ⏳
- TiGER - 격자 기반, 고속 연산 ⏳
- PALOMA - 동형암호 친화적 ⏳

**Digital Signatures:**
- AIMer - 대수적 기법, 작은 서명 ⏳
- HAETAE - 격자 기반, Dilithium 개선형 ⏳
- SOLMAE (MQ-Sign) - 다변수 기반, 빠른 서명 ⏳
- GCKSign - 그룹 서명 지원 ⏳

⏳ = API 정의 완료, 구현 예정 (Rust 크레이트 대기 중)

**NIST-KPQC 공통 알고리즘:**
- Kyber, Dilithium, Falcon, SPHINCS+ (✅ 이미 구현됨)


### Python

```python
from elecrypto import aes_generate_key, aes_gcm_encrypt, aes_gcm_decrypt

# Generate key
key = aes_generate_key()

# Encrypt
plaintext = b"Secret message"
ciphertext, nonce = aes_gcm_encrypt(plaintext, key)

# Decrypt
decrypted = aes_gcm_decrypt(ciphertext, key, nonce)
print(decrypted)  # b"Secret message"
```

### Node.js/TypeScript

```typescript
import { aesGenerateKey, aesGcmEncrypt, aesGcmDecrypt } from 'elecrypto';

// Generate key
const key = aesGenerateKey();

// Encrypt
const plaintext = Buffer.from('Secret message');
const { ciphertext, nonce } = aesGcmEncrypt(plaintext, key);

// Decrypt
const decrypted = aesGcmDecrypt(ciphertext, key, nonce);
console.log(decrypted.toString()); // "Secret message"
```

### Rust

```rust
use elecrypto::{aes_generate_key, aes_gcm_encrypt, aes_gcm_decrypt};

// Generate key
let key = aes_generate_key();

// Encrypt
let plaintext = b"Secret message";
let (ciphertext, nonce) = aes_gcm_encrypt(plaintext, &key, None, None)?;

// Decrypt
let decrypted = aes_gcm_decrypt(&ciphertext, &key, &nonce, None)?;
println!("{}", String::from_utf8(decrypted)?); // "Secret message"
```

### Java/Android

```java
import com.elecrypto.*;

// Generate key
byte[] key = Elecrypto.aesGenerateKey();

// Encrypt
byte[] plaintext = "Secret message".getBytes();
EncryptResult result = Elecrypto.aesGcmEncrypt(plaintext, key);

// Decrypt
byte[] decrypted = Elecrypto.aesGcmDecrypt(
    result.ciphertext,
    key,
    result.nonce
);
System.out.println(new String(decrypted)); // "Secret message"
```

### Swift/iOS

```swift
import Elecrypto

// Generate key
let key = Elecrypto.aesGenerateKey()

// Encrypt
let plaintext = "Secret message".data(using: .utf8)!
let (ciphertext, nonce) = try Elecrypto.aesGcmEncrypt(plaintext, key: key)

// Decrypt
let decrypted = try Elecrypto.aesGcmDecrypt(ciphertext, key: key, nonce: nonce)
print(String(data: decrypted, encoding: .utf8)!) // "Secret message"
```

### Go

```go
import "github.com/elecrypto/elecrypto-go"

// Generate key
key := elecrypto.AesGenerateKey()

// Encrypt
plaintext := []byte("Secret message")
ciphertext, nonce, err := elecrypto.AesGcmEncrypt(plaintext, key, nil, nil)

// Decrypt
decrypted, err := elecrypto.AesGcmDecrypt(ciphertext, key, nonce, nil)
fmt.Println(string(decrypted)) // "Secret message"
```

## Installation

### Python (pip)
```bash
pip install elecrypto
```

### Node.js (npm)
```bash
npm install elecrypto
```

### Rust (Cargo)
```toml
[dependencies]
elecrypto = "1.0"
```

### Java (Maven)
```xml
<dependency>
    <groupId>com.elecrypto</groupId>
    <artifactId>elecrypto</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Go
```bash
go get github.com/elecrypto/elecrypto-go
```

### iOS (Swift Package Manager)
```swift
dependencies: [
    .package(url: "https://github.com/elecrypto/elecrypto-ios", from: "1.0.0")
]
```

### Android (Gradle)
```gradle
dependencies {
    implementation 'com.elecrypto:elecrypto:1.0.0'
}
```

## Documentation

- [API Specification](./API_SPEC.md) - Complete API reference
- [Architecture](./ARCHITECTURE.md) - System design and structure
- [Security](./SECURITY.md) - Security considerations and best practices
- [Examples](./docs/guides/) - Usage examples and tutorials

## Building from Source

### Prerequisites
- Rust 1.70+ (for core library)
- Python 3.8+ (for Python bindings)
- Node.js 18+ (for Node.js bindings)
- JDK 11+ (for Java bindings)
- Go 1.20+ (for Go bindings)
- Xcode 14+ (for iOS)
- Android NDK (for Android)

### Build Core Library
```bash
cd core
cargo build --release
```

### Build All Bindings
```bash
./scripts/build-all.sh
```

### Run Tests
```bash
./scripts/test-all.sh
```

## Architecture

Elecrypto uses a **Rust core** with **FFI bindings** for other languages:

```
┌─────────────────────────────────────────────┐
│         Language Bindings (Idiomatic)       │
│  Python │ Node.js │ Java │ Go │ Swift │ ... │
└─────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────┐
│            C FFI Layer (ABI-stable)         │
└─────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────┐
│        Rust Core (Implementation)           │
│  • Memory safe                              │
│  • High performance                         │
│  • Constant-time operations                 │
└─────────────────────────────────────────────┘
```

This architecture ensures:
- **Single source of truth**: Core algorithms in one place
- **Consistent behavior**: Same implementation across all languages
- **Easy maintenance**: Bug fixes and updates in one location
- **Native performance**: Zero-cost abstractions in Rust
- **Memory safety**: Rust's guarantees prevent common vulnerabilities

See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed design documentation.

## Security

Elecrypto is designed with security as the top priority:

- **Audited algorithms**: Uses well-tested cryptographic libraries
- **Constant-time operations**: Resistant to timing attacks
- **Memory safety**: Automatic zeroing of sensitive data
- **Secure defaults**: Authenticated encryption, strong parameters
- **No deprecated algorithms**: Only modern, secure algorithms

See [SECURITY.md](./SECURITY.md) for security considerations and reporting vulnerabilities.

## Roadmap

### Phase 1: Foundation (Current)
- [x] Architecture design
- [x] API specification
- [ ] Core Rust library with basic algorithms
- [ ] C FFI layer
- [ ] Test infrastructure

### Phase 2: Core Implementation
- [ ] All symmetric encryption algorithms
- [ ] Hash functions and KDFs
- [ ] Random number generation
- [ ] Comprehensive tests

### Phase 3: Asymmetric Cryptography
- [ ] RSA implementation
- [ ] ECC implementation
- [ ] Digital signatures

### Phase 4: Language Bindings
- [ ] Python bindings
- [ ] Node.js bindings
- [ ] Java bindings
- [ ] Go bindings

### Phase 5: Mobile Support
- [ ] iOS framework
- [ ] Android library

### Phase 6: v1.0 Release
- [ ] Security audit
- [ ] Performance optimization
- [ ] Complete documentation
- [ ] Release v1.0.0

## Contributing

Contributions are welcome! Please read our [Contributing Guide](./CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone repository
git clone https://github.com/elecrypto/elecrypto.git
cd elecrypto

# Build core
cd core
cargo build
cargo test

# Run all tests
cd ..
./scripts/test-all.sh
```

## License

[MIT License](./LICENSE) - See LICENSE file for details

## Support

- **Issues**: [GitHub Issues](https://github.com/elecrypto/elecrypto/issues)
- **Discussions**: [GitHub Discussions](https://github.com/elecrypto/elecrypto/discussions)
- **Security**: See [SECURITY.md](./SECURITY.md) for reporting vulnerabilities

## Acknowledgments

Elecrypto builds upon the excellent work of:
- [RustCrypto](https://github.com/RustCrypto) - Cryptographic algorithms in Rust
- [ring](https://github.com/briansmith/ring) - Safe, fast crypto using Rust
- [libsodium](https://github.com/jedisct1/libsodium) - Modern crypto library

## Status

🚧 **Currently in Development** - Not yet ready for production use

Follow development progress: [Project Board](https://github.com/elecrypto/elecrypto/projects)

---

**Note**: This library is currently in active development. APIs may change before v1.0 release.
