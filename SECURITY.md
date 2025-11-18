# Security Policy

## Reporting Security Vulnerabilities

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead, please report them via email to: **security@elecrypto.org**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information:
- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Considerations

### Cryptographic Principles

Elecrypto follows these security principles:

1. **Use Well-Established Algorithms**
   - Only NIST-approved and widely peer-reviewed algorithms
   - No custom or proprietary cryptography
   - Regular updates to follow current best practices

2. **Secure by Default**
   - Authenticated encryption preferred (AES-GCM, ChaCha20-Poly1305)
   - Strong default parameters (256-bit keys, sufficient iterations)
   - Automatic nonce generation to prevent reuse

3. **Defense in Depth**
   - Constant-time operations to prevent timing attacks
   - Memory cleared after use to prevent data leakage
   - Input validation to prevent injection attacks
   - Safe error handling without leaking sensitive information

### Best Practices for Users

#### 1. Key Management

**DO:**
- Generate keys using `random_bytes()` or algorithm-specific key generation functions
- Store keys securely (OS keychain, HSM, or secure enclave)
- Use key derivation functions (KDF) for passwords
- Rotate keys periodically
- Use different keys for different purposes

**DON'T:**
- Hardcode keys in source code
- Store keys in plain text files
- Reuse keys across different applications
- Derive keys from weak passwords without proper KDF
- Store keys in version control systems

```python
# BAD - Never do this
KEY = bytes.fromhex("0123456789abcdef...")

# GOOD - Generate fresh keys
from elecrypto import aes_generate_key
key = aes_generate_key()
# Store 'key' securely using OS keychain
```

#### 2. Nonce/IV Management

**Critical**: Never reuse a nonce with the same key for AES-GCM or ChaCha20-Poly1305!

**DO:**
- Let the library generate nonces automatically
- Store nonces alongside ciphertext (they're not secret)
- Use a counter-based approach for sequential encryption
- Track nonce usage to prevent reuse

**DON'T:**
- Reuse nonces with the same key
- Use predictable nonces (e.g., all zeros)
- Encrypt more than 2^32 messages with AES-GCM and same key

```python
# GOOD - Let library generate nonce
ciphertext, nonce = aes_gcm_encrypt(plaintext, key)
# Store both ciphertext and nonce

# GOOD - Decrypt with stored nonce
plaintext = aes_gcm_decrypt(ciphertext, key, nonce)
```

#### 3. Password Hashing

**DO:**
- Use Argon2id for password hashing (preferred)
- Use PBKDF2 as fallback for compatibility
- Use high iteration counts (Argon2: 3+ iterations, PBKDF2: 600,000+)
- Generate unique salts per password
- Store salt alongside hash

**DON'T:**
- Use plain hash functions (SHA-256, etc.) for passwords
- Reuse salts across passwords
- Use low iteration counts
- Use encryption instead of hashing for passwords

```python
# GOOD - Password hashing with Argon2
from elecrypto import argon2id

password = b"user_password"
derived_key, salt = argon2id(password)
# Store derived_key and salt in database

# Later, verify password
check_key, _ = argon2id(password, salt)  # Use same salt
if check_key == derived_key:
    print("Password correct")
```

#### 4. Authenticated Encryption

**DO:**
- Use AES-GCM or ChaCha20-Poly1305 for encryption
- Include associated data (AAD) for context binding
- Verify authentication before processing decrypted data

**DON'T:**
- Use unauthenticated modes (ECB, CBC without MAC)
- Process decrypted data before authentication check
- Ignore authentication failures

```python
# GOOD - Authenticated encryption with AAD
from elecrypto import aes_gcm_encrypt, aes_gcm_decrypt

# Encrypt with context
associated_data = b"user_id:12345"
ciphertext, nonce = aes_gcm_encrypt(
    plaintext,
    key,
    associated_data=associated_data
)

# Decrypt - will fail if AAD doesn't match
try:
    plaintext = aes_gcm_decrypt(
        ciphertext,
        key,
        nonce,
        associated_data=associated_data
    )
except AuthenticationError:
    print("Authentication failed - data tampered!")
```

#### 5. Random Number Generation

**DO:**
- Use `random_bytes()` for all cryptographic random needs
- Generate keys, nonces, salts with cryptographic RNG
- Ensure sufficient entropy on system

**DON'T:**
- Use language built-in random (e.g., Python's `random` module)
- Use timestamp or sequential values as "random"
- Seed cryptographic RNG with predictable values

```python
# BAD - Not cryptographically secure
import random
key = bytes([random.randint(0, 255) for _ in range(32)])

# GOOD - Cryptographically secure
from elecrypto import random_bytes
key = random_bytes(32)
```

#### 6. Error Handling

**DO:**
- Handle errors appropriately
- Log errors for debugging (without sensitive data)
- Fail securely (deny access on error)

**DON'T:**
- Ignore errors
- Log sensitive data (keys, plaintexts)
- Reveal detailed error messages to end users
- Continue execution after authentication failure

```python
# GOOD - Proper error handling
try:
    plaintext = aes_gcm_decrypt(ciphertext, key, nonce)
except AuthenticationError:
    logging.warning("Authentication failed for user")
    return None  # Fail securely
except ElecryptoError as e:
    logging.error(f"Decryption error: {type(e).__name__}")
    return None
```

### Known Limitations

1. **Message Size Limits**
   - AES-GCM: Max 64 GB per message (2^36 - 32 bytes)
   - RSA: Max plaintext = (key_size / 8) - hash_size - 2
   - Recommended: Use hybrid encryption for large data

2. **Performance Considerations**
   - Argon2: High memory usage by design (security feature)
   - RSA: Slower than symmetric encryption
   - PBKDF2: High iteration count increases time (security feature)

3. **Platform Entropy**
   - Requires OS-level entropy source
   - May block on systems with insufficient entropy
   - Ensure `/dev/urandom` (Linux) or equivalent is available

### Side-Channel Protection

Elecrypto implements several protections against side-channel attacks:

1. **Timing Attacks**
   - Constant-time comparisons for authentication tags
   - Constant-time operations in cryptographic primitives
   - No branching on secret data

2. **Memory Attacks**
   - Automatic zeroing of sensitive data
   - No sensitive data in log messages or error strings
   - Minimal time in memory for sensitive data

3. **Cache Attacks**
   - Cache-resistant implementations where possible
   - Table-free implementations for critical operations

### Compliance and Standards

Elecrypto aims to comply with:
- **FIPS 140-2/140-3**: Using approved algorithms
- **NIST SP 800-38D**: AES-GCM specification
- **NIST SP 800-90A**: Random number generation
- **RFC 5869**: HKDF specification
- **RFC 7539**: ChaCha20-Poly1305
- **RFC 8032**: Ed25519 signatures

### Security Audits

| Version | Audit Date | Auditor | Status |
|---------|-----------|---------|--------|
| v1.0 | TBD | TBD | Planned |

Audit reports will be published in the `docs/security/` directory.

### Vulnerability Disclosure Timeline

When a security vulnerability is reported:

1. **Day 0**: Vulnerability reported
2. **Day 1-2**: Acknowledge receipt
3. **Day 3-7**: Verify and assess severity
4. **Day 7-30**: Develop and test fix
5. **Day 30**: Coordinate disclosure with reporter
6. **Day 30-90**: Release patched version
7. **Day 90**: Public disclosure (if not already public)

Critical vulnerabilities may have accelerated timeline.

### Security Updates

Security updates are released as:
- **Critical**: Immediate patch release (v1.0.x)
- **High**: Next patch release (within 1 week)
- **Medium**: Next minor release (within 1 month)
- **Low**: Next major release

### Deprecated Features

These features are deprecated and will be removed:

- None currently (v1.0 in development)

### Algorithm Lifecycle

| Algorithm | Status | Notes |
|-----------|--------|-------|
| AES-256-GCM | Active | Recommended |
| ChaCha20-Poly1305 | Active | Recommended |
| Ed25519 | Active | Recommended for signatures |
| Argon2id | Active | Recommended for passwords |
| SHA-256 | Active | For hashing only, not passwords |
| RSA-2048 | Active | Minimum 2048-bit |
| PBKDF2 | Active | Legacy support, prefer Argon2 |

### Security Checklist for Developers

Before deploying applications using Elecrypto:

- [ ] Keys are generated using cryptographic RNG
- [ ] Keys are stored securely (not in source code)
- [ ] Nonces are never reused with the same key
- [ ] Using authenticated encryption (AES-GCM or ChaCha20-Poly1305)
- [ ] Passwords are hashed with Argon2id or PBKDF2 (high iterations)
- [ ] Error handling doesn't leak sensitive information
- [ ] Latest version of Elecrypto is used
- [ ] Security updates are monitored and applied promptly
- [ ] Sensitive data is not logged
- [ ] Input validation is performed
- [ ] TLS/HTTPS is used for network communication
- [ ] Regular security testing is performed

### Resources

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [Latacora Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html)

### Contact

Security Team: security@elecrypto.org

---

**Note**: This security policy is updated regularly. Last update: 2025-11-18
