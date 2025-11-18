# Elecrypto Python Bindings

Python bindings for the Elecrypto cryptographic library.

## Features

- **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Hash Functions**: SHA-256, SHA-512, SHA3-256, BLAKE3
- **Digital Signatures**: Ed25519
- **Key Derivation**: PBKDF2, Argon2id, HKDF
- **Random Number Generation**: CSPRNG

## Installation

### From Source

1. First, build the Rust core library:
```bash
cd ../../core
cargo build --release
```

2. Install the Python package:
```bash
cd ../bindings/python
pip install -e .
```

### Requirements

- Python 3.7+
- Rust compiled elecrypto-core library

## Usage

### Hash Functions

```python
import elecrypto

message = b"Hello, World!"
hash = elecrypto.sha256(message)
print(hash.hex())
```

### Encryption (AES-256-GCM)

```python
import elecrypto

# Generate a key
key = elecrypto.aes_generate_key()

# Encrypt
plaintext = b"Secret message"
ciphertext, nonce = elecrypto.aes_gcm_encrypt(plaintext, key)

# Decrypt
decrypted = elecrypto.aes_gcm_decrypt(ciphertext, key, nonce)
assert decrypted == plaintext
```

### Digital Signatures (Ed25519)

```python
import elecrypto

# Generate keypair
public_key, secret_key = elecrypto.ed25519_generate_keypair()

# Sign message
message = b"Important document"
signature = elecrypto.ed25519_sign(message, secret_key)

# Verify signature
is_valid = elecrypto.ed25519_verify(message, signature, public_key)
print(f"Signature valid: {is_valid}")
```

### Password Hashing (Argon2id)

```python
import elecrypto

password = b"user_password"
derived_key, salt = elecrypto.argon2id(
    password,
    memory_cost=65536,  # 64 MB
    time_cost=3,
    parallelism=4
)

# Store derived_key and salt in database
```

## Examples

See the `examples/` directory for more usage examples:

```bash
python examples/example_basic.py
```

## API Reference

### Symmetric Encryption

- `aes_generate_key()` → bytes (32 bytes)
- `aes_gcm_encrypt(plaintext, key, nonce=None)` → (ciphertext, nonce)
- `aes_gcm_decrypt(ciphertext, key, nonce)` → plaintext
- `chacha20_generate_key()` → bytes (32 bytes)
- `chacha20_poly1305_encrypt(plaintext, key, nonce=None)` → (ciphertext, nonce)
- `chacha20_poly1305_decrypt(ciphertext, key, nonce)` → plaintext

### Hash Functions

- `sha256(data)` → bytes (32 bytes)
- `sha512(data)` → bytes (64 bytes)
- `sha3_256(data)` → bytes (32 bytes)
- `blake3(data, output_length=32)` → bytes

### Digital Signatures

- `ed25519_generate_keypair()` → (public_key, secret_key)
- `ed25519_sign(message, secret_key)` → signature
- `ed25519_verify(message, signature, public_key)` → bool

### Key Derivation

- `pbkdf2(password, salt, iterations=600000, key_length=32)` → derived_key
- `argon2id(password, salt=None, memory_cost=65536, time_cost=3, parallelism=4, key_length=32)` → (derived_key, salt)
- `hkdf(input_key_material, salt=None, info=None, key_length=32)` → derived_key

### Random

- `random_bytes(length)` → bytes

## License

MIT License
