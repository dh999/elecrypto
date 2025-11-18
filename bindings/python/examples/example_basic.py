#!/usr/bin/env python3
"""
Basic Elecrypto usage examples
"""

import sys
import os

# Add parent directory to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import elecrypto

print("=== Elecrypto Python Bindings Examples ===\n")

# 1. Hash functions
print("1. Hash Functions")
message = b"Hello, Elecrypto!"

sha256_hash = elecrypto.sha256(message)
print(f"SHA-256: {sha256_hash.hex()}")

sha512_hash = elecrypto.sha512(message)
print(f"SHA-512: {sha512_hash.hex()[:64]}...")

blake3_hash = elecrypto.blake3(message)
print(f"BLAKE3:  {blake3_hash.hex()}\n")

# 2. Random number generation
print("2. Random Number Generation")
random_data = elecrypto.random_bytes(32)
print(f"32 random bytes: {random_data.hex()}\n")

# 3. AES-GCM encryption
print("3. AES-256-GCM Encryption")
plaintext = b"This is a secret message!"
key = elecrypto.aes_generate_key()
print(f"Generated key: {key.hex()}")

ciphertext, nonce = elecrypto.aes_gcm_encrypt(plaintext, key)
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Nonce: {nonce.hex()}")

decrypted = elecrypto.aes_gcm_decrypt(ciphertext, key, nonce)
print(f"Decrypted: {decrypted.decode()}")
assert decrypted == plaintext, "Decryption failed!"
print("✓ Encryption/Decryption successful\n")

# 4. ChaCha20-Poly1305 encryption
print("4. ChaCha20-Poly1305 Encryption")
key = elecrypto.chacha20_generate_key()
ciphertext, nonce = elecrypto.chacha20_poly1305_encrypt(plaintext, key)
print(f"Ciphertext: {ciphertext.hex()}")

decrypted = elecrypto.chacha20_poly1305_decrypt(ciphertext, key, nonce)
print(f"Decrypted: {decrypted.decode()}")
assert decrypted == plaintext
print("✓ ChaCha20 encryption successful\n")

# 5. Digital signatures (Ed25519)
print("5. Ed25519 Digital Signatures")
public_key, secret_key = elecrypto.ed25519_generate_keypair()
print(f"Public key: {public_key.hex()}")
print(f"Secret key: {secret_key.hex()[:32]}...")

message = b"Sign this important message"
signature = elecrypto.ed25519_sign(message, secret_key)
print(f"Signature: {signature.hex()[:32]}...")

is_valid = elecrypto.ed25519_verify(message, signature, public_key)
print(f"Signature valid: {is_valid}")
assert is_valid, "Signature verification failed!"

# Try with wrong message
wrong_message = b"Different message"
is_valid = elecrypto.ed25519_verify(wrong_message, signature, public_key)
print(f"Wrong message valid: {is_valid}")
assert not is_valid
print("✓ Digital signature successful\n")

# 6. Key derivation (PBKDF2)
print("6. Key Derivation - PBKDF2")
password = b"super_secret_password"
salt = elecrypto.random_bytes(16)

derived_key = elecrypto.pbkdf2(password, salt, iterations=100000, key_length=32)
print(f"Derived key: {derived_key.hex()}")
print("✓ PBKDF2 successful\n")

# 7. Key derivation (Argon2id)
print("7. Key Derivation - Argon2id")
derived_key, salt = elecrypto.argon2id(
    password,
    memory_cost=65536,  # 64 MB
    time_cost=3,
    parallelism=4,
    key_length=32
)
print(f"Derived key: {derived_key.hex()}")
print(f"Salt: {salt.hex()}")
print("✓ Argon2id successful\n")

# 8. HKDF
print("8. HKDF Key Derivation")
input_key = elecrypto.random_bytes(32)
info = b"application context"

derived = elecrypto.hkdf(input_key, info=info, key_length=64)
print(f"Derived key (64 bytes): {derived.hex()}")
print("✓ HKDF successful\n")

print("=== All tests passed! ===")
