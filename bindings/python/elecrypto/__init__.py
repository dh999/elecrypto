"""
Elecrypto Python Bindings

Cross-platform cryptographic library with post-quantum support.
"""

__version__ = "0.1.0"

from .lib import ElecryptoError
from .symmetric import (
    aes_generate_key,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    chacha20_generate_key,
    chacha20_poly1305_encrypt,
    chacha20_poly1305_decrypt,
)
from .hash import sha256, sha512, sha3_256, blake3
from .random import random_bytes
from .signing import (
    ed25519_generate_keypair,
    ed25519_sign,
    ed25519_verify,
)
from .kdf import pbkdf2, argon2id, hkdf

__all__ = [
    'ElecryptoError',
    # Symmetric encryption
    'aes_generate_key',
    'aes_gcm_encrypt',
    'aes_gcm_decrypt',
    'chacha20_generate_key',
    'chacha20_poly1305_encrypt',
    'chacha20_poly1305_decrypt',
    # Hash functions
    'sha256',
    'sha512',
    'sha3_256',
    'blake3',
    # Random
    'random_bytes',
    # Digital signatures
    'ed25519_generate_keypair',
    'ed25519_sign',
    'ed25519_verify',
    # KDF
    'pbkdf2',
    'argon2id',
    'hkdf',
]
