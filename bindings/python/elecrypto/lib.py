"""
Elecrypto Python Bindings - C Library Loader

This module loads the elecrypto-core shared library and defines C function signatures.
"""

import ctypes
import os
import sys
from ctypes import c_int, c_uint, c_ubyte, POINTER

# Find the shared library
def _find_library():
    """Locate the elecrypto-core shared library"""
    lib_name = {
        'linux': 'libelecrypto_core.so',
        'darwin': 'libelecrypto_core.dylib',
        'win32': 'elecrypto_core.dll',
    }.get(sys.platform, 'libelecrypto_core.so')

    # Try multiple search paths
    search_paths = [
        # Development path
        os.path.join(os.path.dirname(__file__), '..', '..', '..', 'core', 'target', 'release', lib_name),
        # Installed path
        os.path.join(sys.prefix, 'lib', lib_name),
        # Current directory
        lib_name,
    ]

    for path in search_paths:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path):
            return abs_path

    # Fallback: let ctypes find it
    return lib_name

# Load the library
_lib_path = _find_library()
lib = ctypes.CDLL(_lib_path)

# Error codes
ELECRYPTO_SUCCESS = 0
ELECRYPTO_ERROR_INVALID_INPUT = -1
ELECRYPTO_ERROR_INVALID_KEY_LENGTH = -2
ELECRYPTO_ERROR_INVALID_NONCE_LENGTH = -3
ELECRYPTO_ERROR_AUTHENTICATION_FAILED = -4
ELECRYPTO_ERROR_ENCRYPTION_FAILED = -5
ELECRYPTO_ERROR_DECRYPTION_FAILED = -6
ELECRYPTO_ERROR_SIGNING_FAILED = -7
ELECRYPTO_ERROR_VERIFICATION_FAILED = -8
ELECRYPTO_ERROR_KEY_GENERATION_FAILED = -9
ELECRYPTO_ERROR_INVALID_PUBLIC_KEY = -10
ELECRYPTO_ERROR_INVALID_PRIVATE_KEY = -11

# Constants
AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12
AES_TAG_SIZE = 16
CHACHA20_KEY_SIZE = 32
CHACHA20_NONCE_SIZE = 12
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SECRET_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64

# Define function signatures

# Random
lib.elecrypto_random_bytes.argtypes = [POINTER(c_ubyte), c_uint]
lib.elecrypto_random_bytes.restype = c_int

# Hash functions
lib.elecrypto_sha256.argtypes = [POINTER(c_ubyte), c_uint, POINTER(c_ubyte)]
lib.elecrypto_sha256.restype = c_int

lib.elecrypto_sha512.argtypes = [POINTER(c_ubyte), c_uint, POINTER(c_ubyte)]
lib.elecrypto_sha512.restype = c_int

lib.elecrypto_sha3_256.argtypes = [POINTER(c_ubyte), c_uint, POINTER(c_ubyte)]
lib.elecrypto_sha3_256.restype = c_int

lib.elecrypto_blake3.argtypes = [POINTER(c_ubyte), c_uint, POINTER(c_ubyte), c_uint]
lib.elecrypto_blake3.restype = c_int

# AES-GCM
lib.elecrypto_aes_generate_key.argtypes = [POINTER(c_ubyte)]
lib.elecrypto_aes_generate_key.restype = c_int

lib.elecrypto_aes_gcm_encrypt.argtypes = [
    POINTER(c_ubyte), c_uint,  # plaintext
    POINTER(c_ubyte),          # key
    POINTER(c_ubyte),          # nonce (can be NULL)
    POINTER(c_ubyte),          # ciphertext
    POINTER(c_ubyte),          # nonce_out
]
lib.elecrypto_aes_gcm_encrypt.restype = c_int

lib.elecrypto_aes_gcm_decrypt.argtypes = [
    POINTER(c_ubyte), c_uint,  # ciphertext
    POINTER(c_ubyte),          # key
    POINTER(c_ubyte),          # nonce
    POINTER(c_ubyte),          # plaintext
]
lib.elecrypto_aes_gcm_decrypt.restype = c_int

# ChaCha20-Poly1305
lib.elecrypto_chacha20_generate_key.argtypes = [POINTER(c_ubyte)]
lib.elecrypto_chacha20_generate_key.restype = c_int

lib.elecrypto_chacha20_poly1305_encrypt.argtypes = [
    POINTER(c_ubyte), c_uint,
    POINTER(c_ubyte),
    POINTER(c_ubyte),
    POINTER(c_ubyte),
    POINTER(c_ubyte),
]
lib.elecrypto_chacha20_poly1305_encrypt.restype = c_int

lib.elecrypto_chacha20_poly1305_decrypt.argtypes = [
    POINTER(c_ubyte), c_uint,
    POINTER(c_ubyte),
    POINTER(c_ubyte),
    POINTER(c_ubyte),
]
lib.elecrypto_chacha20_poly1305_decrypt.restype = c_int

# Ed25519
lib.elecrypto_ed25519_generate_keypair.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
lib.elecrypto_ed25519_generate_keypair.restype = c_int

lib.elecrypto_ed25519_sign.argtypes = [
    POINTER(c_ubyte), c_uint,
    POINTER(c_ubyte),
    POINTER(c_ubyte),
]
lib.elecrypto_ed25519_sign.restype = c_int

lib.elecrypto_ed25519_verify.argtypes = [
    POINTER(c_ubyte), c_uint,
    POINTER(c_ubyte),
    POINTER(c_ubyte),
]
lib.elecrypto_ed25519_verify.restype = c_int

# KDF
lib.elecrypto_pbkdf2.argtypes = [
    POINTER(c_ubyte), c_uint,
    POINTER(c_ubyte), c_uint,
    c_uint,
    POINTER(c_ubyte), c_uint,
]
lib.elecrypto_pbkdf2.restype = c_int

lib.elecrypto_argon2id.argtypes = [
    POINTER(c_ubyte), c_uint,
    POINTER(c_ubyte),
    c_uint, c_uint, c_uint,
    POINTER(c_ubyte), c_uint,
    POINTER(c_ubyte),
]
lib.elecrypto_argon2id.restype = c_int

lib.elecrypto_hkdf.argtypes = [
    POINTER(c_ubyte), c_uint,
    POINTER(c_ubyte), c_uint,
    POINTER(c_ubyte), c_uint,
    POINTER(c_ubyte), c_uint,
]
lib.elecrypto_hkdf.restype = c_int


class ElecryptoError(Exception):
    """Base exception for Elecrypto errors"""

    ERROR_MESSAGES = {
        ELECRYPTO_ERROR_INVALID_INPUT: "Invalid input",
        ELECRYPTO_ERROR_INVALID_KEY_LENGTH: "Invalid key length",
        ELECRYPTO_ERROR_INVALID_NONCE_LENGTH: "Invalid nonce length",
        ELECRYPTO_ERROR_AUTHENTICATION_FAILED: "Authentication failed",
        ELECRYPTO_ERROR_ENCRYPTION_FAILED: "Encryption failed",
        ELECRYPTO_ERROR_DECRYPTION_FAILED: "Decryption failed",
        ELECRYPTO_ERROR_SIGNING_FAILED: "Signing failed",
        ELECRYPTO_ERROR_VERIFICATION_FAILED: "Verification failed",
        ELECRYPTO_ERROR_KEY_GENERATION_FAILED: "Key generation failed",
        ELECRYPTO_ERROR_INVALID_PUBLIC_KEY: "Invalid public key",
        ELECRYPTO_ERROR_INVALID_PRIVATE_KEY: "Invalid private key",
    }

    def __init__(self, code, message=None):
        self.code = code
        if message is None:
            message = self.ERROR_MESSAGES.get(code, f"Unknown error code: {code}")
        super().__init__(message)


def check_result(result):
    """Check return code and raise exception if error"""
    if result < 0:
        raise ElecryptoError(result)
    return result
