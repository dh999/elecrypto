"""
Asymmetric encryption functions for Elecrypto

Includes RSA-OAEP and ECIES implementations.
"""

import ctypes
from typing import Tuple

from .lib import (
    lib,
    check_result,
    RSA2048_PUBLIC_KEY_SIZE,
    RSA2048_PRIVATE_KEY_SIZE,
    ECIES_PUBLIC_KEY_SIZE,
    ECIES_PRIVATE_KEY_SIZE,
)


# RSA-OAEP Functions

def rsa_generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an RSA-2048 key pair.

    Returns:
        Tuple of (public_key, private_key) in DER format
        - public_key: 294 bytes
        - private_key: 1218 bytes

    Raises:
        ElecryptoError: If key generation fails
    """
    public_key = (ctypes.c_ubyte * RSA2048_PUBLIC_KEY_SIZE)()
    private_key = (ctypes.c_ubyte * RSA2048_PRIVATE_KEY_SIZE)()

    result = lib.elecrypto_rsa_generate_keypair_2048(public_key, private_key)
    check_result(result)

    return bytes(public_key), bytes(private_key)


def rsa_encrypt(plaintext: bytes, public_key: bytes) -> bytes:
    """
    Encrypt data using RSA-OAEP with SHA-256.

    Args:
        plaintext: Data to encrypt (max ~190 bytes for RSA-2048)
        public_key: RSA public key in DER format

    Returns:
        bytes: Encrypted ciphertext (256 bytes for RSA-2048)

    Raises:
        ElecryptoError: If encryption fails
    """
    plaintext_len = len(plaintext)
    public_key_len = len(public_key)

    # RSA-2048 produces 256-byte ciphertext
    max_ciphertext_len = 256

    plaintext_buf = (ctypes.c_ubyte * plaintext_len)(*plaintext)
    public_key_buf = (ctypes.c_ubyte * public_key_len)(*public_key)
    ciphertext_buf = (ctypes.c_ubyte * max_ciphertext_len)()
    ciphertext_len = ctypes.c_uint()

    result = lib.elecrypto_rsa_encrypt(
        plaintext_buf,
        plaintext_len,
        public_key_buf,
        public_key_len,
        ciphertext_buf,
        ctypes.byref(ciphertext_len),
    )

    check_result(result)

    return bytes(ciphertext_buf[:ciphertext_len.value])


def rsa_decrypt(ciphertext: bytes, private_key: bytes) -> bytes:
    """
    Decrypt data using RSA-OAEP with SHA-256.

    Args:
        ciphertext: Encrypted data (256 bytes for RSA-2048)
        private_key: RSA private key in DER format

    Returns:
        bytes: Decrypted plaintext

    Raises:
        ElecryptoError: If decryption fails
    """
    ciphertext_len = len(ciphertext)
    private_key_len = len(private_key)

    # Max plaintext is ~190 bytes for RSA-2048 with OAEP-SHA256
    max_plaintext_len = 256

    ciphertext_buf = (ctypes.c_ubyte * ciphertext_len)(*ciphertext)
    private_key_buf = (ctypes.c_ubyte * private_key_len)(*private_key)
    plaintext_buf = (ctypes.c_ubyte * max_plaintext_len)()
    plaintext_len = ctypes.c_uint()

    result = lib.elecrypto_rsa_decrypt(
        ciphertext_buf,
        ciphertext_len,
        private_key_buf,
        private_key_len,
        plaintext_buf,
        ctypes.byref(plaintext_len),
    )

    check_result(result)

    return bytes(plaintext_buf[:plaintext_len.value])


# ECIES Functions

def ecies_generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an ECIES (P-256) key pair.

    Returns:
        Tuple of (public_key, private_key)
        - public_key: 65 bytes (uncompressed point)
        - private_key: 32 bytes

    Raises:
        ElecryptoError: If key generation fails
    """
    public_key = (ctypes.c_ubyte * ECIES_PUBLIC_KEY_SIZE)()
    private_key = (ctypes.c_ubyte * ECIES_PRIVATE_KEY_SIZE)()

    result = lib.elecrypto_ecies_generate_keypair(public_key, private_key)
    check_result(result)

    return bytes(public_key), bytes(private_key)


def ecies_encrypt(plaintext: bytes, public_key: bytes) -> bytes:
    """
    Encrypt data using ECIES (P-256 ECDH + HKDF-SHA256 + AES-256-GCM).

    Args:
        plaintext: Data to encrypt
        public_key: ECIES public key (65 bytes)

    Returns:
        bytes: Encrypted ciphertext (includes ephemeral public key and auth tag)

    Raises:
        ElecryptoError: If encryption fails
    """
    if len(public_key) != ECIES_PUBLIC_KEY_SIZE:
        raise ValueError(f"Public key must be {ECIES_PUBLIC_KEY_SIZE} bytes, got {len(public_key)}")

    plaintext_len = len(plaintext)

    # ECIES ciphertext = ephemeral_pubkey (65) + nonce (12) + ciphertext + tag (16)
    max_ciphertext_len = 65 + 12 + plaintext_len + 16

    plaintext_buf = (ctypes.c_ubyte * plaintext_len)(*plaintext)
    public_key_buf = (ctypes.c_ubyte * ECIES_PUBLIC_KEY_SIZE)(*public_key)
    ciphertext_buf = (ctypes.c_ubyte * max_ciphertext_len)()
    ciphertext_len = ctypes.c_uint()

    result = lib.elecrypto_ecies_encrypt(
        plaintext_buf,
        plaintext_len,
        public_key_buf,
        ciphertext_buf,
        ctypes.byref(ciphertext_len),
    )

    check_result(result)

    return bytes(ciphertext_buf[:ciphertext_len.value])


def ecies_decrypt(ciphertext: bytes, private_key: bytes) -> bytes:
    """
    Decrypt data using ECIES.

    Args:
        ciphertext: Encrypted data from ecies_encrypt
        private_key: ECIES private key (32 bytes)

    Returns:
        bytes: Decrypted plaintext

    Raises:
        ElecryptoError: If decryption fails
    """
    if len(private_key) != ECIES_PRIVATE_KEY_SIZE:
        raise ValueError(f"Private key must be {ECIES_PRIVATE_KEY_SIZE} bytes, got {len(private_key)}")

    ciphertext_len = len(ciphertext)

    # Max plaintext length (remove overhead)
    max_plaintext_len = ciphertext_len - 65 - 12 - 16
    if max_plaintext_len < 0:
        raise ValueError("Ciphertext too short")

    ciphertext_buf = (ctypes.c_ubyte * ciphertext_len)(*ciphertext)
    private_key_buf = (ctypes.c_ubyte * ECIES_PRIVATE_KEY_SIZE)(*private_key)
    plaintext_buf = (ctypes.c_ubyte * max_plaintext_len)() if max_plaintext_len > 0 else (ctypes.c_ubyte * 1)()
    plaintext_len = ctypes.c_uint()

    result = lib.elecrypto_ecies_decrypt(
        ciphertext_buf,
        ciphertext_len,
        private_key_buf,
        plaintext_buf,
        ctypes.byref(plaintext_len),
    )

    check_result(result)

    return bytes(plaintext_buf[:plaintext_len.value])
