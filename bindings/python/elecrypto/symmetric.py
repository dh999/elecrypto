"""
Symmetric encryption functions for Elecrypto
"""

import ctypes
from typing import Optional, Tuple

from .lib import (
    lib,
    check_result,
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    AES_TAG_SIZE,
    CHACHA20_KEY_SIZE,
    CHACHA20_NONCE_SIZE,
)


def aes_generate_key() -> bytes:
    """
    Generate a random AES-256 key.

    Returns:
        bytes: 32-byte AES-256 key
    """
    key = (ctypes.c_ubyte * AES_KEY_SIZE)()
    check_result(lib.elecrypto_aes_generate_key(key))
    return bytes(key)


def aes_gcm_encrypt(
    plaintext: bytes,
    key: bytes,
    nonce: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """
    Encrypt data using AES-256-GCM (authenticated encryption).

    Args:
        plaintext: Data to encrypt
        key: 32-byte AES-256 key
        nonce: 12-byte nonce (generated if not provided)

    Returns:
        Tuple of (ciphertext, nonce)
        - ciphertext includes 16-byte authentication tag
        - nonce is 12 bytes

    Raises:
        ElecryptoError: If encryption fails
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")

    plaintext_len = len(plaintext)
    ciphertext_len = plaintext_len + AES_TAG_SIZE

    plaintext_buf = (ctypes.c_ubyte * plaintext_len)(*plaintext)
    key_buf = (ctypes.c_ubyte * AES_KEY_SIZE)(*key)
    ciphertext_buf = (ctypes.c_ubyte * ciphertext_len)()
    nonce_out_buf = (ctypes.c_ubyte * AES_NONCE_SIZE)()

    nonce_buf = None
    if nonce is not None:
        if len(nonce) != AES_NONCE_SIZE:
            raise ValueError(f"Nonce must be {AES_NONCE_SIZE} bytes, got {len(nonce)}")
        nonce_buf = (ctypes.c_ubyte * AES_NONCE_SIZE)(*nonce)

    result = lib.elecrypto_aes_gcm_encrypt(
        plaintext_buf,
        plaintext_len,
        key_buf,
        nonce_buf,
        ciphertext_buf,
        nonce_out_buf,
    )

    check_result(result)

    return bytes(ciphertext_buf), bytes(nonce_out_buf)


def aes_gcm_decrypt(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
) -> bytes:
    """
    Decrypt data using AES-256-GCM.

    Args:
        ciphertext: Encrypted data (includes 16-byte authentication tag)
        key: 32-byte AES-256 key
        nonce: 12-byte nonce used during encryption

    Returns:
        bytes: Decrypted plaintext

    Raises:
        ElecryptoError: If decryption or authentication fails
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != AES_NONCE_SIZE:
        raise ValueError(f"Nonce must be {AES_NONCE_SIZE} bytes, got {len(nonce)}")

    ciphertext_len = len(ciphertext)
    plaintext_len = ciphertext_len - AES_TAG_SIZE

    if plaintext_len < 0:
        raise ValueError("Ciphertext too short")

    ciphertext_buf = (ctypes.c_ubyte * ciphertext_len)(*ciphertext)
    key_buf = (ctypes.c_ubyte * AES_KEY_SIZE)(*key)
    nonce_buf = (ctypes.c_ubyte * AES_NONCE_SIZE)(*nonce)
    plaintext_buf = (ctypes.c_ubyte * plaintext_len)()

    result = lib.elecrypto_aes_gcm_decrypt(
        ciphertext_buf,
        ciphertext_len,
        key_buf,
        nonce_buf,
        plaintext_buf,
    )

    check_result(result)

    return bytes(plaintext_buf)


def chacha20_generate_key() -> bytes:
    """
    Generate a random ChaCha20-Poly1305 key.

    Returns:
        bytes: 32-byte key
    """
    key = (ctypes.c_ubyte * CHACHA20_KEY_SIZE)()
    check_result(lib.elecrypto_chacha20_generate_key(key))
    return bytes(key)


def chacha20_poly1305_encrypt(
    plaintext: bytes,
    key: bytes,
    nonce: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """
    Encrypt data using ChaCha20-Poly1305 (authenticated encryption).

    Args:
        plaintext: Data to encrypt
        key: 32-byte key
        nonce: 12-byte nonce (generated if not provided)

    Returns:
        Tuple of (ciphertext, nonce)
    """
    if len(key) != CHACHA20_KEY_SIZE:
        raise ValueError(f"Key must be {CHACHA20_KEY_SIZE} bytes, got {len(key)}")

    plaintext_len = len(plaintext)
    ciphertext_len = plaintext_len + 16  # 16-byte tag

    plaintext_buf = (ctypes.c_ubyte * plaintext_len)(*plaintext)
    key_buf = (ctypes.c_ubyte * CHACHA20_KEY_SIZE)(*key)
    ciphertext_buf = (ctypes.c_ubyte * ciphertext_len)()
    nonce_out_buf = (ctypes.c_ubyte * CHACHA20_NONCE_SIZE)()

    nonce_buf = None
    if nonce is not None:
        if len(nonce) != CHACHA20_NONCE_SIZE:
            raise ValueError(f"Nonce must be {CHACHA20_NONCE_SIZE} bytes, got {len(nonce)}")
        nonce_buf = (ctypes.c_ubyte * CHACHA20_NONCE_SIZE)(*nonce)

    result = lib.elecrypto_chacha20_poly1305_encrypt(
        plaintext_buf,
        plaintext_len,
        key_buf,
        nonce_buf,
        ciphertext_buf,
        nonce_out_buf,
    )

    check_result(result)

    return bytes(ciphertext_buf), bytes(nonce_out_buf)


def chacha20_poly1305_decrypt(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
) -> bytes:
    """
    Decrypt data using ChaCha20-Poly1305.

    Args:
        ciphertext: Encrypted data (includes 16-byte tag)
        key: 32-byte key
        nonce: 12-byte nonce

    Returns:
        bytes: Decrypted plaintext
    """
    if len(key) != CHACHA20_KEY_SIZE:
        raise ValueError(f"Key must be {CHACHA20_KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != CHACHA20_NONCE_SIZE:
        raise ValueError(f"Nonce must be {CHACHA20_NONCE_SIZE} bytes, got {len(nonce)}")

    ciphertext_len = len(ciphertext)
    plaintext_len = ciphertext_len - 16

    if plaintext_len < 0:
        raise ValueError("Ciphertext too short")

    ciphertext_buf = (ctypes.c_ubyte * ciphertext_len)(*ciphertext)
    key_buf = (ctypes.c_ubyte * CHACHA20_KEY_SIZE)(*key)
    nonce_buf = (ctypes.c_ubyte * CHACHA20_NONCE_SIZE)(*nonce)
    plaintext_buf = (ctypes.c_ubyte * plaintext_len)()

    result = lib.elecrypto_chacha20_poly1305_decrypt(
        ciphertext_buf,
        ciphertext_len,
        key_buf,
        nonce_buf,
        plaintext_buf,
    )

    check_result(result)

    return bytes(plaintext_buf)
