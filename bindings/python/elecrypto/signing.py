"""
Digital signature functions for Elecrypto
"""

import ctypes
from typing import Tuple

from .lib import (
    lib,
    check_result,
    ED25519_PUBLIC_KEY_SIZE,
    ED25519_SECRET_KEY_SIZE,
    ED25519_SIGNATURE_SIZE,
)


def ed25519_generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate Ed25519 keypair.

    Returns:
        Tuple of (public_key, secret_key)
        - public_key: 32 bytes
        - secret_key: 64 bytes
    """
    public_key_buf = (ctypes.c_ubyte * ED25519_PUBLIC_KEY_SIZE)()
    secret_key_buf = (ctypes.c_ubyte * ED25519_SECRET_KEY_SIZE)()

    check_result(lib.elecrypto_ed25519_generate_keypair(public_key_buf, secret_key_buf))

    return bytes(public_key_buf), bytes(secret_key_buf)


def ed25519_sign(message: bytes, secret_key: bytes) -> bytes:
    """
    Sign a message with Ed25519.

    Args:
        message: Message to sign
        secret_key: 64-byte secret key

    Returns:
        bytes: 64-byte signature

    Raises:
        ElecryptoError: If signing fails
    """
    if len(secret_key) != ED25519_SECRET_KEY_SIZE:
        raise ValueError(
            f"Secret key must be {ED25519_SECRET_KEY_SIZE} bytes, got {len(secret_key)}"
        )

    message_len = len(message)
    message_buf = (ctypes.c_ubyte * message_len)(*message)
    secret_key_buf = (ctypes.c_ubyte * ED25519_SECRET_KEY_SIZE)(*secret_key)
    signature_buf = (ctypes.c_ubyte * ED25519_SIGNATURE_SIZE)()

    check_result(
        lib.elecrypto_ed25519_sign(
            message_buf,
            message_len,
            secret_key_buf,
            signature_buf,
        )
    )

    return bytes(signature_buf)


def ed25519_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify an Ed25519 signature.

    Args:
        message: Original message
        signature: 64-byte signature
        public_key: 32-byte public key

    Returns:
        bool: True if signature is valid, False otherwise

    Raises:
        ElecryptoError: If verification computation fails
    """
    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise ValueError(
            f"Signature must be {ED25519_SIGNATURE_SIZE} bytes, got {len(signature)}"
        )
    if len(public_key) != ED25519_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"Public key must be {ED25519_PUBLIC_KEY_SIZE} bytes, got {len(public_key)}"
        )

    message_len = len(message)
    message_buf = (ctypes.c_ubyte * message_len)(*message)
    signature_buf = (ctypes.c_ubyte * ED25519_SIGNATURE_SIZE)(*signature)
    public_key_buf = (ctypes.c_ubyte * ED25519_PUBLIC_KEY_SIZE)(*public_key)

    result = lib.elecrypto_ed25519_verify(
        message_buf,
        message_len,
        signature_buf,
        public_key_buf,
    )

    if result < 0:
        check_result(result)  # Will raise exception

    return result == 1
