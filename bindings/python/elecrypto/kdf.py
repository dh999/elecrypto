"""
Key Derivation Functions for Elecrypto
"""

import ctypes
from typing import Optional, Tuple

from .lib import lib, check_result


def pbkdf2(
    password: bytes,
    salt: bytes,
    iterations: int = 600000,
    key_length: int = 32,
) -> bytes:
    """
    Derive key using PBKDF2-HMAC-SHA256.

    Args:
        password: Password to derive key from
        salt: Salt (should be at least 16 bytes)
        iterations: Number of iterations (default: 600000)
        key_length: Desired key length in bytes (default: 32)

    Returns:
        bytes: Derived key

    Raises:
        ElecryptoError: If derivation fails
    """
    password_len = len(password)
    salt_len = len(salt)

    password_buf = (ctypes.c_ubyte * password_len)(*password)
    salt_buf = (ctypes.c_ubyte * salt_len)(*salt)
    output_buf = (ctypes.c_ubyte * key_length)()

    check_result(
        lib.elecrypto_pbkdf2(
            password_buf,
            password_len,
            salt_buf,
            salt_len,
            iterations,
            output_buf,
            key_length,
        )
    )

    return bytes(output_buf)


def argon2id(
    password: bytes,
    salt: Optional[bytes] = None,
    memory_cost: int = 65536,  # 64 MB
    time_cost: int = 3,
    parallelism: int = 4,
    key_length: int = 32,
) -> Tuple[bytes, bytes]:
    """
    Derive key using Argon2id (recommended for passwords).

    Args:
        password: Password to derive key from
        salt: 16-byte salt (generated if not provided)
        memory_cost: Memory cost in KiB (default: 65536 = 64 MB)
        time_cost: Time cost (iterations) (default: 3)
        parallelism: Parallelism factor (default: 4)
        key_length: Desired key length in bytes (default: 32)

    Returns:
        Tuple of (derived_key, salt)

    Raises:
        ElecryptoError: If derivation fails
    """
    password_len = len(password)
    password_buf = (ctypes.c_ubyte * password_len)(*password)

    salt_buf = None
    if salt is not None:
        if len(salt) != 16:
            raise ValueError("Salt must be 16 bytes if provided")
        salt_buf = (ctypes.c_ubyte * 16)(*salt)

    output_buf = (ctypes.c_ubyte * key_length)()
    salt_out_buf = (ctypes.c_ubyte * 16)()

    check_result(
        lib.elecrypto_argon2id(
            password_buf,
            password_len,
            salt_buf,
            memory_cost,
            time_cost,
            parallelism,
            output_buf,
            key_length,
            salt_out_buf,
        )
    )

    return bytes(output_buf), bytes(salt_out_buf)


def hkdf(
    input_key_material: bytes,
    salt: Optional[bytes] = None,
    info: Optional[bytes] = None,
    key_length: int = 32,
) -> bytes:
    """
    Derive key using HKDF (HMAC-based Key Derivation Function).

    Args:
        input_key_material: Input key material
        salt: Optional salt (can be empty)
        info: Optional context/application specific info
        key_length: Desired key length in bytes (default: 32)

    Returns:
        bytes: Derived key

    Raises:
        ElecryptoError: If derivation fails
    """
    ikm_len = len(input_key_material)
    ikm_buf = (ctypes.c_ubyte * ikm_len)(*input_key_material)

    salt_buf = None
    salt_len = 0
    if salt is not None:
        salt_len = len(salt)
        salt_buf = (ctypes.c_ubyte * salt_len)(*salt)

    info_buf = None
    info_len = 0
    if info is not None:
        info_len = len(info)
        info_buf = (ctypes.c_ubyte * info_len)(*info)

    output_buf = (ctypes.c_ubyte * key_length)()

    check_result(
        lib.elecrypto_hkdf(
            ikm_buf,
            ikm_len,
            salt_buf,
            salt_len,
            info_buf,
            info_len,
            output_buf,
            key_length,
        )
    )

    return bytes(output_buf)
