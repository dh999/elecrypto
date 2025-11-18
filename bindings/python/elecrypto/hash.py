"""
Hash functions for Elecrypto
"""

import ctypes
from typing import Optional

from .lib import lib, check_result


def sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 hash.

    Args:
        data: Data to hash

    Returns:
        bytes: 32-byte hash
    """
    data_len = len(data)
    data_buf = (ctypes.c_ubyte * data_len)(*data)
    hash_buf = (ctypes.c_ubyte * 32)()

    check_result(lib.elecrypto_sha256(data_buf, data_len, hash_buf))

    return bytes(hash_buf)


def sha512(data: bytes) -> bytes:
    """
    Compute SHA-512 hash.

    Args:
        data: Data to hash

    Returns:
        bytes: 64-byte hash
    """
    data_len = len(data)
    data_buf = (ctypes.c_ubyte * data_len)(*data)
    hash_buf = (ctypes.c_ubyte * 64)()

    check_result(lib.elecrypto_sha512(data_buf, data_len, hash_buf))

    return bytes(hash_buf)


def sha3_256(data: bytes) -> bytes:
    """
    Compute SHA3-256 hash.

    Args:
        data: Data to hash

    Returns:
        bytes: 32-byte hash
    """
    data_len = len(data)
    data_buf = (ctypes.c_ubyte * data_len)(*data)
    hash_buf = (ctypes.c_ubyte * 32)()

    check_result(lib.elecrypto_sha3_256(data_buf, data_len, hash_buf))

    return bytes(hash_buf)


def blake3(data: bytes, output_length: int = 32) -> bytes:
    """
    Compute BLAKE3 hash with custom output length.

    Args:
        data: Data to hash
        output_length: Desired hash length in bytes (default: 32)

    Returns:
        bytes: Hash of specified length
    """
    data_len = len(data)
    data_buf = (ctypes.c_ubyte * data_len)(*data)
    hash_buf = (ctypes.c_ubyte * output_length)()

    check_result(lib.elecrypto_blake3(data_buf, data_len, hash_buf, output_length))

    return bytes(hash_buf)
