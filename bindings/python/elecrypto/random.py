"""
Random number generation for Elecrypto
"""

import ctypes

from .lib import lib, check_result


def random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Args:
        length: Number of bytes to generate

    Returns:
        bytes: Random data of specified length
    """
    if length < 0:
        raise ValueError("Length must be non-negative")

    output_buf = (ctypes.c_ubyte * length)()
    check_result(lib.elecrypto_random_bytes(output_buf, length))

    return bytes(output_buf)
