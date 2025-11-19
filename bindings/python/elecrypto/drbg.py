"""
Deterministic Random Bit Generator (DRBG) functions for Elecrypto

NIST SP 800-90A compliant random number generation.
"""

import ctypes

from .lib import lib, check_result


def hmac_drbg_generate(seed: bytes, output_len: int) -> bytes:
    """
    Generate random bytes using HMAC-DRBG (NIST SP 800-90A).

    Uses HMAC-SHA256 as the underlying PRF.

    Args:
        seed: Initial entropy (at least 32 bytes recommended)
        output_len: Number of random bytes to generate

    Returns:
        bytes: Random bytes

    Raises:
        ElecryptoError: If generation fails
    """
    if len(seed) < 1:
        raise ValueError("Seed cannot be empty")
    if output_len < 1:
        raise ValueError("Output length must be at least 1")

    seed_len = len(seed)
    seed_buf = (ctypes.c_ubyte * seed_len)(*seed)
    output_buf = (ctypes.c_ubyte * output_len)()

    result = lib.elecrypto_hmac_drbg_generate(
        seed_buf,
        seed_len,
        output_buf,
        output_len,
    )

    check_result(result)

    return bytes(output_buf)


def ctr_drbg_generate(seed: bytes, output_len: int) -> bytes:
    """
    Generate random bytes using CTR-DRBG (NIST SP 800-90A).

    Uses AES-256-CTR as the underlying block cipher.

    Args:
        seed: Initial entropy (at least 48 bytes: 32 for key + 16 for counter)
        output_len: Number of random bytes to generate

    Returns:
        bytes: Random bytes

    Raises:
        ElecryptoError: If generation fails
    """
    if len(seed) < 48:
        raise ValueError("Seed must be at least 48 bytes for CTR-DRBG")
    if output_len < 1:
        raise ValueError("Output length must be at least 1")

    seed_len = len(seed)
    seed_buf = (ctypes.c_ubyte * seed_len)(*seed)
    output_buf = (ctypes.c_ubyte * output_len)()

    result = lib.elecrypto_ctr_drbg_generate(
        seed_buf,
        seed_len,
        output_buf,
        output_len,
    )

    check_result(result)

    return bytes(output_buf)
