"""
Post-Quantum Cryptography functions for Elecrypto

NIST standard post-quantum algorithms:
- Kyber (ML-KEM): Key Encapsulation Mechanism
- Dilithium (ML-DSA): Digital Signatures
"""

import ctypes
from typing import Tuple

from .lib import (
    lib,
    check_result,
    KYBER512_PUBLIC_KEY_SIZE,
    KYBER512_SECRET_KEY_SIZE,
    KYBER512_CIPHERTEXT_SIZE,
    KYBER512_SHARED_SECRET_SIZE,
    DILITHIUM2_PUBLIC_KEY_SIZE,
    DILITHIUM2_SECRET_KEY_SIZE,
    DILITHIUM2_SIGNATURE_SIZE,
)


# Kyber (ML-KEM) Key Encapsulation

def kyber512_generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a Kyber-512 key pair for key encapsulation.

    Returns:
        Tuple of (public_key, secret_key)
        - public_key: 800 bytes
        - secret_key: 1632 bytes

    Raises:
        ElecryptoError: If key generation fails
    """
    public_key = (ctypes.c_ubyte * KYBER512_PUBLIC_KEY_SIZE)()
    secret_key = (ctypes.c_ubyte * KYBER512_SECRET_KEY_SIZE)()

    result = lib.elecrypto_kyber512_generate_keypair(public_key, secret_key)
    check_result(result)

    return bytes(public_key), bytes(secret_key)


def kyber512_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using Kyber-512.

    Generates a random shared secret and encapsulates it using the public key.

    Args:
        public_key: Kyber-512 public key (800 bytes)

    Returns:
        Tuple of (ciphertext, shared_secret)
        - ciphertext: 768 bytes
        - shared_secret: 32 bytes

    Raises:
        ElecryptoError: If encapsulation fails
    """
    if len(public_key) != KYBER512_PUBLIC_KEY_SIZE:
        raise ValueError(f"Public key must be {KYBER512_PUBLIC_KEY_SIZE} bytes, got {len(public_key)}")

    public_key_buf = (ctypes.c_ubyte * KYBER512_PUBLIC_KEY_SIZE)(*public_key)
    ciphertext = (ctypes.c_ubyte * KYBER512_CIPHERTEXT_SIZE)()
    shared_secret = (ctypes.c_ubyte * KYBER512_SHARED_SECRET_SIZE)()

    result = lib.elecrypto_kyber512_encapsulate(
        public_key_buf,
        ciphertext,
        shared_secret,
    )

    check_result(result)

    return bytes(ciphertext), bytes(shared_secret)


def kyber512_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    Decapsulate a shared secret using Kyber-512.

    Recovers the shared secret from the ciphertext using the secret key.

    Args:
        ciphertext: Kyber-512 ciphertext (768 bytes)
        secret_key: Kyber-512 secret key (1632 bytes)

    Returns:
        bytes: Shared secret (32 bytes)

    Raises:
        ElecryptoError: If decapsulation fails
    """
    if len(ciphertext) != KYBER512_CIPHERTEXT_SIZE:
        raise ValueError(f"Ciphertext must be {KYBER512_CIPHERTEXT_SIZE} bytes, got {len(ciphertext)}")
    if len(secret_key) != KYBER512_SECRET_KEY_SIZE:
        raise ValueError(f"Secret key must be {KYBER512_SECRET_KEY_SIZE} bytes, got {len(secret_key)}")

    ciphertext_buf = (ctypes.c_ubyte * KYBER512_CIPHERTEXT_SIZE)(*ciphertext)
    secret_key_buf = (ctypes.c_ubyte * KYBER512_SECRET_KEY_SIZE)(*secret_key)
    shared_secret = (ctypes.c_ubyte * KYBER512_SHARED_SECRET_SIZE)()

    result = lib.elecrypto_kyber512_decapsulate(
        ciphertext_buf,
        secret_key_buf,
        shared_secret,
    )

    check_result(result)

    return bytes(shared_secret)


# Dilithium (ML-DSA) Digital Signatures

def dilithium2_generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a Dilithium2 key pair for digital signatures.

    Returns:
        Tuple of (public_key, secret_key)
        - public_key: 1312 bytes
        - secret_key: 2560 bytes

    Raises:
        ElecryptoError: If key generation fails
    """
    public_key = (ctypes.c_ubyte * DILITHIUM2_PUBLIC_KEY_SIZE)()
    secret_key = (ctypes.c_ubyte * DILITHIUM2_SECRET_KEY_SIZE)()

    result = lib.elecrypto_dilithium2_generate_keypair(public_key, secret_key)
    check_result(result)

    return bytes(public_key), bytes(secret_key)


def dilithium2_sign(message: bytes, secret_key: bytes) -> bytes:
    """
    Sign a message using Dilithium2.

    Args:
        message: Message to sign
        secret_key: Dilithium2 secret key (2560 bytes)

    Returns:
        bytes: Signature (2420 bytes)

    Raises:
        ElecryptoError: If signing fails
    """
    if len(secret_key) != DILITHIUM2_SECRET_KEY_SIZE:
        raise ValueError(f"Secret key must be {DILITHIUM2_SECRET_KEY_SIZE} bytes, got {len(secret_key)}")

    message_len = len(message)
    message_buf = (ctypes.c_ubyte * message_len)(*message) if message_len > 0 else (ctypes.c_ubyte * 1)()
    secret_key_buf = (ctypes.c_ubyte * DILITHIUM2_SECRET_KEY_SIZE)(*secret_key)
    signature = (ctypes.c_ubyte * DILITHIUM2_SIGNATURE_SIZE)()

    result = lib.elecrypto_dilithium2_sign(
        message_buf,
        message_len,
        secret_key_buf,
        signature,
    )

    check_result(result)

    return bytes(signature)


def dilithium2_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify a Dilithium2 signature.

    Args:
        message: Original message
        signature: Signature to verify (2420 bytes)
        public_key: Dilithium2 public key (1312 bytes)

    Returns:
        bool: True if signature is valid

    Raises:
        ElecryptoError: If verification fails (invalid signature)
    """
    if len(signature) != DILITHIUM2_SIGNATURE_SIZE:
        raise ValueError(f"Signature must be {DILITHIUM2_SIGNATURE_SIZE} bytes, got {len(signature)}")
    if len(public_key) != DILITHIUM2_PUBLIC_KEY_SIZE:
        raise ValueError(f"Public key must be {DILITHIUM2_PUBLIC_KEY_SIZE} bytes, got {len(public_key)}")

    message_len = len(message)
    message_buf = (ctypes.c_ubyte * message_len)(*message) if message_len > 0 else (ctypes.c_ubyte * 1)()
    signature_buf = (ctypes.c_ubyte * DILITHIUM2_SIGNATURE_SIZE)(*signature)
    public_key_buf = (ctypes.c_ubyte * DILITHIUM2_PUBLIC_KEY_SIZE)(*public_key)

    result = lib.elecrypto_dilithium2_verify(
        message_buf,
        message_len,
        signature_buf,
        public_key_buf,
    )

    check_result(result)

    return True
