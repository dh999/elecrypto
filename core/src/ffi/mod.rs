//! Foreign Function Interface (FFI) for C compatibility
//!
//! This module provides C-compatible functions for use in other languages.
//! All functions use C calling conventions and return error codes.
//!
//! **Note**: This module is under development.
//! FFI bindings will be generated using cbindgen.

#![allow(missing_docs)]

use std::os::raw::{c_int, c_uchar, c_uint};
use std::ptr;
use std::slice;

use crate::hash::{sha256, sha512, sha3_256, blake3_hash};
use crate::random::random_bytes;
use crate::symmetric::{aes_gcm_encrypt, aes_gcm_decrypt, aes_generate_key};
use crate::symmetric::{chacha20_poly1305_encrypt, chacha20_poly1305_decrypt, chacha20_generate_key};
use crate::signing::{ed25519_generate_keypair, ed25519_sign, ed25519_verify};
use crate::kdf::{pbkdf2, argon2id, hkdf_derive};
use crate::asymmetric::{
    RsaKeySize, rsa_generate_keypair, rsa_encrypt, rsa_decrypt,
    rsa_public_key_to_der, rsa_private_key_to_der,
    rsa_public_key_from_der, rsa_private_key_from_der,
    ecies_generate_keypair, ecies_encrypt, ecies_decrypt,
    ecies_public_key_to_bytes, ecies_private_key_to_bytes,
    ecies_public_key_from_bytes, ecies_private_key_from_bytes,
};
use crate::drbg::{Drbg, HmacDrbg, CtrDrbg};
use crate::pqc::{kyber512_keypair, kyber512_encapsulate, kyber512_decapsulate};
use crate::pqc::{dilithium2_keypair, dilithium2_sign, dilithium2_verify};

/// Success return code
pub const ELECRYPTO_SUCCESS: c_int = 0;

/// Error codes (negative values)
pub const ELECRYPTO_ERROR_INVALID_INPUT: c_int = -1;
pub const ELECRYPTO_ERROR_INVALID_KEY_LENGTH: c_int = -2;
pub const ELECRYPTO_ERROR_INVALID_NONCE_LENGTH: c_int = -3;
pub const ELECRYPTO_ERROR_AUTHENTICATION_FAILED: c_int = -4;
pub const ELECRYPTO_ERROR_ENCRYPTION_FAILED: c_int = -5;
pub const ELECRYPTO_ERROR_DECRYPTION_FAILED: c_int = -6;
pub const ELECRYPTO_ERROR_SIGNING_FAILED: c_int = -7;
pub const ELECRYPTO_ERROR_VERIFICATION_FAILED: c_int = -8;
pub const ELECRYPTO_ERROR_KEY_GENERATION_FAILED: c_int = -9;
pub const ELECRYPTO_ERROR_INVALID_PUBLIC_KEY: c_int = -10;
pub const ELECRYPTO_ERROR_INVALID_PRIVATE_KEY: c_int = -11;
pub const ELECRYPTO_ERROR_KEY_DERIVATION_FAILED: c_int = -17;
pub const ELECRYPTO_ERROR_ENCODING_FAILED: c_int = -18;
pub const ELECRYPTO_ERROR_DECODING_FAILED: c_int = -19;

/// RSA-2048 public key DER size (approximate max)
pub const ELECRYPTO_RSA2048_PUBLIC_KEY_SIZE: c_uint = 294;
/// RSA-2048 private key DER size (approximate max)
pub const ELECRYPTO_RSA2048_PRIVATE_KEY_SIZE: c_uint = 1218;

/// ECIES public key size (P-256 uncompressed point)
pub const ELECRYPTO_ECIES_PUBLIC_KEY_SIZE: c_uint = 65;
/// ECIES private key size (P-256 scalar)
pub const ELECRYPTO_ECIES_PRIVATE_KEY_SIZE: c_uint = 32;

/// Kyber512 public key size
pub const ELECRYPTO_KYBER512_PUBLIC_KEY_SIZE: c_uint = 800;
/// Kyber512 secret key size
pub const ELECRYPTO_KYBER512_SECRET_KEY_SIZE: c_uint = 1632;
/// Kyber512 ciphertext size
pub const ELECRYPTO_KYBER512_CIPHERTEXT_SIZE: c_uint = 768;
/// Kyber512 shared secret size
pub const ELECRYPTO_KYBER512_SHARED_SECRET_SIZE: c_uint = 32;

/// Dilithium2 public key size
pub const ELECRYPTO_DILITHIUM2_PUBLIC_KEY_SIZE: c_uint = 1312;
/// Dilithium2 secret key size
pub const ELECRYPTO_DILITHIUM2_SECRET_KEY_SIZE: c_uint = 2560;
/// Dilithium2 signature size
pub const ELECRYPTO_DILITHIUM2_SIGNATURE_SIZE: c_uint = 2420;

/// AES-256-GCM key size (32 bytes)
pub const ELECRYPTO_AES_KEY_SIZE: c_uint = 32;
/// AES-GCM nonce size (12 bytes)
pub const ELECRYPTO_AES_NONCE_SIZE: c_uint = 12;
/// AES-GCM authentication tag size (16 bytes)
pub const ELECRYPTO_AES_TAG_SIZE: c_uint = 16;

/// ChaCha20-Poly1305 key size (32 bytes)
pub const ELECRYPTO_CHACHA20_KEY_SIZE: c_uint = 32;
/// ChaCha20-Poly1305 nonce size (12 bytes)
pub const ELECRYPTO_CHACHA20_NONCE_SIZE: c_uint = 12;

/// Ed25519 public key size (32 bytes)
pub const ELECRYPTO_ED25519_PUBLIC_KEY_SIZE: c_uint = 32;
/// Ed25519 secret key size (64 bytes)
pub const ELECRYPTO_ED25519_SECRET_KEY_SIZE: c_uint = 32;
/// Ed25519 signature size (64 bytes)
pub const ELECRYPTO_ED25519_SIGNATURE_SIZE: c_uint = 64;

/// Generate random bytes
///
/// # Safety
///
/// Caller must ensure `output` points to valid memory of at least `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn elecrypto_random_bytes(
    output: *mut c_uchar,
    length: c_uint,
) -> c_int {
    if output.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let bytes = random_bytes(length as usize);
    ptr::copy_nonoverlapping(bytes.as_ptr(), output, length as usize);

    ELECRYPTO_SUCCESS
}

/// Compute SHA-256 hash
///
/// # Safety
///
/// - `input` must point to valid memory of at least `input_len` bytes
/// - `output` must point to valid memory of at least 32 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_sha256(
    input: *const c_uchar,
    input_len: c_uint,
    output: *mut c_uchar,
) -> c_int {
    if input.is_null() || output.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let input_slice = slice::from_raw_parts(input, input_len as usize);
    let hash = sha256(input_slice);

    ptr::copy_nonoverlapping(hash.as_ptr(), output, 32);

    ELECRYPTO_SUCCESS
}

/// Compute SHA-512 hash
///
/// # Safety
///
/// - `input` must point to valid memory of at least `input_len` bytes
/// - `output` must point to valid memory of at least 64 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_sha512(
    input: *const c_uchar,
    input_len: c_uint,
    output: *mut c_uchar,
) -> c_int {
    if input.is_null() || output.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let input_slice = slice::from_raw_parts(input, input_len as usize);
    let hash = sha512(input_slice);

    ptr::copy_nonoverlapping(hash.as_ptr(), output, 64);

    ELECRYPTO_SUCCESS
}

/// Generate AES-256 key
///
/// # Safety
///
/// `output` must point to valid memory of at least 32 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_aes_generate_key(output: *mut c_uchar) -> c_int {
    if output.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let key = aes_generate_key();
    ptr::copy_nonoverlapping(key.as_ptr(), output, 32);

    ELECRYPTO_SUCCESS
}

/// Encrypt with AES-256-GCM
///
/// # Safety
///
/// - `plaintext` must point to valid memory of `plaintext_len` bytes
/// - `key` must point to valid memory of 32 bytes
/// - `nonce` must point to valid memory of 12 bytes (can be NULL to auto-generate)
/// - `ciphertext` must point to valid memory of at least `plaintext_len + 16` bytes
/// - `nonce_out` must point to valid memory of 12 bytes (receives used nonce)
///
/// Returns number of ciphertext bytes written (plaintext_len + 16), or negative error code
#[no_mangle]
pub unsafe extern "C" fn elecrypto_aes_gcm_encrypt(
    plaintext: *const c_uchar,
    plaintext_len: c_uint,
    key: *const c_uchar,
    nonce: *const c_uchar,
    ciphertext: *mut c_uchar,
    nonce_out: *mut c_uchar,
) -> c_int {
    if plaintext.is_null() || key.is_null() || ciphertext.is_null() || nonce_out.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len as usize);
    let key_slice = slice::from_raw_parts(key, 32);

    let nonce_option = if nonce.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(nonce, 12))
    };

    match aes_gcm_encrypt(plaintext_slice, key_slice, nonce_option, None) {
        Ok((ct, nonce_used)) => {
            ptr::copy_nonoverlapping(ct.as_ptr(), ciphertext, ct.len());
            ptr::copy_nonoverlapping(nonce_used.as_ptr(), nonce_out, 12);
            ct.len() as c_int
        }
        Err(_) => ELECRYPTO_ERROR_ENCRYPTION_FAILED,
    }
}

/// Decrypt with AES-256-GCM
///
/// # Safety
///
/// - `ciphertext` must point to valid memory of `ciphertext_len` bytes (includes 16-byte tag)
/// - `key` must point to valid memory of 32 bytes
/// - `nonce` must point to valid memory of 12 bytes
/// - `plaintext` must point to valid memory of at least `ciphertext_len - 16` bytes
///
/// Returns number of plaintext bytes written, or negative error code
#[no_mangle]
pub unsafe extern "C" fn elecrypto_aes_gcm_decrypt(
    ciphertext: *const c_uchar,
    ciphertext_len: c_uint,
    key: *const c_uchar,
    nonce: *const c_uchar,
    plaintext: *mut c_uchar,
) -> c_int {
    if ciphertext.is_null() || key.is_null() || nonce.is_null() || plaintext.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len as usize);
    let key_slice = slice::from_raw_parts(key, 32);
    let nonce_slice = slice::from_raw_parts(nonce, 12);

    match aes_gcm_decrypt(ciphertext_slice, key_slice, nonce_slice, None) {
        Ok(pt) => {
            ptr::copy_nonoverlapping(pt.as_ptr(), plaintext, pt.len());
            pt.len() as c_int
        }
        Err(_) => ELECRYPTO_ERROR_DECRYPTION_FAILED,
    }
}

/// Generate ChaCha20-Poly1305 key
///
/// # Safety
///
/// `output` must point to valid memory of at least 32 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_chacha20_generate_key(output: *mut c_uchar) -> c_int {
    if output.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let key = chacha20_generate_key();
    ptr::copy_nonoverlapping(key.as_ptr(), output, 32);

    ELECRYPTO_SUCCESS
}

/// Encrypt with ChaCha20-Poly1305
///
/// # Safety
///
/// Similar safety requirements to AES-GCM encrypt
#[no_mangle]
pub unsafe extern "C" fn elecrypto_chacha20_poly1305_encrypt(
    plaintext: *const c_uchar,
    plaintext_len: c_uint,
    key: *const c_uchar,
    nonce: *const c_uchar,
    ciphertext: *mut c_uchar,
    nonce_out: *mut c_uchar,
) -> c_int {
    if plaintext.is_null() || key.is_null() || ciphertext.is_null() || nonce_out.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len as usize);
    let key_slice = slice::from_raw_parts(key, 32);

    let nonce_option = if nonce.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(nonce, 12))
    };

    match chacha20_poly1305_encrypt(plaintext_slice, key_slice, nonce_option, None) {
        Ok((ct, nonce_used)) => {
            ptr::copy_nonoverlapping(ct.as_ptr(), ciphertext, ct.len());
            ptr::copy_nonoverlapping(nonce_used.as_ptr(), nonce_out, 12);
            ct.len() as c_int
        }
        Err(_) => ELECRYPTO_ERROR_ENCRYPTION_FAILED,
    }
}

/// Decrypt with ChaCha20-Poly1305
///
/// # Safety
///
/// Similar safety requirements to AES-GCM decrypt
#[no_mangle]
pub unsafe extern "C" fn elecrypto_chacha20_poly1305_decrypt(
    ciphertext: *const c_uchar,
    ciphertext_len: c_uint,
    key: *const c_uchar,
    nonce: *const c_uchar,
    plaintext: *mut c_uchar,
) -> c_int {
    if ciphertext.is_null() || key.is_null() || nonce.is_null() || plaintext.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len as usize);
    let key_slice = slice::from_raw_parts(key, 32);
    let nonce_slice = slice::from_raw_parts(nonce, 12);

    match chacha20_poly1305_decrypt(ciphertext_slice, key_slice, nonce_slice, None) {
        Ok(pt) => {
            ptr::copy_nonoverlapping(pt.as_ptr(), plaintext, pt.len());
            pt.len() as c_int
        }
        Err(_) => ELECRYPTO_ERROR_DECRYPTION_FAILED,
    }
}

/// Compute SHA3-256 hash
///
/// # Safety
///
/// - `input` must point to valid memory of at least `input_len` bytes
/// - `output` must point to valid memory of at least 32 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_sha3_256(
    input: *const c_uchar,
    input_len: c_uint,
    output: *mut c_uchar,
) -> c_int {
    if input.is_null() || output.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let input_slice = slice::from_raw_parts(input, input_len as usize);
    let hash = sha3_256(input_slice);

    ptr::copy_nonoverlapping(hash.as_ptr(), output, 32);

    ELECRYPTO_SUCCESS
}

/// Compute BLAKE3 hash
///
/// # Safety
///
/// - `input` must point to valid memory of at least `input_len` bytes
/// - `output` must point to valid memory of at least `output_len` bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_blake3(
    input: *const c_uchar,
    input_len: c_uint,
    output: *mut c_uchar,
    output_len: c_uint,
) -> c_int {
    if input.is_null() || output.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let input_slice = slice::from_raw_parts(input, input_len as usize);
    let hash = blake3_hash(input_slice, output_len as usize);

    ptr::copy_nonoverlapping(hash.as_ptr(), output, output_len as usize);

    ELECRYPTO_SUCCESS
}

/// Generate Ed25519 keypair
///
/// # Safety
///
/// - `public_key` must point to valid memory of at least 32 bytes
/// - `secret_key` must point to valid memory of at least 64 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_ed25519_generate_keypair(
    public_key: *mut c_uchar,
    secret_key: *mut c_uchar,
) -> c_int {
    if public_key.is_null() || secret_key.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let (pk, sk) = ed25519_generate_keypair();
    ptr::copy_nonoverlapping(pk.as_ptr(), public_key, 32);
    ptr::copy_nonoverlapping(sk.as_ptr(), secret_key, 64);

    ELECRYPTO_SUCCESS
}

/// Sign message with Ed25519
///
/// # Safety
///
/// - `message` must point to valid memory of `message_len` bytes
/// - `secret_key` must point to valid memory of 64 bytes
/// - `signature` must point to valid memory of at least 64 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_ed25519_sign(
    message: *const c_uchar,
    message_len: c_uint,
    secret_key: *const c_uchar,
    signature: *mut c_uchar,
) -> c_int {
    if message.is_null() || secret_key.is_null() || signature.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let message_slice = slice::from_raw_parts(message, message_len as usize);
    let sk_slice = slice::from_raw_parts(secret_key, 32);

    match ed25519_sign(message_slice, sk_slice) {
        Ok(sig) => {
            ptr::copy_nonoverlapping(sig.as_ptr(), signature, 64);
            ELECRYPTO_SUCCESS
        }
        Err(_) => ELECRYPTO_ERROR_SIGNING_FAILED,
    }
}

/// Verify Ed25519 signature
///
/// # Safety
///
/// - `message` must point to valid memory of `message_len` bytes
/// - `signature` must point to valid memory of 64 bytes
/// - `public_key` must point to valid memory of 32 bytes
///
/// Returns 1 if valid, 0 if invalid, negative on error
#[no_mangle]
pub unsafe extern "C" fn elecrypto_ed25519_verify(
    message: *const c_uchar,
    message_len: c_uint,
    signature: *const c_uchar,
    public_key: *const c_uchar,
) -> c_int {
    if message.is_null() || signature.is_null() || public_key.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let message_slice = slice::from_raw_parts(message, message_len as usize);
    let sig_slice = slice::from_raw_parts(signature, 64);
    let pk_slice = slice::from_raw_parts(public_key, 32);

    match ed25519_verify(message_slice, sig_slice, pk_slice) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => ELECRYPTO_ERROR_VERIFICATION_FAILED,
    }
}

/// PBKDF2 key derivation
///
/// # Safety
///
/// - `password` must point to valid memory of `password_len` bytes
/// - `salt` must point to valid memory of `salt_len` bytes
/// - `output` must point to valid memory of `output_len` bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_pbkdf2(
    password: *const c_uchar,
    password_len: c_uint,
    salt: *const c_uchar,
    salt_len: c_uint,
    iterations: c_uint,
    output: *mut c_uchar,
    output_len: c_uint,
) -> c_int {
    if password.is_null() || salt.is_null() || output.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let password_slice = slice::from_raw_parts(password, password_len as usize);
    let salt_slice = slice::from_raw_parts(salt, salt_len as usize);

    match pbkdf2(
        password_slice,
        Some(salt_slice),
        Some(iterations),
        Some(output_len as usize),
    ) {
        Ok((key, _)) => {
            ptr::copy_nonoverlapping(key.as_ptr(), output, output_len as usize);
            ELECRYPTO_SUCCESS
        }
        Err(_) => ELECRYPTO_ERROR_ENCRYPTION_FAILED,
    }
}

/// Argon2id key derivation
///
/// # Safety
///
/// - `password` must point to valid memory of `password_len` bytes
/// - `salt` must point to valid memory of 16 bytes (can be NULL to auto-generate)
/// - `output` must point to valid memory of `output_len` bytes
/// - `salt_out` must point to valid memory of 16 bytes (receives used salt)
#[no_mangle]
pub unsafe extern "C" fn elecrypto_argon2id(
    password: *const c_uchar,
    password_len: c_uint,
    salt: *const c_uchar,
    memory_cost: c_uint,
    time_cost: c_uint,
    parallelism: c_uint,
    output: *mut c_uchar,
    output_len: c_uint,
    salt_out: *mut c_uchar,
) -> c_int {
    if password.is_null() || output.is_null() || salt_out.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let password_slice = slice::from_raw_parts(password, password_len as usize);

    let salt_option = if salt.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(salt, 16))
    };

    match argon2id(
        password_slice,
        salt_option,
        Some(memory_cost),
        Some(time_cost),
        Some(parallelism),
        Some(output_len as usize),
    ) {
        Ok((key, salt_used)) => {
            ptr::copy_nonoverlapping(key.as_ptr(), output, output_len as usize);
            ptr::copy_nonoverlapping(salt_used.as_ptr(), salt_out, 16);
            ELECRYPTO_SUCCESS
        }
        Err(_) => ELECRYPTO_ERROR_ENCRYPTION_FAILED,
    }
}

/// HKDF key derivation
///
/// # Safety
///
/// - `input_key_material` must point to valid memory of `ikm_len` bytes
/// - `salt` can be NULL (optional)
/// - `info` can be NULL (optional)
/// - `output` must point to valid memory of `output_len` bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_hkdf(
    input_key_material: *const c_uchar,
    ikm_len: c_uint,
    salt: *const c_uchar,
    salt_len: c_uint,
    info: *const c_uchar,
    info_len: c_uint,
    output: *mut c_uchar,
    output_len: c_uint,
) -> c_int {
    if input_key_material.is_null() || output.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let ikm_slice = slice::from_raw_parts(input_key_material, ikm_len as usize);

    let salt_option = if salt.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(salt, salt_len as usize))
    };

    let info_option = if info.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(info, info_len as usize))
    };

    match hkdf_derive(ikm_slice, salt_option, info_option, Some(output_len as usize)) {
        Ok(key) => {
            ptr::copy_nonoverlapping(key.as_ptr(), output, output_len as usize);
            ELECRYPTO_SUCCESS
        }
        Err(_) => ELECRYPTO_ERROR_ENCRYPTION_FAILED,
    }
}

// =============================================================================
// RSA-OAEP Functions
// =============================================================================

/// Generate RSA-2048 keypair
///
/// # Safety
///
/// - `public_key` must point to valid memory of at least 294 bytes
/// - `public_key_len` must point to valid memory
/// - `private_key` must point to valid memory of at least 1218 bytes
/// - `private_key_len` must point to valid memory
#[no_mangle]
pub unsafe extern "C" fn elecrypto_rsa_generate_keypair_2048(
    public_key: *mut c_uchar,
    public_key_len: *mut c_uint,
    private_key: *mut c_uchar,
    private_key_len: *mut c_uint,
) -> c_int {
    if public_key.is_null() || public_key_len.is_null() ||
       private_key.is_null() || private_key_len.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    match rsa_generate_keypair(RsaKeySize::Rsa2048) {
        Ok((pk, sk)) => {
            match (rsa_public_key_to_der(&pk), rsa_private_key_to_der(&sk)) {
                (Ok(pk_der), Ok(sk_der)) => {
                    ptr::copy_nonoverlapping(pk_der.as_ptr(), public_key, pk_der.len());
                    *public_key_len = pk_der.len() as c_uint;
                    ptr::copy_nonoverlapping(sk_der.as_ptr(), private_key, sk_der.len());
                    *private_key_len = sk_der.len() as c_uint;
                    ELECRYPTO_SUCCESS
                }
                _ => ELECRYPTO_ERROR_ENCODING_FAILED,
            }
        }
        Err(_) => ELECRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}

/// Encrypt with RSA-OAEP
///
/// # Safety
///
/// - `plaintext` must point to valid memory of `plaintext_len` bytes
/// - `public_key` must point to valid memory of `public_key_len` bytes (DER format)
/// - `ciphertext` must point to valid memory of at least 256 bytes (for RSA-2048)
#[no_mangle]
pub unsafe extern "C" fn elecrypto_rsa_encrypt(
    plaintext: *const c_uchar,
    plaintext_len: c_uint,
    public_key: *const c_uchar,
    public_key_len: c_uint,
    ciphertext: *mut c_uchar,
) -> c_int {
    if plaintext.is_null() || public_key.is_null() || ciphertext.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len as usize);
    let pk_slice = slice::from_raw_parts(public_key, public_key_len as usize);

    match rsa_public_key_from_der(pk_slice) {
        Ok(pk) => {
            match rsa_encrypt(plaintext_slice, &pk) {
                Ok(ct) => {
                    ptr::copy_nonoverlapping(ct.as_ptr(), ciphertext, ct.len());
                    ct.len() as c_int
                }
                Err(_) => ELECRYPTO_ERROR_ENCRYPTION_FAILED,
            }
        }
        Err(_) => ELECRYPTO_ERROR_INVALID_PUBLIC_KEY,
    }
}

/// Decrypt with RSA-OAEP
///
/// # Safety
///
/// - `ciphertext` must point to valid memory of `ciphertext_len` bytes
/// - `private_key` must point to valid memory of `private_key_len` bytes (DER format)
/// - `plaintext` must point to valid memory of at least 256 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_rsa_decrypt(
    ciphertext: *const c_uchar,
    ciphertext_len: c_uint,
    private_key: *const c_uchar,
    private_key_len: c_uint,
    plaintext: *mut c_uchar,
) -> c_int {
    if ciphertext.is_null() || private_key.is_null() || plaintext.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let ct_slice = slice::from_raw_parts(ciphertext, ciphertext_len as usize);
    let sk_slice = slice::from_raw_parts(private_key, private_key_len as usize);

    match rsa_private_key_from_der(sk_slice) {
        Ok(sk) => {
            match rsa_decrypt(ct_slice, &sk) {
                Ok(pt) => {
                    ptr::copy_nonoverlapping(pt.as_ptr(), plaintext, pt.len());
                    pt.len() as c_int
                }
                Err(_) => ELECRYPTO_ERROR_DECRYPTION_FAILED,
            }
        }
        Err(_) => ELECRYPTO_ERROR_INVALID_PRIVATE_KEY,
    }
}

// =============================================================================
// ECIES Functions
// =============================================================================

/// Generate ECIES keypair (P-256)
///
/// # Safety
///
/// - `public_key` must point to valid memory of at least 65 bytes
/// - `private_key` must point to valid memory of at least 32 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_ecies_generate_keypair(
    public_key: *mut c_uchar,
    private_key: *mut c_uchar,
) -> c_int {
    if public_key.is_null() || private_key.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    match ecies_generate_keypair() {
        Ok((pk, sk)) => {
            let pk_bytes = ecies_public_key_to_bytes(&pk);
            let sk_bytes = ecies_private_key_to_bytes(&sk);

            ptr::copy_nonoverlapping(pk_bytes.as_ptr(), public_key, pk_bytes.len());
            ptr::copy_nonoverlapping(sk_bytes.as_ptr(), private_key, sk_bytes.len());
            ELECRYPTO_SUCCESS
        }
        Err(_) => ELECRYPTO_ERROR_KEY_GENERATION_FAILED,
    }
}

/// Encrypt with ECIES
///
/// Returns ciphertext length (65 + plaintext_len + 16 + 12)
///
/// # Safety
///
/// - `plaintext` must point to valid memory of `plaintext_len` bytes
/// - `public_key` must point to valid memory of 65 bytes
/// - `ciphertext` must point to valid memory of at least `plaintext_len + 93` bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_ecies_encrypt(
    plaintext: *const c_uchar,
    plaintext_len: c_uint,
    public_key: *const c_uchar,
    ciphertext: *mut c_uchar,
) -> c_int {
    if plaintext.is_null() || public_key.is_null() || ciphertext.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len as usize);
    let pk_slice = slice::from_raw_parts(public_key, 65);

    match ecies_public_key_from_bytes(pk_slice) {
        Ok(pk) => {
            match ecies_encrypt(plaintext_slice, &pk) {
                Ok(ct) => {
                    ptr::copy_nonoverlapping(ct.as_ptr(), ciphertext, ct.len());
                    ct.len() as c_int
                }
                Err(_) => ELECRYPTO_ERROR_ENCRYPTION_FAILED,
            }
        }
        Err(_) => ELECRYPTO_ERROR_INVALID_PUBLIC_KEY,
    }
}

/// Decrypt with ECIES
///
/// # Safety
///
/// - `ciphertext` must point to valid memory of `ciphertext_len` bytes
/// - `private_key` must point to valid memory of 32 bytes
/// - `plaintext` must point to valid memory of at least `ciphertext_len - 93` bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_ecies_decrypt(
    ciphertext: *const c_uchar,
    ciphertext_len: c_uint,
    private_key: *const c_uchar,
    plaintext: *mut c_uchar,
) -> c_int {
    if ciphertext.is_null() || private_key.is_null() || plaintext.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let ct_slice = slice::from_raw_parts(ciphertext, ciphertext_len as usize);
    let sk_slice = slice::from_raw_parts(private_key, 32);

    match ecies_private_key_from_bytes(sk_slice) {
        Ok(sk) => {
            match ecies_decrypt(ct_slice, &sk) {
                Ok(pt) => {
                    ptr::copy_nonoverlapping(pt.as_ptr(), plaintext, pt.len());
                    pt.len() as c_int
                }
                Err(_) => ELECRYPTO_ERROR_DECRYPTION_FAILED,
            }
        }
        Err(_) => ELECRYPTO_ERROR_INVALID_PRIVATE_KEY,
    }
}

// =============================================================================
// DRBG Functions (using opaque handles)
// =============================================================================

/// Create HMAC-DRBG instance
///
/// Returns handle (positive) or error (negative)
///
/// # Safety
///
/// - `entropy` must point to valid memory of at least 32 bytes
/// - `nonce` must point to valid memory of at least 16 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_hmac_drbg_generate(
    entropy: *const c_uchar,
    entropy_len: c_uint,
    nonce: *const c_uchar,
    nonce_len: c_uint,
    output: *mut c_uchar,
    output_len: c_uint,
) -> c_int {
    if entropy.is_null() || nonce.is_null() || output.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let entropy_slice = slice::from_raw_parts(entropy, entropy_len as usize);
    let nonce_slice = slice::from_raw_parts(nonce, nonce_len as usize);

    match HmacDrbg::instantiate(entropy_slice, nonce_slice, None) {
        Ok(mut drbg) => {
            let mut out_vec = vec![0u8; output_len as usize];
            match drbg.generate(&mut out_vec, None) {
                Ok(()) => {
                    ptr::copy_nonoverlapping(out_vec.as_ptr(), output, output_len as usize);
                    ELECRYPTO_SUCCESS
                }
                Err(_) => ELECRYPTO_ERROR_KEY_DERIVATION_FAILED,
            }
        }
        Err(_) => ELECRYPTO_ERROR_INVALID_INPUT,
    }
}

/// Generate random bytes using CTR-DRBG
#[no_mangle]
pub unsafe extern "C" fn elecrypto_ctr_drbg_generate(
    entropy: *const c_uchar,
    entropy_len: c_uint,
    nonce: *const c_uchar,
    nonce_len: c_uint,
    output: *mut c_uchar,
    output_len: c_uint,
) -> c_int {
    if entropy.is_null() || nonce.is_null() || output.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let entropy_slice = slice::from_raw_parts(entropy, entropy_len as usize);
    let nonce_slice = slice::from_raw_parts(nonce, nonce_len as usize);

    match CtrDrbg::instantiate(entropy_slice, nonce_slice, None) {
        Ok(mut drbg) => {
            let mut out_vec = vec![0u8; output_len as usize];
            match drbg.generate(&mut out_vec, None) {
                Ok(()) => {
                    ptr::copy_nonoverlapping(out_vec.as_ptr(), output, output_len as usize);
                    ELECRYPTO_SUCCESS
                }
                Err(_) => ELECRYPTO_ERROR_KEY_DERIVATION_FAILED,
            }
        }
        Err(_) => ELECRYPTO_ERROR_INVALID_INPUT,
    }
}

// =============================================================================
// Post-Quantum Cryptography Functions
// =============================================================================

/// Generate Kyber512 keypair
///
/// # Safety
///
/// - `public_key` must point to valid memory of at least 800 bytes
/// - `secret_key` must point to valid memory of at least 1632 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_kyber512_generate_keypair(
    public_key: *mut c_uchar,
    secret_key: *mut c_uchar,
) -> c_int {
    if public_key.is_null() || secret_key.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let (pk, sk) = kyber512_keypair();
    ptr::copy_nonoverlapping(pk.as_ptr(), public_key, pk.len());
    ptr::copy_nonoverlapping(sk.as_ptr(), secret_key, sk.len());
    ELECRYPTO_SUCCESS
}

/// Kyber512 encapsulation
///
/// # Safety
///
/// - `public_key` must point to valid memory of 800 bytes
/// - `ciphertext` must point to valid memory of at least 768 bytes
/// - `shared_secret` must point to valid memory of at least 32 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_kyber512_encapsulate(
    public_key: *const c_uchar,
    ciphertext: *mut c_uchar,
    shared_secret: *mut c_uchar,
) -> c_int {
    if public_key.is_null() || ciphertext.is_null() || shared_secret.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let pk_slice = slice::from_raw_parts(public_key, 800);

    match kyber512_encapsulate(pk_slice) {
        Ok((ct, ss)) => {
            ptr::copy_nonoverlapping(ct.as_ptr(), ciphertext, ct.len());
            ptr::copy_nonoverlapping(ss.as_ptr(), shared_secret, ss.len());
            ELECRYPTO_SUCCESS
        }
        Err(_) => ELECRYPTO_ERROR_ENCRYPTION_FAILED,
    }
}

/// Kyber512 decapsulation
///
/// # Safety
///
/// - `ciphertext` must point to valid memory of 768 bytes
/// - `secret_key` must point to valid memory of 1632 bytes
/// - `shared_secret` must point to valid memory of at least 32 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_kyber512_decapsulate(
    ciphertext: *const c_uchar,
    secret_key: *const c_uchar,
    shared_secret: *mut c_uchar,
) -> c_int {
    if ciphertext.is_null() || secret_key.is_null() || shared_secret.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let ct_slice = slice::from_raw_parts(ciphertext, 768);
    let sk_slice = slice::from_raw_parts(secret_key, 1632);

    match kyber512_decapsulate(ct_slice, sk_slice) {
        Ok(ss) => {
            ptr::copy_nonoverlapping(ss.as_ptr(), shared_secret, ss.len());
            ELECRYPTO_SUCCESS
        }
        Err(_) => ELECRYPTO_ERROR_DECRYPTION_FAILED,
    }
}

/// Generate Dilithium2 keypair
///
/// # Safety
///
/// - `public_key` must point to valid memory of at least 1312 bytes
/// - `secret_key` must point to valid memory of at least 2560 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_dilithium2_generate_keypair(
    public_key: *mut c_uchar,
    secret_key: *mut c_uchar,
) -> c_int {
    if public_key.is_null() || secret_key.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let (pk, sk) = dilithium2_keypair();
    ptr::copy_nonoverlapping(pk.as_ptr(), public_key, pk.len());
    ptr::copy_nonoverlapping(sk.as_ptr(), secret_key, sk.len());
    ELECRYPTO_SUCCESS
}

/// Sign with Dilithium2
///
/// # Safety
///
/// - `message` must point to valid memory of `message_len` bytes
/// - `secret_key` must point to valid memory of 2560 bytes
/// - `signature` must point to valid memory of at least 2420 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_dilithium2_sign(
    message: *const c_uchar,
    message_len: c_uint,
    secret_key: *const c_uchar,
    signature: *mut c_uchar,
) -> c_int {
    if message.is_null() || secret_key.is_null() || signature.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let msg_slice = slice::from_raw_parts(message, message_len as usize);
    let sk_slice = slice::from_raw_parts(secret_key, 2560);

    match dilithium2_sign(msg_slice, sk_slice) {
        Ok(sig) => {
            ptr::copy_nonoverlapping(sig.as_ptr(), signature, sig.len());
            sig.len() as c_int
        }
        Err(_) => ELECRYPTO_ERROR_SIGNING_FAILED,
    }
}

/// Verify Dilithium2 signature
///
/// Returns 1 if valid, 0 if invalid, negative on error
///
/// # Safety
///
/// - `message` must point to valid memory of `message_len` bytes
/// - `signature` must point to valid memory of `signature_len` bytes
/// - `public_key` must point to valid memory of 1312 bytes
#[no_mangle]
pub unsafe extern "C" fn elecrypto_dilithium2_verify(
    message: *const c_uchar,
    message_len: c_uint,
    signature: *const c_uchar,
    signature_len: c_uint,
    public_key: *const c_uchar,
) -> c_int {
    if message.is_null() || signature.is_null() || public_key.is_null() {
        return ELECRYPTO_ERROR_INVALID_INPUT;
    }

    let msg_slice = slice::from_raw_parts(message, message_len as usize);
    let sig_slice = slice::from_raw_parts(signature, signature_len as usize);
    let pk_slice = slice::from_raw_parts(public_key, 1312);

    match dilithium2_verify(msg_slice, sig_slice, pk_slice) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => ELECRYPTO_ERROR_VERIFICATION_FAILED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_random_bytes() {
        let mut output = [0u8; 32];
        let result = unsafe { elecrypto_random_bytes(output.as_mut_ptr(), 32) };

        assert_eq!(result, ELECRYPTO_SUCCESS);

        // Check that output is not all zeros
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_ffi_sha256() {
        let input = b"Hello, World!";
        let mut output = [0u8; 32];

        let result = unsafe {
            elecrypto_sha256(input.as_ptr(), input.len() as c_uint, output.as_mut_ptr())
        };

        assert_eq!(result, ELECRYPTO_SUCCESS);
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_ffi_sha512() {
        let input = b"Hello, World!";
        let mut output = [0u8; 64];

        let result = unsafe {
            elecrypto_sha512(input.as_ptr(), input.len() as c_uint, output.as_mut_ptr())
        };

        assert_eq!(result, ELECRYPTO_SUCCESS);
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_ffi_null_pointer() {
        let result = unsafe { elecrypto_random_bytes(ptr::null_mut(), 32) };
        assert_eq!(result, ELECRYPTO_ERROR_INVALID_INPUT);
    }
}
