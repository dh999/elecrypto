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
