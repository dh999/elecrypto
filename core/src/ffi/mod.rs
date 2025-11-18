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

use crate::hash::{sha256, sha512};
use crate::random::random_bytes;

/// Success return code
pub const ELECRYPTO_SUCCESS: c_int = 0;

/// Error codes (negative values)
pub const ELECRYPTO_ERROR_INVALID_INPUT: c_int = -1;
pub const ELECRYPTO_ERROR_INVALID_KEY_LENGTH: c_int = -2;
pub const ELECRYPTO_ERROR_INVALID_NONCE_LENGTH: c_int = -3;
pub const ELECRYPTO_ERROR_AUTHENTICATION_FAILED: c_int = -4;
pub const ELECRYPTO_ERROR_ENCRYPTION_FAILED: c_int = -5;
pub const ELECRYPTO_ERROR_DECRYPTION_FAILED: c_int = -6;

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

// Note: More FFI functions will be added for:
// - AES-GCM encrypt/decrypt
// - ChaCha20-Poly1305 encrypt/decrypt
// - KDF functions
// - Signing functions
//
// These will require more complex memory management and will be implemented
// in subsequent iterations.

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
