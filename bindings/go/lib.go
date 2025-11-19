// Package elecrypto provides Go bindings for the Elecrypto cryptographic library
package elecrypto

/*
#cgo LDFLAGS: -L../../core/target/release -lelecrypto_core
#cgo CFLAGS: -I../../bindings/c/include
#include <elecrypto.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

// Error codes
const (
	Success                  = 0
	ErrorInvalidInput        = -1
	ErrorInvalidKeyLength    = -2
	ErrorInvalidNonceLength  = -3
	ErrorAuthenticationFailed = -4
	ErrorEncryptionFailed    = -5
	ErrorDecryptionFailed    = -6
	ErrorSigningFailed       = -7
	ErrorVerificationFailed  = -8
)

// Constants
const (
	AESKeySize           = 32
	AESNonceSize         = 12
	AESTagSize           = 16
	ChaCha20KeySize      = 32
	ChaCha20NonceSize    = 12
	Ed25519PublicKeySize = 32
	Ed25519SecretKeySize = 32
	Ed25519SignatureSize = 64

	// RSA constants
	RSA2048PublicKeySize  = 294
	RSA2048PrivateKeySize = 1218

	// ECIES constants
	ECIESPublicKeySize  = 65
	ECIESPrivateKeySize = 32

	// Kyber constants
	Kyber512PublicKeySize    = 800
	Kyber512SecretKeySize    = 1632
	Kyber512CiphertextSize   = 768
	Kyber512SharedSecretSize = 32

	// Dilithium constants
	Dilithium2PublicKeySize  = 1312
	Dilithium2SecretKeySize  = 2560
	Dilithium2SignatureSize  = 2420
)

// Error represents an Elecrypto error
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

// checkResult converts C return codes to Go errors
func checkResult(code C.int) error {
	if code >= 0 {
		return nil
	}

	errorMessages := map[int]string{
		ErrorInvalidInput:        "invalid input",
		ErrorInvalidKeyLength:    "invalid key length",
		ErrorInvalidNonceLength:  "invalid nonce length",
		ErrorAuthenticationFailed: "authentication failed",
		ErrorEncryptionFailed:    "encryption failed",
		ErrorDecryptionFailed:    "decryption failed",
		ErrorSigningFailed:       "signing failed",
		ErrorVerificationFailed:  "verification failed",
	}

	msg, ok := errorMessages[int(code)]
	if !ok {
		msg = "unknown error"
	}

	return &Error{
		Code:    int(code),
		Message: msg,
	}
}

// Helper functions for C interop
func bytesToC(data []byte) (*C.uchar, C.uint) {
	if len(data) == 0 {
		return nil, 0
	}
	return (*C.uchar)(unsafe.Pointer(&data[0])), C.uint(len(data))
}

func cToBytes(ptr *C.uchar, length int) []byte {
	if ptr == nil || length == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length))
}
