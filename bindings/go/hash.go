package elecrypto

/*
#include <elecrypto.h>
#include <stdlib.h>
*/
import "C"
import "unsafe"

// SHA256 computes the SHA-256 hash of the input data
func SHA256(data []byte) ([]byte, error) {
	hash := make([]byte, 32)
	dataPtr, dataLen := bytesToC(data)

	result := C.elecrypto_sha256(
		dataPtr,
		dataLen,
		(*C.uchar)(unsafe.Pointer(&hash[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return hash, nil
}

// SHA512 computes the SHA-512 hash of the input data
func SHA512(data []byte) ([]byte, error) {
	hash := make([]byte, 64)
	dataPtr, dataLen := bytesToC(data)

	result := C.elecrypto_sha512(
		dataPtr,
		dataLen,
		(*C.uchar)(unsafe.Pointer(&hash[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return hash, nil
}

// SHA3_256 computes the SHA3-256 hash of the input data
func SHA3_256(data []byte) ([]byte, error) {
	hash := make([]byte, 32)
	dataPtr, dataLen := bytesToC(data)

	result := C.elecrypto_sha3_256(
		dataPtr,
		dataLen,
		(*C.uchar)(unsafe.Pointer(&hash[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return hash, nil
}

// BLAKE3 computes the BLAKE3 hash of the input data with custom output length
func BLAKE3(data []byte, outputLength int) ([]byte, error) {
	if outputLength <= 0 {
		outputLength = 32
	}

	hash := make([]byte, outputLength)
	dataPtr, dataLen := bytesToC(data)

	result := C.elecrypto_blake3(
		dataPtr,
		dataLen,
		(*C.uchar)(unsafe.Pointer(&hash[0])),
		C.uint(outputLength),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return hash, nil
}
