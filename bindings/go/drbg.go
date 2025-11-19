package elecrypto

/*
#include <elecrypto.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

// HMACDRBGGenerate generates random bytes using HMAC-DRBG (NIST SP 800-90A)
func HMACDRBGGenerate(seed []byte, outputLen int) ([]byte, error) {
	if len(seed) == 0 {
		return nil, errors.New("seed cannot be empty")
	}
	if outputLen < 1 {
		return nil, errors.New("output length must be at least 1")
	}

	output := make([]byte, outputLen)

	result := C.elecrypto_hmac_drbg_generate(
		(*C.uchar)(unsafe.Pointer(&seed[0])),
		C.uint(len(seed)),
		(*C.uchar)(unsafe.Pointer(&output[0])),
		C.uint(outputLen),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return output, nil
}

// CTRDRBGGenerate generates random bytes using CTR-DRBG (NIST SP 800-90A)
func CTRDRBGGenerate(seed []byte, outputLen int) ([]byte, error) {
	if len(seed) < 48 {
		return nil, errors.New("seed must be at least 48 bytes for CTR-DRBG")
	}
	if outputLen < 1 {
		return nil, errors.New("output length must be at least 1")
	}

	output := make([]byte, outputLen)

	result := C.elecrypto_ctr_drbg_generate(
		(*C.uchar)(unsafe.Pointer(&seed[0])),
		C.uint(len(seed)),
		(*C.uchar)(unsafe.Pointer(&output[0])),
		C.uint(outputLen),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return output, nil
}
