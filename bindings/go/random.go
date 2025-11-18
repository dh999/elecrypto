package elecrypto

/*
#include <elecrypto.h>
*/
import "C"
import "unsafe"

// RandomBytes generates cryptographically secure random bytes
func RandomBytes(length int) ([]byte, error) {
	if length < 0 {
		return nil, &Error{Code: ErrorInvalidInput, Message: "length must be non-negative"}
	}

	output := make([]byte, length)
	if length == 0 {
		return output, nil
	}

	result := C.elecrypto_random_bytes(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		C.uint(length),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return output, nil
}
