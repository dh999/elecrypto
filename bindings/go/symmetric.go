package elecrypto

/*
#include <elecrypto.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

// EncryptResult contains the ciphertext and nonce from encryption
type EncryptResult struct {
	Ciphertext []byte
	Nonce      []byte
}

// AESGenerateKey generates a random AES-256 key
func AESGenerateKey() ([]byte, error) {
	key := make([]byte, AESKeySize)

	result := C.elecrypto_aes_generate_key(
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return key, nil
}

// AESGCMEncrypt encrypts data using AES-256-GCM
func AESGCMEncrypt(plaintext, key []byte, nonce []byte) (*EncryptResult, error) {
	if len(key) != AESKeySize {
		return nil, errors.New("key must be 32 bytes")
	}

	if nonce != nil && len(nonce) != AESNonceSize {
		return nil, errors.New("nonce must be 12 bytes if provided")
	}

	ciphertext := make([]byte, len(plaintext)+AESTagSize)
	nonceOut := make([]byte, AESNonceSize)

	plaintextPtr, plaintextLen := bytesToC(plaintext)
	keyPtr, _ := bytesToC(key)

	var noncePtr *C.uchar
	if nonce != nil {
		noncePtr, _ = bytesToC(nonce)
	}

	result := C.elecrypto_aes_gcm_encrypt(
		plaintextPtr,
		plaintextLen,
		keyPtr,
		noncePtr,
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		(*C.uchar)(unsafe.Pointer(&nonceOut[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return &EncryptResult{
		Ciphertext: ciphertext,
		Nonce:      nonceOut,
	}, nil
}

// AESGCMDecrypt decrypts data using AES-256-GCM
func AESGCMDecrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, errors.New("key must be 32 bytes")
	}

	if len(nonce) != AESNonceSize {
		return nil, errors.New("nonce must be 12 bytes")
	}

	plaintextLen := len(ciphertext) - AESTagSize
	if plaintextLen < 0 {
		return nil, errors.New("ciphertext too short")
	}

	plaintext := make([]byte, plaintextLen)

	ciphertextPtr, ciphertextLen := bytesToC(ciphertext)
	keyPtr, _ := bytesToC(key)
	noncePtr, _ := bytesToC(nonce)

	result := C.elecrypto_aes_gcm_decrypt(
		ciphertextPtr,
		ciphertextLen,
		keyPtr,
		noncePtr,
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ChaCha20GenerateKey generates a random ChaCha20-Poly1305 key
func ChaCha20GenerateKey() ([]byte, error) {
	key := make([]byte, ChaCha20KeySize)

	result := C.elecrypto_chacha20_generate_key(
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return key, nil
}

// ChaCha20Poly1305Encrypt encrypts data using ChaCha20-Poly1305
func ChaCha20Poly1305Encrypt(plaintext, key []byte, nonce []byte) (*EncryptResult, error) {
	if len(key) != ChaCha20KeySize {
		return nil, errors.New("key must be 32 bytes")
	}

	if nonce != nil && len(nonce) != ChaCha20NonceSize {
		return nil, errors.New("nonce must be 12 bytes if provided")
	}

	ciphertext := make([]byte, len(plaintext)+16)
	nonceOut := make([]byte, ChaCha20NonceSize)

	plaintextPtr, plaintextLen := bytesToC(plaintext)
	keyPtr, _ := bytesToC(key)

	var noncePtr *C.uchar
	if nonce != nil {
		noncePtr, _ = bytesToC(nonce)
	}

	result := C.elecrypto_chacha20_poly1305_encrypt(
		plaintextPtr,
		plaintextLen,
		keyPtr,
		noncePtr,
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		(*C.uchar)(unsafe.Pointer(&nonceOut[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return &EncryptResult{
		Ciphertext: ciphertext,
		Nonce:      nonceOut,
	}, nil
}

// ChaCha20Poly1305Decrypt decrypts data using ChaCha20-Poly1305
func ChaCha20Poly1305Decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	if len(key) != ChaCha20KeySize {
		return nil, errors.New("key must be 32 bytes")
	}

	if len(nonce) != ChaCha20NonceSize {
		return nil, errors.New("nonce must be 12 bytes")
	}

	plaintextLen := len(ciphertext) - 16
	if plaintextLen < 0 {
		return nil, errors.New("ciphertext too short")
	}

	plaintext := make([]byte, plaintextLen)

	ciphertextPtr, ciphertextLen := bytesToC(ciphertext)
	keyPtr, _ := bytesToC(key)
	noncePtr, _ := bytesToC(nonce)

	result := C.elecrypto_chacha20_poly1305_decrypt(
		ciphertextPtr,
		ciphertextLen,
		keyPtr,
		noncePtr,
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return plaintext, nil
}
