package elecrypto

/*
#include <elecrypto.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

// RSAKeypair represents an RSA key pair
type RSAKeypair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// ECIESKeypair represents an ECIES key pair
type ECIESKeypair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// RSAGenerateKeypair generates an RSA-2048 key pair
func RSAGenerateKeypair() (*RSAKeypair, error) {
	publicKey := make([]byte, RSA2048PublicKeySize)
	privateKey := make([]byte, RSA2048PrivateKeySize)

	result := C.elecrypto_rsa_generate_keypair_2048(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&privateKey[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return &RSAKeypair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// RSAEncrypt encrypts data using RSA-OAEP with SHA-256
func RSAEncrypt(plaintext, publicKey []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	maxCiphertextLen := 256
	ciphertext := make([]byte, maxCiphertextLen)
	var ciphertextLen C.uint

	result := C.elecrypto_rsa_encrypt(
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
		C.uint(len(plaintext)),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		C.uint(len(publicKey)),
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		&ciphertextLen,
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return ciphertext[:ciphertextLen], nil
}

// RSADecrypt decrypts data using RSA-OAEP with SHA-256
func RSADecrypt(ciphertext, privateKey []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext cannot be empty")
	}

	maxPlaintextLen := 256
	plaintext := make([]byte, maxPlaintextLen)
	var plaintextLen C.uint

	result := C.elecrypto_rsa_decrypt(
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		C.uint(len(ciphertext)),
		(*C.uchar)(unsafe.Pointer(&privateKey[0])),
		C.uint(len(privateKey)),
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
		&plaintextLen,
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return plaintext[:plaintextLen], nil
}

// ECIESGenerateKeypair generates an ECIES (P-256) key pair
func ECIESGenerateKeypair() (*ECIESKeypair, error) {
	publicKey := make([]byte, ECIESPublicKeySize)
	privateKey := make([]byte, ECIESPrivateKeySize)

	result := C.elecrypto_ecies_generate_keypair(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&privateKey[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return &ECIESKeypair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// ECIESEncrypt encrypts data using ECIES (P-256 ECDH + HKDF-SHA256 + AES-256-GCM)
func ECIESEncrypt(plaintext, publicKey []byte) ([]byte, error) {
	if len(publicKey) != ECIESPublicKeySize {
		return nil, errors.New("invalid public key size")
	}

	// ECIES ciphertext = ephemeral_pubkey (65) + nonce (12) + ciphertext + tag (16)
	maxCiphertextLen := 65 + 12 + len(plaintext) + 16
	ciphertext := make([]byte, maxCiphertextLen)
	var ciphertextLen C.uint

	var plaintextPtr *C.uchar
	if len(plaintext) > 0 {
		plaintextPtr = (*C.uchar)(unsafe.Pointer(&plaintext[0]))
	}

	result := C.elecrypto_ecies_encrypt(
		plaintextPtr,
		C.uint(len(plaintext)),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		&ciphertextLen,
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return ciphertext[:ciphertextLen], nil
}

// ECIESDecrypt decrypts data using ECIES
func ECIESDecrypt(ciphertext, privateKey []byte) ([]byte, error) {
	if len(privateKey) != ECIESPrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	if len(ciphertext) < 65+12+16 {
		return nil, errors.New("ciphertext too short")
	}

	maxPlaintextLen := len(ciphertext) - 65 - 12 - 16
	if maxPlaintextLen < 1 {
		maxPlaintextLen = 1
	}
	plaintext := make([]byte, maxPlaintextLen)
	var plaintextLen C.uint

	result := C.elecrypto_ecies_decrypt(
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		C.uint(len(ciphertext)),
		(*C.uchar)(unsafe.Pointer(&privateKey[0])),
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
		&plaintextLen,
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return plaintext[:plaintextLen], nil
}
