package elecrypto

/*
#include <elecrypto.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

// Kyber512Keypair represents a Kyber-512 key pair
type Kyber512Keypair struct {
	PublicKey []byte
	SecretKey []byte
}

// Kyber512EncapsulationResult represents the result of Kyber encapsulation
type Kyber512EncapsulationResult struct {
	Ciphertext   []byte
	SharedSecret []byte
}

// Dilithium2Keypair represents a Dilithium2 key pair
type Dilithium2Keypair struct {
	PublicKey []byte
	SecretKey []byte
}

// Kyber512GenerateKeypair generates a Kyber-512 key pair for key encapsulation
func Kyber512GenerateKeypair() (*Kyber512Keypair, error) {
	publicKey := make([]byte, Kyber512PublicKeySize)
	secretKey := make([]byte, Kyber512SecretKeySize)

	result := C.elecrypto_kyber512_generate_keypair(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return &Kyber512Keypair{
		PublicKey: publicKey,
		SecretKey: secretKey,
	}, nil
}

// Kyber512Encapsulate encapsulates a shared secret using Kyber-512
func Kyber512Encapsulate(publicKey []byte) (*Kyber512EncapsulationResult, error) {
	if len(publicKey) != Kyber512PublicKeySize {
		return nil, errors.New("invalid public key size")
	}

	ciphertext := make([]byte, Kyber512CiphertextSize)
	sharedSecret := make([]byte, Kyber512SharedSecretSize)

	result := C.elecrypto_kyber512_encapsulate(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return &Kyber512EncapsulationResult{
		Ciphertext:   ciphertext,
		SharedSecret: sharedSecret,
	}, nil
}

// Kyber512Decapsulate decapsulates a shared secret using Kyber-512
func Kyber512Decapsulate(ciphertext, secretKey []byte) ([]byte, error) {
	if len(ciphertext) != Kyber512CiphertextSize {
		return nil, errors.New("invalid ciphertext size")
	}
	if len(secretKey) != Kyber512SecretKeySize {
		return nil, errors.New("invalid secret key size")
	}

	sharedSecret := make([]byte, Kyber512SharedSecretSize)

	result := C.elecrypto_kyber512_decapsulate(
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return sharedSecret, nil
}

// Dilithium2GenerateKeypair generates a Dilithium2 key pair for digital signatures
func Dilithium2GenerateKeypair() (*Dilithium2Keypair, error) {
	publicKey := make([]byte, Dilithium2PublicKeySize)
	secretKey := make([]byte, Dilithium2SecretKeySize)

	result := C.elecrypto_dilithium2_generate_keypair(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return &Dilithium2Keypair{
		PublicKey: publicKey,
		SecretKey: secretKey,
	}, nil
}

// Dilithium2Sign signs a message using Dilithium2
func Dilithium2Sign(message, secretKey []byte) ([]byte, error) {
	if len(secretKey) != Dilithium2SecretKeySize {
		return nil, errors.New("invalid secret key size")
	}

	signature := make([]byte, Dilithium2SignatureSize)

	var messagePtr *C.uchar
	if len(message) > 0 {
		messagePtr = (*C.uchar)(unsafe.Pointer(&message[0]))
	}

	result := C.elecrypto_dilithium2_sign(
		messagePtr,
		C.uint(len(message)),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return signature, nil
}

// Dilithium2Verify verifies a Dilithium2 signature
func Dilithium2Verify(message, signature, publicKey []byte) error {
	if len(signature) != Dilithium2SignatureSize {
		return errors.New("invalid signature size")
	}
	if len(publicKey) != Dilithium2PublicKeySize {
		return errors.New("invalid public key size")
	}

	var messagePtr *C.uchar
	if len(message) > 0 {
		messagePtr = (*C.uchar)(unsafe.Pointer(&message[0]))
	}

	result := C.elecrypto_dilithium2_verify(
		messagePtr,
		C.uint(len(message)),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
	)

	return checkResult(result)
}
