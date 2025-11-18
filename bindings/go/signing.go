package elecrypto

/*
#include <elecrypto.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

// Ed25519Keypair contains a public and secret key pair
type Ed25519Keypair struct {
	PublicKey []byte
	SecretKey []byte
}

// Ed25519GenerateKeypair generates an Ed25519 keypair
func Ed25519GenerateKeypair() (*Ed25519Keypair, error) {
	publicKey := make([]byte, Ed25519PublicKeySize)
	secretKey := make([]byte, Ed25519SecretKeySize)

	result := C.elecrypto_ed25519_generate_keypair(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return &Ed25519Keypair{
		PublicKey: publicKey,
		SecretKey: secretKey,
	}, nil
}

// Ed25519Sign signs a message with Ed25519
func Ed25519Sign(message, secretKey []byte) ([]byte, error) {
	if len(secretKey) != Ed25519SecretKeySize {
		return nil, errors.New("secret key must be 32 bytes")
	}

	signature := make([]byte, Ed25519SignatureSize)

	messagePtr, messageLen := bytesToC(message)
	secretKeyPtr, _ := bytesToC(secretKey)

	result := C.elecrypto_ed25519_sign(
		messagePtr,
		messageLen,
		secretKeyPtr,
		(*C.uchar)(unsafe.Pointer(&signature[0])),
	)

	if err := checkResult(result); err != nil {
		return nil, err
	}

	return signature, nil
}

// Ed25519Verify verifies an Ed25519 signature
func Ed25519Verify(message, signature, publicKey []byte) (bool, error) {
	if len(signature) != Ed25519SignatureSize {
		return false, errors.New("signature must be 64 bytes")
	}

	if len(publicKey) != Ed25519PublicKeySize {
		return false, errors.New("public key must be 32 bytes")
	}

	messagePtr, messageLen := bytesToC(message)
	signaturePtr, _ := bytesToC(signature)
	publicKeyPtr, _ := bytesToC(publicKey)

	result := C.elecrypto_ed25519_verify(
		messagePtr,
		messageLen,
		signaturePtr,
		publicKeyPtr,
	)

	if result < 0 {
		return false, checkResult(result)
	}

	return result == 1, nil
}
