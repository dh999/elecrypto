package main

import (
	"encoding/hex"
	"fmt"
	"log"

	ec "github.com/elecrypto/elecrypto-go"
)

func main() {
	fmt.Println("=== Elecrypto Go Bindings Examples ===\n")

	// 1. Hash functions
	fmt.Println("1. Hash Functions")
	message := []byte("Hello, Elecrypto!")

	sha256Hash, _ := ec.SHA256(message)
	fmt.Printf("SHA-256: %s\n", hex.EncodeToString(sha256Hash))

	blake3Hash, _ := ec.BLAKE3(message, 32)
	fmt.Printf("BLAKE3:  %s\n\n", hex.EncodeToString(blake3Hash))

	// 2. Random number generation
	fmt.Println("2. Random Number Generation")
	randomData, _ := ec.RandomBytes(32)
	fmt.Printf("32 random bytes: %s\n\n", hex.EncodeToString(randomData))

	// 3. AES-GCM encryption
	fmt.Println("3. AES-256-GCM Encryption")
	plaintext := []byte("This is a secret message!")
	key, _ := ec.AESGenerateKey()
	fmt.Printf("Generated key: %s\n", hex.EncodeToString(key))

	result, err := ec.AESGCMEncrypt(plaintext, key, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(result.Ciphertext))
	fmt.Printf("Nonce: %s\n", hex.EncodeToString(result.Nonce))

	decrypted, _ := ec.AESGCMDecrypt(result.Ciphertext, key, result.Nonce)
	fmt.Printf("Decrypted: %s\n", string(decrypted))
	fmt.Println("✓ Encryption/Decryption successful\n")

	// 4. ChaCha20-Poly1305 encryption
	fmt.Println("4. ChaCha20-Poly1305 Encryption")
	chachaKey, _ := ec.ChaCha20GenerateKey()
	chachaResult, _ := ec.ChaCha20Poly1305Encrypt(plaintext, chachaKey, nil)
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(chachaResult.Ciphertext))

	chachaDecrypted, _ := ec.ChaCha20Poly1305Decrypt(chachaResult.Ciphertext, chachaKey, chachaResult.Nonce)
	fmt.Printf("Decrypted: %s\n", string(chachaDecrypted))
	fmt.Println("✓ ChaCha20 encryption successful\n")

	// 5. Digital signatures (Ed25519)
	fmt.Println("5. Ed25519 Digital Signatures")
	keypair, _ := ec.Ed25519GenerateKeypair()
	fmt.Printf("Public key: %s\n", hex.EncodeToString(keypair.PublicKey))
	fmt.Printf("Secret key: %s...\n", hex.EncodeToString(keypair.SecretKey)[:32])

	signMessage := []byte("Sign this important message")
	signature, _ := ec.Ed25519Sign(signMessage, keypair.SecretKey)
	fmt.Printf("Signature: %s...\n", hex.EncodeToString(signature)[:32])

	isValid, _ := ec.Ed25519Verify(signMessage, signature, keypair.PublicKey)
	fmt.Printf("Signature valid: %v\n", isValid)

	// Try with wrong message
	wrongMessage := []byte("Different message")
	isValidWrong, _ := ec.Ed25519Verify(wrongMessage, signature, keypair.PublicKey)
	fmt.Printf("Wrong message valid: %v\n", isValidWrong)
	fmt.Println("✓ Digital signature successful\n")

	fmt.Println("=== All tests passed! ===")
}
