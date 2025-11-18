# Elecrypto Go Bindings

Go bindings for the Elecrypto cryptographic library using cgo.

## Features

- **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Hash Functions**: SHA-256, SHA-512, SHA3-256, BLAKE3
- **Digital Signatures**: Ed25519
- **Random Number Generation**: CSPRNG
- **Native Performance**: Direct C bindings via cgo

## Installation

### Prerequisites

1. Build the Rust core library:
```bash
cd ../../core
cargo build --release
```

2. Set library path (for development):
```bash
export CGO_LDFLAGS="-L$(pwd)/../../core/target/release"
export LD_LIBRARY_PATH="$(pwd)/../../core/target/release:$LD_LIBRARY_PATH"
```

### Usage

```bash
go get github.com/elecrypto/elecrypto-go
```

## Quick Start

```go
package main

import (
    "fmt"
    ec "github.com/elecrypto/elecrypto-go"
)

func main() {
    // Hash function
    hash, _ := ec.SHA256([]byte("Hello, World!"))
    fmt.Printf("SHA-256: %x\n", hash)

    // AES-256-GCM encryption
    key, _ := ec.AESGenerateKey()
    result, _ := ec.AESGCMEncrypt([]byte("Secret"), key, nil)
    plaintext, _ := ec.AESGCMDecrypt(result.Ciphertext, key, result.Nonce)
    fmt.Printf("Decrypted: %s\n", plaintext)

    // Ed25519 signatures
    keypair, _ := ec.Ed25519GenerateKeypair()
    signature, _ := ec.Ed25519Sign([]byte("Message"), keypair.SecretKey)
    valid, _ := ec.Ed25519Verify([]byte("Message"), signature, keypair.PublicKey)
    fmt.Printf("Valid: %v\n", valid)
}
```

## API Reference

### Hash Functions

```go
func SHA256(data []byte) ([]byte, error)
func SHA512(data []byte) ([]byte, error)
func SHA3_256(data []byte) ([]byte, error)
func BLAKE3(data []byte, outputLength int) ([]byte, error)
```

### Symmetric Encryption

```go
type EncryptResult struct {
    Ciphertext []byte
    Nonce      []byte
}

func AESGenerateKey() ([]byte, error)
func AESGCMEncrypt(plaintext, key []byte, nonce []byte) (*EncryptResult, error)
func AESGCMDecrypt(ciphertext, key, nonce []byte) ([]byte, error)

func ChaCha20GenerateKey() ([]byte, error)
func ChaCha20Poly1305Encrypt(plaintext, key []byte, nonce []byte) (*EncryptResult, error)
func ChaCha20Poly1305Decrypt(ciphertext, key, nonce []byte) ([]byte, error)
```

### Digital Signatures

```go
type Ed25519Keypair struct {
    PublicKey []byte
    SecretKey []byte
}

func Ed25519GenerateKeypair() (*Ed25519Keypair, error)
func Ed25519Sign(message, secretKey []byte) ([]byte, error)
func Ed25519Verify(message, signature, publicKey []byte) (bool, error)
```

### Random

```go
func RandomBytes(length int) ([]byte, error)
```

## Error Handling

```go
result, err := ec.AESGCMEncrypt(plaintext, key, nil)
if err != nil {
    if ecErr, ok := err.(*ec.Error); ok {
        fmt.Printf("Error code: %d, message: %s\n", ecErr.Code, ecErr.Message)
    }
    return err
}
```

## Examples

```bash
cd examples
CGO_LDFLAGS="-L../../../core/target/release" go run basic.go
```

## Constants

```go
const (
    AESKeySize           = 32
    AESNonceSize         = 12
    AESTagSize           = 16
    ChaCha20KeySize      = 32
    ChaCha20NonceSize    = 12
    Ed25519PublicKeySize = 32
    Ed25519SecretKeySize = 32
    Ed25519SignatureSize = 64
)
```

## License

MIT License
