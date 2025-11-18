# Elecrypto iOS Bindings

Swift bindings for the Elecrypto cryptographic library for iOS and macOS.

## Features

- **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Hash Functions**: SHA-256, SHA-512, BLAKE3
- **Digital Signatures**: Ed25519
- **Random Number Generation**: CSPRNG
- **Swift-native API**: Idiomatic Swift with error handling
- **iOS & macOS Support**: Compatible with iOS 13+ and macOS 10.15+

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/yourusername/elecrypto-ios", from: "0.1.0")
]
```

Or in Xcode: File > Add Packages...

### Prerequisites

The Rust core library must be compiled for iOS/macOS targets:

```bash
# For iOS
cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios  # Simulator

# For macOS
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
```

## Usage

### Basic Example

```swift
import Elecrypto

do {
    // Hash function
    let data = "Hello, World!".data(using: .utf8)!
    let hash = try Elecrypto.sha256(data)
    print("SHA-256: \(hash.hexString)")

    // AES-256-GCM encryption
    let key = try Elecrypto.aesGenerateKey()
    let plaintext = "Secret message".data(using: .utf8)!

    let result = try Elecrypto.aesGcmEncrypt(
        plaintext: plaintext,
        key: key
    )

    let decrypted = try Elecrypto.aesGcmDecrypt(
        ciphertext: result.ciphertext,
        key: key,
        nonce: result.nonce
    )

    // Ed25519 signatures
    let keypair = try Elecrypto.ed25519GenerateKeypair()
    let message = "Important message".data(using: .utf8)!

    let signature = try Elecrypto.ed25519Sign(
        message: message,
        secretKey: keypair.secretKey
    )

    let isValid = try Elecrypto.ed25519Verify(
        message: message,
        signature: signature,
        publicKey: keypair.publicKey
    )
    print("Signature valid: \(isValid)")

} catch let error as Elecrypto.ElecryptoError {
    print("Crypto error: \(error)")
} catch {
    print("Error: \(error)")
}
```

### iOS App Example

```swift
import UIKit
import Elecrypto

class SecureViewController: UIViewController {
    func encryptUserData(_ data: Data) {
        do {
            // Generate key (store in Keychain in production)
            let key = try Elecrypto.aesGenerateKey()

            // Encrypt sensitive data
            let result = try Elecrypto.aesGcmEncrypt(
                plaintext: data,
                key: key
            )

            // Save encrypted data and nonce
            UserDefaults.standard.set(result.ciphertext, forKey: "encryptedData")
            UserDefaults.standard.set(result.nonce, forKey: "nonce")

        } catch {
            print("Encryption failed: \(error)")
        }
    }

    func generateRandomToken() -> String {
        do {
            let random = try Elecrypto.randomBytes(length: 32)
            return random.base64EncodedString()
        } catch {
            return ""
        }
    }
}
```

## API Reference

### Static Methods

```swift
// Random
static func randomBytes(length: Int) throws -> Data

// Hash functions
static func sha256(_ data: Data) throws -> Data

// Symmetric encryption
static func aesGenerateKey() throws -> Data
static func aesGcmEncrypt(plaintext: Data, key: Data, nonce: Data?) throws -> EncryptResult
static func aesGcmDecrypt(ciphertext: Data, key: Data, nonce: Data) throws -> Data

// Digital signatures
static func ed25519GenerateKeypair() throws -> Ed25519Keypair
static func ed25519Sign(message: Data, secretKey: Data) throws -> Data
static func ed25519Verify(message: Data, signature: Data, publicKey: Data) throws -> Bool
```

### Data Types

```swift
// Encryption result
struct EncryptResult {
    let ciphertext: Data
    let nonce: Data
}

// Ed25519 keypair
struct Ed25519Keypair {
    let publicKey: Data
    let secretKey: Data
}
```

### Error Handling

```swift
enum ElecryptoError: Error {
    case invalidInput
    case invalidKeyLength
    case invalidNonceLength
    case authenticationFailed
    case encryptionFailed
    case decryptionFailed
    case signingFailed
    case verificationFailed
    case unknownError(Int32)
}
```

## Constants

```swift
static let aesKeySize = 32
static let aesNonceSize = 12
static let chaCha20KeySize = 32
static let ed25519PublicKeySize = 32
static let ed25519SecretKeySize = 32
static let ed25519SignatureSize = 64
```

## Best Practices

1. **Key Storage**: Use Keychain to store cryptographic keys securely
2. **Random Generation**: Use `randomBytes()` for all nonces and salts
3. **Error Handling**: Always handle errors properly in production code
4. **Memory Safety**: Swift's automatic memory management handles cleanup

## Integration with Keychain

```swift
import Security

func saveKeyToKeychain(_ key: Data, identifier: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: identifier,
        kSecValueData as String: key
    ]

    SecItemDelete(query as CFDictionary)
    SecItemAdd(query as CFDictionary, nil)
}
```

## License

MIT License
