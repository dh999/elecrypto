import Foundation

/// Elecrypto - Cross-platform Cryptographic Library
/// iOS bindings using Swift and C interop
public class Elecrypto {

    // MARK: - Error Handling

    public enum ElecryptoError: Error {
        case invalidInput
        case invalidKeyLength
        case invalidNonceLength
        case authenticationFailed
        case encryptionFailed
        case decryptionFailed
        case signingFailed
        case verificationFailed
        case unknownError(Int32)

        init(code: Int32) {
            switch code {
            case -1: self = .invalidInput
            case -2: self = .invalidKeyLength
            case -3: self = .invalidNonceLength
            case -4: self = .authenticationFailed
            case -5: self = .encryptionFailed
            case -6: self = .decryptionFailed
            case -7: self = .signingFailed
            case -8: self = .verificationFailed
            default: self = .unknownError(code)
            }
        }
    }

    // MARK: - Constants

    public static let aesKeySize = 32
    public static let aesNonceSize = 12
    public static let chaCha20KeySize = 32
    public static let ed25519PublicKeySize = 32
    public static let ed25519SecretKeySize = 32
    public static let ed25519SignatureSize = 64

    // MARK: - Helper Methods

    private static func checkResult(_ code: Int32) throws {
        guard code >= 0 else {
            throw ElecryptoError(code: code)
        }
    }

    // MARK: - Random

    /// Generate cryptographically secure random bytes
    public static func randomBytes(length: Int) throws -> Data {
        var output = Data(count: length)
        let result = output.withUnsafeMutableBytes { (ptr: UnsafeMutableRawBufferPointer) -> Int32 in
            guard let baseAddress = ptr.baseAddress else { return -1 }
            return elecrypto_random_bytes(
                baseAddress.assumingMemoryBound(to: UInt8.self),
                UInt32(length)
            )
        }
        try checkResult(result)
        return output
    }

    // MARK: - Hash Functions

    /// Compute SHA-256 hash
    public static func sha256(_ data: Data) throws -> Data {
        var hash = Data(count: 32)
        let result = data.withUnsafeBytes { (dataPtr: UnsafeRawBufferPointer) -> Int32 in
            hash.withUnsafeMutableBytes { (hashPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                guard let dataBase = dataPtr.baseAddress,
                      let hashBase = hashPtr.baseAddress else { return -1 }
                return elecrypto_sha256(
                    dataBase.assumingMemoryBound(to: UInt8.self),
                    UInt32(data.count),
                    hashBase.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        try checkResult(result)
        return hash
    }

    // MARK: - Symmetric Encryption

    /// Encryption result containing ciphertext and nonce
    public struct EncryptResult {
        public let ciphertext: Data
        public let nonce: Data
    }

    /// Generate AES-256 key
    public static func aesGenerateKey() throws -> Data {
        var key = Data(count: aesKeySize)
        let result = key.withUnsafeMutableBytes { (ptr: UnsafeMutableRawBufferPointer) -> Int32 in
            guard let baseAddress = ptr.baseAddress else { return -1 }
            return elecrypto_aes_generate_key(
                baseAddress.assumingMemoryBound(to: UInt8.self)
            )
        }
        try checkResult(result)
        return key
    }

    /// Encrypt with AES-256-GCM
    public static func aesGcmEncrypt(plaintext: Data, key: Data, nonce: Data? = nil) throws -> EncryptResult {
        guard key.count == aesKeySize else {
            throw ElecryptoError.invalidKeyLength
        }

        var ciphertext = Data(count: plaintext.count + 16)
        var nonceOut = Data(count: aesNonceSize)

        let result = plaintext.withUnsafeBytes { (ptPtr: UnsafeRawBufferPointer) -> Int32 in
            key.withUnsafeBytes { (keyPtr: UnsafeRawBufferPointer) -> Int32 in
                ciphertext.withUnsafeMutableBytes { (ctPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                    nonceOut.withUnsafeMutableBytes { (nonceOutPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                        guard let ptBase = ptPtr.baseAddress,
                              let keyBase = keyPtr.baseAddress,
                              let ctBase = ctPtr.baseAddress,
                              let nonceOutBase = nonceOutPtr.baseAddress else { return -1 }

                        let noncePtr = nonce?.withUnsafeBytes { $0.baseAddress?.assumingMemoryBound(to: UInt8.self) }

                        return elecrypto_aes_gcm_encrypt(
                            ptBase.assumingMemoryBound(to: UInt8.self),
                            UInt32(plaintext.count),
                            keyBase.assumingMemoryBound(to: UInt8.self),
                            noncePtr,
                            ctBase.assumingMemoryBound(to: UInt8.self),
                            nonceOutBase.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }
        try checkResult(result)

        return EncryptResult(ciphertext: ciphertext, nonce: nonceOut)
    }

    /// Decrypt with AES-256-GCM
    public static func aesGcmDecrypt(ciphertext: Data, key: Data, nonce: Data) throws -> Data {
        guard key.count == aesKeySize else {
            throw ElecryptoError.invalidKeyLength
        }
        guard nonce.count == aesNonceSize else {
            throw ElecryptoError.invalidNonceLength
        }

        var plaintext = Data(count: ciphertext.count - 16)

        let result = ciphertext.withUnsafeBytes { (ctPtr: UnsafeRawBufferPointer) -> Int32 in
            key.withUnsafeBytes { (keyPtr: UnsafeRawBufferPointer) -> Int32 in
                nonce.withUnsafeBytes { (noncePtr: UnsafeRawBufferPointer) -> Int32 in
                    plaintext.withUnsafeMutableBytes { (ptPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                        guard let ctBase = ctPtr.baseAddress,
                              let keyBase = keyPtr.baseAddress,
                              let nonceBase = noncePtr.baseAddress,
                              let ptBase = ptPtr.baseAddress else { return -1 }

                        return elecrypto_aes_gcm_decrypt(
                            ctBase.assumingMemoryBound(to: UInt8.self),
                            UInt32(ciphertext.count),
                            keyBase.assumingMemoryBound(to: UInt8.self),
                            nonceBase.assumingMemoryBound(to: UInt8.self),
                            ptBase.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }
        try checkResult(result)

        return plaintext
    }

    // MARK: - Digital Signatures

    /// Ed25519 keypair
    public struct Ed25519Keypair {
        public let publicKey: Data
        public let secretKey: Data
    }

    /// Generate Ed25519 keypair
    public static func ed25519GenerateKeypair() throws -> Ed25519Keypair {
        var publicKey = Data(count: ed25519PublicKeySize)
        var secretKey = Data(count: ed25519SecretKeySize)

        let result = publicKey.withUnsafeMutableBytes { (pkPtr: UnsafeMutableRawBufferPointer) -> Int32 in
            secretKey.withUnsafeMutableBytes { (skPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                guard let pkBase = pkPtr.baseAddress,
                      let skBase = skPtr.baseAddress else { return -1 }

                return elecrypto_ed25519_generate_keypair(
                    pkBase.assumingMemoryBound(to: UInt8.self),
                    skBase.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        try checkResult(result)

        return Ed25519Keypair(publicKey: publicKey, secretKey: secretKey)
    }

    /// Sign message with Ed25519
    public static func ed25519Sign(message: Data, secretKey: Data) throws -> Data {
        guard secretKey.count == ed25519SecretKeySize else {
            throw ElecryptoError.invalidKeyLength
        }

        var signature = Data(count: ed25519SignatureSize)

        let result = message.withUnsafeBytes { (msgPtr: UnsafeRawBufferPointer) -> Int32 in
            secretKey.withUnsafeBytes { (skPtr: UnsafeRawBufferPointer) -> Int32 in
                signature.withUnsafeMutableBytes { (sigPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                    guard let msgBase = msgPtr.baseAddress,
                          let skBase = skPtr.baseAddress,
                          let sigBase = sigPtr.baseAddress else { return -1 }

                    return elecrypto_ed25519_sign(
                        msgBase.assumingMemoryBound(to: UInt8.self),
                        UInt32(message.count),
                        skBase.assumingMemoryBound(to: UInt8.self),
                        sigBase.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        try checkResult(result)

        return signature
    }

    /// Verify Ed25519 signature
    public static func ed25519Verify(message: Data, signature: Data, publicKey: Data) throws -> Bool {
        guard signature.count == ed25519SignatureSize else {
            throw ElecryptoError.invalidInput
        }
        guard publicKey.count == ed25519PublicKeySize else {
            throw ElecryptoError.invalidKeyLength
        }

        let result = message.withUnsafeBytes { (msgPtr: UnsafeRawBufferPointer) -> Int32 in
            signature.withUnsafeBytes { (sigPtr: UnsafeRawBufferPointer) -> Int32 in
                publicKey.withUnsafeBytes { (pkPtr: UnsafeRawBufferPointer) -> Int32 in
                    guard let msgBase = msgPtr.baseAddress,
                          let sigBase = sigPtr.baseAddress,
                          let pkBase = pkPtr.baseAddress else { return -1 }

                    return elecrypto_ed25519_verify(
                        msgBase.assumingMemoryBound(to: UInt8.self),
                        UInt32(message.count),
                        sigBase.assumingMemoryBound(to: UInt8.self),
                        pkBase.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }

        if result < 0 {
            try checkResult(result)
        }

        return result == 1
    }
}

// MARK: - C Declarations

@_silgen_name("elecrypto_random_bytes")
func elecrypto_random_bytes(_ output: UnsafeMutablePointer<UInt8>, _ length: UInt32) -> Int32

@_silgen_name("elecrypto_sha256")
func elecrypto_sha256(_ input: UnsafePointer<UInt8>, _ inputLen: UInt32, _ output: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("elecrypto_aes_generate_key")
func elecrypto_aes_generate_key(_ key: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("elecrypto_aes_gcm_encrypt")
func elecrypto_aes_gcm_encrypt(_ plaintext: UnsafePointer<UInt8>, _ plaintextLen: UInt32,
                               _ key: UnsafePointer<UInt8>, _ nonce: UnsafePointer<UInt8>?,
                               _ ciphertext: UnsafeMutablePointer<UInt8>,
                               _ nonceOut: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("elecrypto_aes_gcm_decrypt")
func elecrypto_aes_gcm_decrypt(_ ciphertext: UnsafePointer<UInt8>, _ ciphertextLen: UInt32,
                               _ key: UnsafePointer<UInt8>, _ nonce: UnsafePointer<UInt8>,
                               _ plaintext: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("elecrypto_ed25519_generate_keypair")
func elecrypto_ed25519_generate_keypair(_ publicKey: UnsafeMutablePointer<UInt8>,
                                        _ secretKey: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("elecrypto_ed25519_sign")
func elecrypto_ed25519_sign(_ message: UnsafePointer<UInt8>, _ messageLen: UInt32,
                             _ secretKey: UnsafePointer<UInt8>,
                             _ signature: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("elecrypto_ed25519_verify")
func elecrypto_ed25519_verify(_ message: UnsafePointer<UInt8>, _ messageLen: UInt32,
                               _ signature: UnsafePointer<UInt8>,
                               _ publicKey: UnsafePointer<UInt8>) -> Int32
