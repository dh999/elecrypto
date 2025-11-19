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

    // RSA constants
    public static let rsa2048PublicKeySize = 294
    public static let rsa2048PrivateKeySize = 1218

    // ECIES constants
    public static let eciesPublicKeySize = 65
    public static let eciesPrivateKeySize = 32

    // Kyber constants
    public static let kyber512PublicKeySize = 800
    public static let kyber512SecretKeySize = 1632
    public static let kyber512CiphertextSize = 768
    public static let kyber512SharedSecretSize = 32

    // Dilithium constants
    public static let dilithium2PublicKeySize = 1312
    public static let dilithium2SecretKeySize = 2560
    public static let dilithium2SignatureSize = 2420

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

    // MARK: - RSA-OAEP

    /// RSA keypair
    public struct RsaKeypair {
        public let publicKey: Data
        public let privateKey: Data
    }

    /// Generate RSA-2048 keypair
    public static func rsaGenerateKeypair() throws -> RsaKeypair {
        var publicKey = Data(count: rsa2048PublicKeySize)
        var privateKey = Data(count: rsa2048PrivateKeySize)

        let result = publicKey.withUnsafeMutableBytes { (pkPtr: UnsafeMutableRawBufferPointer) -> Int32 in
            privateKey.withUnsafeMutableBytes { (skPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                guard let pkBase = pkPtr.baseAddress,
                      let skBase = skPtr.baseAddress else { return -1 }

                return elecrypto_rsa_generate_keypair_2048(
                    pkBase.assumingMemoryBound(to: UInt8.self),
                    skBase.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        try checkResult(result)

        return RsaKeypair(publicKey: publicKey, privateKey: privateKey)
    }

    /// Encrypt with RSA-OAEP
    public static func rsaEncrypt(plaintext: Data, publicKey: Data) throws -> Data {
        var ciphertext = Data(count: 256)
        var ciphertextLen: UInt32 = 0

        let result = plaintext.withUnsafeBytes { (ptPtr: UnsafeRawBufferPointer) -> Int32 in
            publicKey.withUnsafeBytes { (pkPtr: UnsafeRawBufferPointer) -> Int32 in
                ciphertext.withUnsafeMutableBytes { (ctPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                    guard let ptBase = ptPtr.baseAddress,
                          let pkBase = pkPtr.baseAddress,
                          let ctBase = ctPtr.baseAddress else { return -1 }

                    return elecrypto_rsa_encrypt(
                        ptBase.assumingMemoryBound(to: UInt8.self),
                        UInt32(plaintext.count),
                        pkBase.assumingMemoryBound(to: UInt8.self),
                        UInt32(publicKey.count),
                        ctBase.assumingMemoryBound(to: UInt8.self),
                        &ciphertextLen
                    )
                }
            }
        }
        try checkResult(result)

        return ciphertext.prefix(Int(ciphertextLen))
    }

    /// Decrypt with RSA-OAEP
    public static func rsaDecrypt(ciphertext: Data, privateKey: Data) throws -> Data {
        var plaintext = Data(count: 256)
        var plaintextLen: UInt32 = 0

        let result = ciphertext.withUnsafeBytes { (ctPtr: UnsafeRawBufferPointer) -> Int32 in
            privateKey.withUnsafeBytes { (skPtr: UnsafeRawBufferPointer) -> Int32 in
                plaintext.withUnsafeMutableBytes { (ptPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                    guard let ctBase = ctPtr.baseAddress,
                          let skBase = skPtr.baseAddress,
                          let ptBase = ptPtr.baseAddress else { return -1 }

                    return elecrypto_rsa_decrypt(
                        ctBase.assumingMemoryBound(to: UInt8.self),
                        UInt32(ciphertext.count),
                        skBase.assumingMemoryBound(to: UInt8.self),
                        UInt32(privateKey.count),
                        ptBase.assumingMemoryBound(to: UInt8.self),
                        &plaintextLen
                    )
                }
            }
        }
        try checkResult(result)

        return plaintext.prefix(Int(plaintextLen))
    }

    // MARK: - ECIES

    /// ECIES keypair
    public struct EciesKeypair {
        public let publicKey: Data
        public let privateKey: Data
    }

    /// Generate ECIES keypair
    public static func eciesGenerateKeypair() throws -> EciesKeypair {
        var publicKey = Data(count: eciesPublicKeySize)
        var privateKey = Data(count: eciesPrivateKeySize)

        let result = publicKey.withUnsafeMutableBytes { (pkPtr: UnsafeMutableRawBufferPointer) -> Int32 in
            privateKey.withUnsafeMutableBytes { (skPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                guard let pkBase = pkPtr.baseAddress,
                      let skBase = skPtr.baseAddress else { return -1 }

                return elecrypto_ecies_generate_keypair(
                    pkBase.assumingMemoryBound(to: UInt8.self),
                    skBase.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        try checkResult(result)

        return EciesKeypair(publicKey: publicKey, privateKey: privateKey)
    }

    /// Encrypt with ECIES
    public static func eciesEncrypt(plaintext: Data, publicKey: Data) throws -> Data {
        let maxLen = 65 + 12 + plaintext.count + 16
        var ciphertext = Data(count: maxLen)
        var ciphertextLen: UInt32 = 0

        let result = plaintext.withUnsafeBytes { (ptPtr: UnsafeRawBufferPointer) -> Int32 in
            publicKey.withUnsafeBytes { (pkPtr: UnsafeRawBufferPointer) -> Int32 in
                ciphertext.withUnsafeMutableBytes { (ctPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                    guard let ptBase = ptPtr.baseAddress,
                          let pkBase = pkPtr.baseAddress,
                          let ctBase = ctPtr.baseAddress else { return -1 }

                    return elecrypto_ecies_encrypt(
                        ptBase.assumingMemoryBound(to: UInt8.self),
                        UInt32(plaintext.count),
                        pkBase.assumingMemoryBound(to: UInt8.self),
                        ctBase.assumingMemoryBound(to: UInt8.self),
                        &ciphertextLen
                    )
                }
            }
        }
        try checkResult(result)

        return ciphertext.prefix(Int(ciphertextLen))
    }

    /// Decrypt with ECIES
    public static func eciesDecrypt(ciphertext: Data, privateKey: Data) throws -> Data {
        let maxLen = max(1, ciphertext.count - 65 - 12 - 16)
        var plaintext = Data(count: maxLen)
        var plaintextLen: UInt32 = 0

        let result = ciphertext.withUnsafeBytes { (ctPtr: UnsafeRawBufferPointer) -> Int32 in
            privateKey.withUnsafeBytes { (skPtr: UnsafeRawBufferPointer) -> Int32 in
                plaintext.withUnsafeMutableBytes { (ptPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                    guard let ctBase = ctPtr.baseAddress,
                          let skBase = skPtr.baseAddress,
                          let ptBase = ptPtr.baseAddress else { return -1 }

                    return elecrypto_ecies_decrypt(
                        ctBase.assumingMemoryBound(to: UInt8.self),
                        UInt32(ciphertext.count),
                        skBase.assumingMemoryBound(to: UInt8.self),
                        ptBase.assumingMemoryBound(to: UInt8.self),
                        &plaintextLen
                    )
                }
            }
        }
        try checkResult(result)

        return plaintext.prefix(Int(plaintextLen))
    }

    // MARK: - DRBG

    /// Generate random bytes using HMAC-DRBG
    public static func hmacDrbgGenerate(seed: Data, outputLen: Int) throws -> Data {
        var output = Data(count: outputLen)

        let result = seed.withUnsafeBytes { (seedPtr: UnsafeRawBufferPointer) -> Int32 in
            output.withUnsafeMutableBytes { (outPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                guard let seedBase = seedPtr.baseAddress,
                      let outBase = outPtr.baseAddress else { return -1 }

                return elecrypto_hmac_drbg_generate(
                    seedBase.assumingMemoryBound(to: UInt8.self),
                    UInt32(seed.count),
                    outBase.assumingMemoryBound(to: UInt8.self),
                    UInt32(outputLen)
                )
            }
        }
        try checkResult(result)

        return output
    }

    /// Generate random bytes using CTR-DRBG
    public static func ctrDrbgGenerate(seed: Data, outputLen: Int) throws -> Data {
        var output = Data(count: outputLen)

        let result = seed.withUnsafeBytes { (seedPtr: UnsafeRawBufferPointer) -> Int32 in
            output.withUnsafeMutableBytes { (outPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                guard let seedBase = seedPtr.baseAddress,
                      let outBase = outPtr.baseAddress else { return -1 }

                return elecrypto_ctr_drbg_generate(
                    seedBase.assumingMemoryBound(to: UInt8.self),
                    UInt32(seed.count),
                    outBase.assumingMemoryBound(to: UInt8.self),
                    UInt32(outputLen)
                )
            }
        }
        try checkResult(result)

        return output
    }

    // MARK: - Kyber (Post-Quantum KEM)

    /// Kyber-512 keypair
    public struct Kyber512Keypair {
        public let publicKey: Data
        public let secretKey: Data
    }

    /// Kyber-512 encapsulation result
    public struct Kyber512EncapsulationResult {
        public let ciphertext: Data
        public let sharedSecret: Data
    }

    /// Generate Kyber-512 keypair
    public static func kyber512GenerateKeypair() throws -> Kyber512Keypair {
        var publicKey = Data(count: kyber512PublicKeySize)
        var secretKey = Data(count: kyber512SecretKeySize)

        let result = publicKey.withUnsafeMutableBytes { (pkPtr: UnsafeMutableRawBufferPointer) -> Int32 in
            secretKey.withUnsafeMutableBytes { (skPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                guard let pkBase = pkPtr.baseAddress,
                      let skBase = skPtr.baseAddress else { return -1 }

                return elecrypto_kyber512_generate_keypair(
                    pkBase.assumingMemoryBound(to: UInt8.self),
                    skBase.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        try checkResult(result)

        return Kyber512Keypair(publicKey: publicKey, secretKey: secretKey)
    }

    /// Encapsulate shared secret with Kyber-512
    public static func kyber512Encapsulate(publicKey: Data) throws -> Kyber512EncapsulationResult {
        var ciphertext = Data(count: kyber512CiphertextSize)
        var sharedSecret = Data(count: kyber512SharedSecretSize)

        let result = publicKey.withUnsafeBytes { (pkPtr: UnsafeRawBufferPointer) -> Int32 in
            ciphertext.withUnsafeMutableBytes { (ctPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                sharedSecret.withUnsafeMutableBytes { (ssPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                    guard let pkBase = pkPtr.baseAddress,
                          let ctBase = ctPtr.baseAddress,
                          let ssBase = ssPtr.baseAddress else { return -1 }

                    return elecrypto_kyber512_encapsulate(
                        pkBase.assumingMemoryBound(to: UInt8.self),
                        ctBase.assumingMemoryBound(to: UInt8.self),
                        ssBase.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        try checkResult(result)

        return Kyber512EncapsulationResult(ciphertext: ciphertext, sharedSecret: sharedSecret)
    }

    /// Decapsulate shared secret with Kyber-512
    public static func kyber512Decapsulate(ciphertext: Data, secretKey: Data) throws -> Data {
        var sharedSecret = Data(count: kyber512SharedSecretSize)

        let result = ciphertext.withUnsafeBytes { (ctPtr: UnsafeRawBufferPointer) -> Int32 in
            secretKey.withUnsafeBytes { (skPtr: UnsafeRawBufferPointer) -> Int32 in
                sharedSecret.withUnsafeMutableBytes { (ssPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                    guard let ctBase = ctPtr.baseAddress,
                          let skBase = skPtr.baseAddress,
                          let ssBase = ssPtr.baseAddress else { return -1 }

                    return elecrypto_kyber512_decapsulate(
                        ctBase.assumingMemoryBound(to: UInt8.self),
                        skBase.assumingMemoryBound(to: UInt8.self),
                        ssBase.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        try checkResult(result)

        return sharedSecret
    }

    // MARK: - Dilithium (Post-Quantum Signatures)

    /// Dilithium2 keypair
    public struct Dilithium2Keypair {
        public let publicKey: Data
        public let secretKey: Data
    }

    /// Generate Dilithium2 keypair
    public static func dilithium2GenerateKeypair() throws -> Dilithium2Keypair {
        var publicKey = Data(count: dilithium2PublicKeySize)
        var secretKey = Data(count: dilithium2SecretKeySize)

        let result = publicKey.withUnsafeMutableBytes { (pkPtr: UnsafeMutableRawBufferPointer) -> Int32 in
            secretKey.withUnsafeMutableBytes { (skPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                guard let pkBase = pkPtr.baseAddress,
                      let skBase = skPtr.baseAddress else { return -1 }

                return elecrypto_dilithium2_generate_keypair(
                    pkBase.assumingMemoryBound(to: UInt8.self),
                    skBase.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        try checkResult(result)

        return Dilithium2Keypair(publicKey: publicKey, secretKey: secretKey)
    }

    /// Sign message with Dilithium2
    public static func dilithium2Sign(message: Data, secretKey: Data) throws -> Data {
        var signature = Data(count: dilithium2SignatureSize)

        let result = message.withUnsafeBytes { (msgPtr: UnsafeRawBufferPointer) -> Int32 in
            secretKey.withUnsafeBytes { (skPtr: UnsafeRawBufferPointer) -> Int32 in
                signature.withUnsafeMutableBytes { (sigPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                    guard let msgBase = msgPtr.baseAddress,
                          let skBase = skPtr.baseAddress,
                          let sigBase = sigPtr.baseAddress else { return -1 }

                    return elecrypto_dilithium2_sign(
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

    /// Verify Dilithium2 signature
    public static func dilithium2Verify(message: Data, signature: Data, publicKey: Data) throws -> Bool {
        let result = message.withUnsafeBytes { (msgPtr: UnsafeRawBufferPointer) -> Int32 in
            signature.withUnsafeBytes { (sigPtr: UnsafeRawBufferPointer) -> Int32 in
                publicKey.withUnsafeBytes { (pkPtr: UnsafeRawBufferPointer) -> Int32 in
                    guard let msgBase = msgPtr.baseAddress,
                          let sigBase = sigPtr.baseAddress,
                          let pkBase = pkPtr.baseAddress else { return -1 }

                    return elecrypto_dilithium2_verify(
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

        return true
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

// RSA-OAEP
@_silgen_name("elecrypto_rsa_generate_keypair_2048")
func elecrypto_rsa_generate_keypair_2048(_ publicKey: UnsafeMutablePointer<UInt8>,
                                          _ privateKey: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("elecrypto_rsa_encrypt")
func elecrypto_rsa_encrypt(_ plaintext: UnsafePointer<UInt8>, _ plaintextLen: UInt32,
                            _ publicKey: UnsafePointer<UInt8>, _ publicKeyLen: UInt32,
                            _ ciphertext: UnsafeMutablePointer<UInt8>,
                            _ ciphertextLen: UnsafeMutablePointer<UInt32>) -> Int32

@_silgen_name("elecrypto_rsa_decrypt")
func elecrypto_rsa_decrypt(_ ciphertext: UnsafePointer<UInt8>, _ ciphertextLen: UInt32,
                            _ privateKey: UnsafePointer<UInt8>, _ privateKeyLen: UInt32,
                            _ plaintext: UnsafeMutablePointer<UInt8>,
                            _ plaintextLen: UnsafeMutablePointer<UInt32>) -> Int32

// ECIES
@_silgen_name("elecrypto_ecies_generate_keypair")
func elecrypto_ecies_generate_keypair(_ publicKey: UnsafeMutablePointer<UInt8>,
                                       _ privateKey: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("elecrypto_ecies_encrypt")
func elecrypto_ecies_encrypt(_ plaintext: UnsafePointer<UInt8>, _ plaintextLen: UInt32,
                              _ publicKey: UnsafePointer<UInt8>,
                              _ ciphertext: UnsafeMutablePointer<UInt8>,
                              _ ciphertextLen: UnsafeMutablePointer<UInt32>) -> Int32

@_silgen_name("elecrypto_ecies_decrypt")
func elecrypto_ecies_decrypt(_ ciphertext: UnsafePointer<UInt8>, _ ciphertextLen: UInt32,
                              _ privateKey: UnsafePointer<UInt8>,
                              _ plaintext: UnsafeMutablePointer<UInt8>,
                              _ plaintextLen: UnsafeMutablePointer<UInt32>) -> Int32

// DRBG
@_silgen_name("elecrypto_hmac_drbg_generate")
func elecrypto_hmac_drbg_generate(_ seed: UnsafePointer<UInt8>, _ seedLen: UInt32,
                                   _ output: UnsafeMutablePointer<UInt8>, _ outputLen: UInt32) -> Int32

@_silgen_name("elecrypto_ctr_drbg_generate")
func elecrypto_ctr_drbg_generate(_ seed: UnsafePointer<UInt8>, _ seedLen: UInt32,
                                  _ output: UnsafeMutablePointer<UInt8>, _ outputLen: UInt32) -> Int32

// Kyber
@_silgen_name("elecrypto_kyber512_generate_keypair")
func elecrypto_kyber512_generate_keypair(_ publicKey: UnsafeMutablePointer<UInt8>,
                                          _ secretKey: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("elecrypto_kyber512_encapsulate")
func elecrypto_kyber512_encapsulate(_ publicKey: UnsafePointer<UInt8>,
                                     _ ciphertext: UnsafeMutablePointer<UInt8>,
                                     _ sharedSecret: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("elecrypto_kyber512_decapsulate")
func elecrypto_kyber512_decapsulate(_ ciphertext: UnsafePointer<UInt8>,
                                     _ secretKey: UnsafePointer<UInt8>,
                                     _ sharedSecret: UnsafeMutablePointer<UInt8>) -> Int32

// Dilithium
@_silgen_name("elecrypto_dilithium2_generate_keypair")
func elecrypto_dilithium2_generate_keypair(_ publicKey: UnsafeMutablePointer<UInt8>,
                                            _ secretKey: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("elecrypto_dilithium2_sign")
func elecrypto_dilithium2_sign(_ message: UnsafePointer<UInt8>, _ messageLen: UInt32,
                                _ secretKey: UnsafePointer<UInt8>,
                                _ signature: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("elecrypto_dilithium2_verify")
func elecrypto_dilithium2_verify(_ message: UnsafePointer<UInt8>, _ messageLen: UInt32,
                                  _ signature: UnsafePointer<UInt8>,
                                  _ publicKey: UnsafePointer<UInt8>) -> Int32
