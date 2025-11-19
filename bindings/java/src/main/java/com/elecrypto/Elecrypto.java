package com.elecrypto;

/**
 * Elecrypto - Cross-platform Cryptographic Library
 * Java/Android bindings using JNI
 */
public class Elecrypto {
    // Load native library
    static {
        try {
            System.loadLibrary("elecrypto_core");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Failed to load elecrypto_core library: " + e.getMessage());
            throw e;
        }
    }

    // Error codes
    public static final int SUCCESS = 0;
    public static final int ERROR_INVALID_INPUT = -1;
    public static final int ERROR_INVALID_KEY_LENGTH = -2;
    public static final int ERROR_ENCRYPTION_FAILED = -5;
    public static final int ERROR_DECRYPTION_FAILED = -6;

    // Constants
    public static final int AES_KEY_SIZE = 32;
    public static final int AES_NONCE_SIZE = 12;
    public static final int CHACHA20_KEY_SIZE = 32;
    public static final int ED25519_PUBLIC_KEY_SIZE = 32;
    public static final int ED25519_SECRET_KEY_SIZE = 32;
    public static final int ED25519_SIGNATURE_SIZE = 64;

    // RSA constants
    public static final int RSA2048_PUBLIC_KEY_SIZE = 294;
    public static final int RSA2048_PRIVATE_KEY_SIZE = 1218;

    // ECIES constants
    public static final int ECIES_PUBLIC_KEY_SIZE = 65;
    public static final int ECIES_PRIVATE_KEY_SIZE = 32;

    // Kyber constants
    public static final int KYBER512_PUBLIC_KEY_SIZE = 800;
    public static final int KYBER512_SECRET_KEY_SIZE = 1632;
    public static final int KYBER512_CIPHERTEXT_SIZE = 768;
    public static final int KYBER512_SHARED_SECRET_SIZE = 32;

    // Dilithium constants
    public static final int DILITHIUM2_PUBLIC_KEY_SIZE = 1312;
    public static final int DILITHIUM2_SECRET_KEY_SIZE = 2560;
    public static final int DILITHIUM2_SIGNATURE_SIZE = 2420;

    // Native methods
    private static native int nativeRandomBytes(byte[] output, int length);
    private static native int nativeSha256(byte[] input, int inputLen, byte[] output);
    private static native int nativeAesGenerateKey(byte[] key);
    private static native int nativeAesGcmEncrypt(byte[] plaintext, int plaintextLen,
        byte[] key, byte[] nonce, byte[] ciphertext, byte[] nonceOut);
    private static native int nativeAesGcmDecrypt(byte[] ciphertext, int ciphertextLen,
        byte[] key, byte[] nonce, byte[] plaintext);
    private static native int nativeEd25519GenerateKeypair(byte[] publicKey, byte[] secretKey);
    private static native int nativeEd25519Sign(byte[] message, int messageLen,
        byte[] secretKey, byte[] signature);
    private static native int nativeEd25519Verify(byte[] message, int messageLen,
        byte[] signature, byte[] publicKey);

    // RSA native methods
    private static native int nativeRsaGenerateKeypair2048(byte[] publicKey, byte[] privateKey);
    private static native int nativeRsaEncrypt(byte[] plaintext, int plaintextLen,
        byte[] publicKey, int publicKeyLen, byte[] ciphertext, int[] ciphertextLen);
    private static native int nativeRsaDecrypt(byte[] ciphertext, int ciphertextLen,
        byte[] privateKey, int privateKeyLen, byte[] plaintext, int[] plaintextLen);

    // ECIES native methods
    private static native int nativeEciesGenerateKeypair(byte[] publicKey, byte[] privateKey);
    private static native int nativeEciesEncrypt(byte[] plaintext, int plaintextLen,
        byte[] publicKey, byte[] ciphertext, int[] ciphertextLen);
    private static native int nativeEciesDecrypt(byte[] ciphertext, int ciphertextLen,
        byte[] privateKey, byte[] plaintext, int[] plaintextLen);

    // DRBG native methods
    private static native int nativeHmacDrbgGenerate(byte[] seed, int seedLen,
        byte[] output, int outputLen);
    private static native int nativeCtrDrbgGenerate(byte[] seed, int seedLen,
        byte[] output, int outputLen);

    // Kyber native methods
    private static native int nativeKyber512GenerateKeypair(byte[] publicKey, byte[] secretKey);
    private static native int nativeKyber512Encapsulate(byte[] publicKey,
        byte[] ciphertext, byte[] sharedSecret);
    private static native int nativeKyber512Decapsulate(byte[] ciphertext,
        byte[] secretKey, byte[] sharedSecret);

    // Dilithium native methods
    private static native int nativeDilithium2GenerateKeypair(byte[] publicKey, byte[] secretKey);
    private static native int nativeDilithium2Sign(byte[] message, int messageLen,
        byte[] secretKey, byte[] signature);
    private static native int nativeDilithium2Verify(byte[] message, int messageLen,
        byte[] signature, byte[] publicKey);

    /**
     * Generate cryptographically secure random bytes
     */
    public static byte[] randomBytes(int length) throws ElecryptoException {
        byte[] output = new byte[length];
        int result = nativeRandomBytes(output, length);
        if (result < 0) {
            throw new ElecryptoException(result, "Failed to generate random bytes");
        }
        return output;
    }

    /**
     * Compute SHA-256 hash
     */
    public static byte[] sha256(byte[] data) throws ElecryptoException {
        byte[] hash = new byte[32];
        int result = nativeSha256(data, data.length, hash);
        if (result < 0) {
            throw new ElecryptoException(result, "SHA-256 hash failed");
        }
        return hash;
    }

    /**
     * Generate AES-256 key
     */
    public static byte[] aesGenerateKey() throws ElecryptoException {
        byte[] key = new byte[AES_KEY_SIZE];
        int result = nativeAesGenerateKey(key);
        if (result < 0) {
            throw new ElecryptoException(result, "Key generation failed");
        }
        return key;
    }

    /**
     * Encrypt with AES-256-GCM
     */
    public static EncryptResult aesGcmEncrypt(byte[] plaintext, byte[] key) throws ElecryptoException {
        if (key.length != AES_KEY_SIZE) {
            throw new IllegalArgumentException("Key must be 32 bytes");
        }

        byte[] ciphertext = new byte[plaintext.length + 16];
        byte[] nonce = new byte[AES_NONCE_SIZE];

        int result = nativeAesGcmEncrypt(plaintext, plaintext.length, key, null, ciphertext, nonce);
        if (result < 0) {
            throw new ElecryptoException(result, "Encryption failed");
        }

        return new EncryptResult(ciphertext, nonce);
    }

    /**
     * Decrypt with AES-256-GCM
     */
    public static byte[] aesGcmDecrypt(byte[] ciphertext, byte[] key, byte[] nonce) throws ElecryptoException {
        if (key.length != AES_KEY_SIZE) {
            throw new IllegalArgumentException("Key must be 32 bytes");
        }

        byte[] plaintext = new byte[ciphertext.length - 16];

        int result = nativeAesGcmDecrypt(ciphertext, ciphertext.length, key, nonce, plaintext);
        if (result < 0) {
            throw new ElecryptoException(result, "Decryption failed");
        }

        return plaintext;
    }

    /**
     * Generate Ed25519 keypair
     */
    public static Ed25519Keypair ed25519GenerateKeypair() throws ElecryptoException {
        byte[] publicKey = new byte[ED25519_PUBLIC_KEY_SIZE];
        byte[] secretKey = new byte[ED25519_SECRET_KEY_SIZE];

        int result = nativeEd25519GenerateKeypair(publicKey, secretKey);
        if (result < 0) {
            throw new ElecryptoException(result, "Keypair generation failed");
        }

        return new Ed25519Keypair(publicKey, secretKey);
    }

    /**
     * Sign message with Ed25519
     */
    public static byte[] ed25519Sign(byte[] message, byte[] secretKey) throws ElecryptoException {
        byte[] signature = new byte[ED25519_SIGNATURE_SIZE];

        int result = nativeEd25519Sign(message, message.length, secretKey, signature);
        if (result < 0) {
            throw new ElecryptoException(result, "Signing failed");
        }

        return signature;
    }

    /**
     * Verify Ed25519 signature
     */
    public static boolean ed25519Verify(byte[] message, byte[] signature, byte[] publicKey) throws ElecryptoException {
        int result = nativeEd25519Verify(message, message.length, signature, publicKey);
        if (result < 0) {
            throw new ElecryptoException(result, "Verification failed");
        }

        return result == 1;
    }

    /**
     * Result of encryption operation
     */
    public static class EncryptResult {
        public final byte[] ciphertext;
        public final byte[] nonce;

        public EncryptResult(byte[] ciphertext, byte[] nonce) {
            this.ciphertext = ciphertext;
            this.nonce = nonce;
        }
    }

    /**
     * Ed25519 keypair
     */
    public static class Ed25519Keypair {
        public final byte[] publicKey;
        public final byte[] secretKey;

        public Ed25519Keypair(byte[] publicKey, byte[] secretKey) {
            this.publicKey = publicKey;
            this.secretKey = secretKey;
        }
    }

    // RSA-OAEP Methods

    /**
     * Generate RSA-2048 keypair
     */
    public static RsaKeypair rsaGenerateKeypair() throws ElecryptoException {
        byte[] publicKey = new byte[RSA2048_PUBLIC_KEY_SIZE];
        byte[] privateKey = new byte[RSA2048_PRIVATE_KEY_SIZE];

        int result = nativeRsaGenerateKeypair2048(publicKey, privateKey);
        if (result < 0) {
            throw new ElecryptoException(result, "RSA keypair generation failed");
        }

        return new RsaKeypair(publicKey, privateKey);
    }

    /**
     * Encrypt with RSA-OAEP
     */
    public static byte[] rsaEncrypt(byte[] plaintext, byte[] publicKey) throws ElecryptoException {
        byte[] ciphertext = new byte[256];
        int[] ciphertextLen = new int[1];

        int result = nativeRsaEncrypt(plaintext, plaintext.length,
            publicKey, publicKey.length, ciphertext, ciphertextLen);
        if (result < 0) {
            throw new ElecryptoException(result, "RSA encryption failed");
        }

        byte[] output = new byte[ciphertextLen[0]];
        System.arraycopy(ciphertext, 0, output, 0, ciphertextLen[0]);
        return output;
    }

    /**
     * Decrypt with RSA-OAEP
     */
    public static byte[] rsaDecrypt(byte[] ciphertext, byte[] privateKey) throws ElecryptoException {
        byte[] plaintext = new byte[256];
        int[] plaintextLen = new int[1];

        int result = nativeRsaDecrypt(ciphertext, ciphertext.length,
            privateKey, privateKey.length, plaintext, plaintextLen);
        if (result < 0) {
            throw new ElecryptoException(result, "RSA decryption failed");
        }

        byte[] output = new byte[plaintextLen[0]];
        System.arraycopy(plaintext, 0, output, 0, plaintextLen[0]);
        return output;
    }

    // ECIES Methods

    /**
     * Generate ECIES keypair
     */
    public static EciesKeypair eciesGenerateKeypair() throws ElecryptoException {
        byte[] publicKey = new byte[ECIES_PUBLIC_KEY_SIZE];
        byte[] privateKey = new byte[ECIES_PRIVATE_KEY_SIZE];

        int result = nativeEciesGenerateKeypair(publicKey, privateKey);
        if (result < 0) {
            throw new ElecryptoException(result, "ECIES keypair generation failed");
        }

        return new EciesKeypair(publicKey, privateKey);
    }

    /**
     * Encrypt with ECIES
     */
    public static byte[] eciesEncrypt(byte[] plaintext, byte[] publicKey) throws ElecryptoException {
        int maxLen = 65 + 12 + plaintext.length + 16;
        byte[] ciphertext = new byte[maxLen];
        int[] ciphertextLen = new int[1];

        int result = nativeEciesEncrypt(plaintext, plaintext.length,
            publicKey, ciphertext, ciphertextLen);
        if (result < 0) {
            throw new ElecryptoException(result, "ECIES encryption failed");
        }

        byte[] output = new byte[ciphertextLen[0]];
        System.arraycopy(ciphertext, 0, output, 0, ciphertextLen[0]);
        return output;
    }

    /**
     * Decrypt with ECIES
     */
    public static byte[] eciesDecrypt(byte[] ciphertext, byte[] privateKey) throws ElecryptoException {
        int maxLen = ciphertext.length - 65 - 12 - 16;
        if (maxLen < 1) maxLen = 1;
        byte[] plaintext = new byte[maxLen];
        int[] plaintextLen = new int[1];

        int result = nativeEciesDecrypt(ciphertext, ciphertext.length,
            privateKey, plaintext, plaintextLen);
        if (result < 0) {
            throw new ElecryptoException(result, "ECIES decryption failed");
        }

        byte[] output = new byte[plaintextLen[0]];
        System.arraycopy(plaintext, 0, output, 0, plaintextLen[0]);
        return output;
    }

    // DRBG Methods

    /**
     * Generate random bytes using HMAC-DRBG
     */
    public static byte[] hmacDrbgGenerate(byte[] seed, int outputLen) throws ElecryptoException {
        byte[] output = new byte[outputLen];

        int result = nativeHmacDrbgGenerate(seed, seed.length, output, outputLen);
        if (result < 0) {
            throw new ElecryptoException(result, "HMAC-DRBG generation failed");
        }

        return output;
    }

    /**
     * Generate random bytes using CTR-DRBG
     */
    public static byte[] ctrDrbgGenerate(byte[] seed, int outputLen) throws ElecryptoException {
        byte[] output = new byte[outputLen];

        int result = nativeCtrDrbgGenerate(seed, seed.length, output, outputLen);
        if (result < 0) {
            throw new ElecryptoException(result, "CTR-DRBG generation failed");
        }

        return output;
    }

    // Kyber Methods

    /**
     * Generate Kyber-512 keypair
     */
    public static Kyber512Keypair kyber512GenerateKeypair() throws ElecryptoException {
        byte[] publicKey = new byte[KYBER512_PUBLIC_KEY_SIZE];
        byte[] secretKey = new byte[KYBER512_SECRET_KEY_SIZE];

        int result = nativeKyber512GenerateKeypair(publicKey, secretKey);
        if (result < 0) {
            throw new ElecryptoException(result, "Kyber keypair generation failed");
        }

        return new Kyber512Keypair(publicKey, secretKey);
    }

    /**
     * Encapsulate shared secret with Kyber-512
     */
    public static Kyber512EncapsulationResult kyber512Encapsulate(byte[] publicKey) throws ElecryptoException {
        byte[] ciphertext = new byte[KYBER512_CIPHERTEXT_SIZE];
        byte[] sharedSecret = new byte[KYBER512_SHARED_SECRET_SIZE];

        int result = nativeKyber512Encapsulate(publicKey, ciphertext, sharedSecret);
        if (result < 0) {
            throw new ElecryptoException(result, "Kyber encapsulation failed");
        }

        return new Kyber512EncapsulationResult(ciphertext, sharedSecret);
    }

    /**
     * Decapsulate shared secret with Kyber-512
     */
    public static byte[] kyber512Decapsulate(byte[] ciphertext, byte[] secretKey) throws ElecryptoException {
        byte[] sharedSecret = new byte[KYBER512_SHARED_SECRET_SIZE];

        int result = nativeKyber512Decapsulate(ciphertext, secretKey, sharedSecret);
        if (result < 0) {
            throw new ElecryptoException(result, "Kyber decapsulation failed");
        }

        return sharedSecret;
    }

    // Dilithium Methods

    /**
     * Generate Dilithium2 keypair
     */
    public static Dilithium2Keypair dilithium2GenerateKeypair() throws ElecryptoException {
        byte[] publicKey = new byte[DILITHIUM2_PUBLIC_KEY_SIZE];
        byte[] secretKey = new byte[DILITHIUM2_SECRET_KEY_SIZE];

        int result = nativeDilithium2GenerateKeypair(publicKey, secretKey);
        if (result < 0) {
            throw new ElecryptoException(result, "Dilithium keypair generation failed");
        }

        return new Dilithium2Keypair(publicKey, secretKey);
    }

    /**
     * Sign with Dilithium2
     */
    public static byte[] dilithium2Sign(byte[] message, byte[] secretKey) throws ElecryptoException {
        byte[] signature = new byte[DILITHIUM2_SIGNATURE_SIZE];

        int result = nativeDilithium2Sign(message, message.length, secretKey, signature);
        if (result < 0) {
            throw new ElecryptoException(result, "Dilithium signing failed");
        }

        return signature;
    }

    /**
     * Verify Dilithium2 signature
     */
    public static boolean dilithium2Verify(byte[] message, byte[] signature, byte[] publicKey) throws ElecryptoException {
        int result = nativeDilithium2Verify(message, message.length, signature, publicKey);
        if (result < 0) {
            throw new ElecryptoException(result, "Dilithium verification failed");
        }

        return true;
    }

    // Additional result classes

    /**
     * RSA keypair
     */
    public static class RsaKeypair {
        public final byte[] publicKey;
        public final byte[] privateKey;

        public RsaKeypair(byte[] publicKey, byte[] privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
    }

    /**
     * ECIES keypair
     */
    public static class EciesKeypair {
        public final byte[] publicKey;
        public final byte[] privateKey;

        public EciesKeypair(byte[] publicKey, byte[] privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
    }

    /**
     * Kyber-512 keypair
     */
    public static class Kyber512Keypair {
        public final byte[] publicKey;
        public final byte[] secretKey;

        public Kyber512Keypair(byte[] publicKey, byte[] secretKey) {
            this.publicKey = publicKey;
            this.secretKey = secretKey;
        }
    }

    /**
     * Kyber-512 encapsulation result
     */
    public static class Kyber512EncapsulationResult {
        public final byte[] ciphertext;
        public final byte[] sharedSecret;

        public Kyber512EncapsulationResult(byte[] ciphertext, byte[] sharedSecret) {
            this.ciphertext = ciphertext;
            this.sharedSecret = sharedSecret;
        }
    }

    /**
     * Dilithium2 keypair
     */
    public static class Dilithium2Keypair {
        public final byte[] publicKey;
        public final byte[] secretKey;

        public Dilithium2Keypair(byte[] publicKey, byte[] secretKey) {
            this.publicKey = publicKey;
            this.secretKey = secretKey;
        }
    }
}
