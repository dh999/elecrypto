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
}
