# Elecrypto Java/Android Bindings

Java and Android bindings for the Elecrypto cryptographic library using JNI (Java Native Interface).

## Features

- **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Hash Functions**: SHA-256, SHA-512, BLAKE3
- **Digital Signatures**: Ed25519
- **Random Number Generation**: CSPRNG
- **Android Support**: Compatible with Android NDK

## Installation

### Prerequisites

1. Build the Rust core library:
```bash
cd ../../core
cargo build --release
```

2. The JNI bindings need to be compiled (requires JDK and Android NDK for Android builds)

## Usage

### Java

```java
import com.elecrypto.Elecrypto;
import com.elecrypto.ElecryptoException;

public class Example {
    public static void main(String[] args) {
        try {
            // Hash function
            byte[] hash = Elecrypto.sha256("Hello, World!".getBytes());
            System.out.println("SHA-256: " + bytesToHex(hash));

            // AES-256-GCM encryption
            byte[] key = Elecrypto.aesGenerateKey();
            Elecrypto.EncryptResult result = Elecrypto.aesGcmEncrypt(
                "Secret message".getBytes(),
                key
            );

            byte[] plaintext = Elecrypto.aesGcmDecrypt(
                result.ciphertext,
                key,
                result.nonce
            );

            // Ed25519 signatures
            Elecrypto.Ed25519Keypair keypair = Elecrypto.ed25519GenerateKeypair();
            byte[] signature = Elecrypto.ed25519Sign(
                "Message".getBytes(),
                keypair.secretKey
            );
            boolean valid = Elecrypto.ed25519Verify(
                "Message".getBytes(),
                signature,
                keypair.publicKey
            );

        } catch (ElecryptoException e) {
            System.err.println("Crypto error: " + e.getMessage());
        }
    }
}
```

### Android

```java
import com.elecrypto.Elecrypto;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        try {
            // Generate random bytes
            byte[] random = Elecrypto.randomBytes(32);

            // Encrypt data
            byte[] key = Elecrypto.aesGenerateKey();
            Elecrypto.EncryptResult result = Elecrypto.aesGcmEncrypt(
                data,
                key
            );

            // Store encrypted data securely
            saveToSecureStorage(result.ciphertext, result.nonce);

        } catch (ElecryptoException e) {
            Log.e("Crypto", "Error: " + e.getMessage());
        }
    }
}
```

## API Reference

### Static Methods

- `byte[] randomBytes(int length)` - Generate random bytes
- `byte[] sha256(byte[] data)` - SHA-256 hash
- `byte[] aesGenerateKey()` - Generate AES-256 key
- `EncryptResult aesGcmEncrypt(byte[] plaintext, byte[] key)` - Encrypt with AES-GCM
- `byte[] aesGcmDecrypt(byte[] ciphertext, byte[] key, byte[] nonce)` - Decrypt with AES-GCM
- `Ed25519Keypair ed25519GenerateKeypair()` - Generate Ed25519 keypair
- `byte[] ed25519Sign(byte[] message, byte[] secretKey)` - Sign message
- `boolean ed25519Verify(byte[] message, byte[] signature, byte[] publicKey)` - Verify signature

### Inner Classes

```java
// Encryption result
class EncryptResult {
    public final byte[] ciphertext;
    public final byte[] nonce;
}

// Ed25519 keypair
class Ed25519Keypair {
    public final byte[] publicKey;
    public final byte[] secretKey;
}
```

### Exception

```java
class ElecryptoException extends Exception {
    public int getErrorCode();
}
```

## Building for Android

1. Add to your `build.gradle`:
```gradle
android {
    defaultConfig {
        ndk {
            abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'
        }
    }
}
```

2. Place the compiled native libraries in:
```
src/main/jniLibs/arm64-v8a/libelecrypto_core.so
src/main/jniLibs/armeabi-v7a/libelecrypto_core.so
src/main/jniLibs/x86/libelecrypto_core.so
src/main/jniLibs/x86_64/libelecrypto_core.so
```

## Constants

```java
public static final int AES_KEY_SIZE = 32;
public static final int AES_NONCE_SIZE = 12;
public static final int CHACHA20_KEY_SIZE = 32;
public static final int ED25519_PUBLIC_KEY_SIZE = 32;
public static final int ED25519_SECRET_KEY_SIZE = 32;
public static final int ED25519_SIGNATURE_SIZE = 64;
```

## License

MIT License

## Note

JNI bindings require compilation. The Java classes define the interface,
but the actual JNI implementation (C code) needs to be built separately
to connect to the Rust core library.
