#!/usr/bin/env node
/**
 * Basic Elecrypto usage examples for Node.js
 */

const elecrypto = require('../dist/index');

console.log('=== Elecrypto Node.js Bindings Examples ===\n');

// 1. Hash functions
console.log('1. Hash Functions');
const message = Buffer.from('Hello, Elecrypto!');

const sha256Hash = elecrypto.sha256(message);
console.log(`SHA-256: ${sha256Hash.toString('hex')}`);

const sha512Hash = elecrypto.sha512(message);
console.log(`SHA-512: ${sha512Hash.toString('hex').slice(0, 64)}...`);

const blake3Hash = elecrypto.blake3(message);
console.log(`BLAKE3:  ${blake3Hash.toString('hex')}\n`);

// 2. Random number generation
console.log('2. Random Number Generation');
const randomData = elecrypto.randomBytes(32);
console.log(`32 random bytes: ${randomData.toString('hex')}\n`);

// 3. AES-GCM encryption
console.log('3. AES-256-GCM Encryption');
const plaintext = Buffer.from('This is a secret message!');
const aesKey = elecrypto.aesGenerateKey();
console.log(`Generated key: ${aesKey.toString('hex')}`);

const { ciphertext: aesCiphertext, nonce: aesNonce } = elecrypto.aesGcmEncrypt(plaintext, aesKey);
console.log(`Ciphertext: ${aesCiphertext.toString('hex')}`);
console.log(`Nonce: ${aesNonce.toString('hex')}`);

const aesDecrypted = elecrypto.aesGcmDecrypt(aesCiphertext, aesKey, aesNonce);
console.log(`Decrypted: ${aesDecrypted.toString()}`);
console.log('✓ Encryption/Decryption successful\n');

// 4. ChaCha20-Poly1305 encryption
console.log('4. ChaCha20-Poly1305 Encryption');
const chachaKey = elecrypto.chacha20GenerateKey();
const { ciphertext: chachaCiphertext, nonce: chachaNonce } = elecrypto.chacha20Poly1305Encrypt(plaintext, chachaKey);
console.log(`Ciphertext: ${chachaCiphertext.toString('hex')}`);

const chachaDecrypted = elecrypto.chacha20Poly1305Decrypt(chachaCiphertext, chachaKey, chachaNonce);
console.log(`Decrypted: ${chachaDecrypted.toString()}`);
console.log('✓ ChaCha20 encryption successful\n');

// 5. Digital signatures (Ed25519)
console.log('5. Ed25519 Digital Signatures');
const { publicKey, secretKey } = elecrypto.ed25519GenerateKeypair();
console.log(`Public key: ${publicKey.toString('hex')}`);
console.log(`Secret key: ${secretKey.toString('hex').slice(0, 32)}...`);

const signMessage = Buffer.from('Sign this important message');
const signature = elecrypto.ed25519Sign(signMessage, secretKey);
console.log(`Signature: ${signature.toString('hex').slice(0, 32)}...`);

const isValid = elecrypto.ed25519Verify(signMessage, signature, publicKey);
console.log(`Signature valid: ${isValid}`);

// Try with wrong message
const wrongMessage = Buffer.from('Different message');
const isValidWrong = elecrypto.ed25519Verify(wrongMessage, signature, publicKey);
console.log(`Wrong message valid: ${isValidWrong}`);
console.log('✓ Digital signature successful\n');

// 6. Key derivation (PBKDF2)
console.log('6. Key Derivation - PBKDF2');
const password = Buffer.from('super_secret_password');
const pbkdf2Salt = elecrypto.randomBytes(16);

const pbkdf2Key = elecrypto.pbkdf2(password, pbkdf2Salt, 100000, 32);
console.log(`Derived key: ${pbkdf2Key.toString('hex')}`);
console.log('✓ PBKDF2 successful\n');

// 7. Key derivation (Argon2id)
console.log('7. Key Derivation - Argon2id');
const { derivedKey, salt } = elecrypto.argon2id(password, undefined, 65536, 3, 4, 32);
console.log(`Derived key: ${derivedKey.toString('hex')}`);
console.log(`Salt: ${salt.toString('hex')}`);
console.log('✓ Argon2id successful\n');

// 8. HKDF
console.log('8. HKDF Key Derivation');
const inputKey = elecrypto.randomBytes(32);
const info = Buffer.from('application context');

const hkdfKey = elecrypto.hkdf(inputKey, undefined, info, 64);
console.log(`Derived key (64 bytes): ${hkdfKey.toString('hex')}`);
console.log('✓ HKDF successful\n');

console.log('=== All tests passed! ===');
