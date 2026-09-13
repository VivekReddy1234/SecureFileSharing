import { describe, it, expect } from 'vitest';
import {
  generateAesKey,
  importAesKey,
  exportAesKey,
  aesEncrypt,
  aesDecrypt,
  generateRsaKeyPair,
  exportPublicKey,
  importPublicKey,
  exportPrivateKey,
  importPrivateKey,
  rsaWrapKey,
  rsaUnwrapKey,
  deriveMasterKey,
  deriveBitsWithHkdf,
  deriveAuthKey,
  deriveShareLinkKey,
  wrapPrivateKey,
  unwrapPrivateKey,
  wrapPrivateKeyWithRecoveryKey,
  unwrapPrivateKeyWithRecoveryKey,
  buildManifest,
  encryptManifest,
  decryptManifest,
  generateIv,
  generateSalt,
  generateRecoveryKey,
  stringToBytes,
  bytesToString,
  uint32ToBytes,
  toBase64,
  toBase64Url,
  fromBase64Url,
  HKDF_CONTEXT,
} from '../index';

describe('Cryptographic Architecture & Primitives Verification', () => {
  describe('AES-256-GCM', () => {
    it('encrypts plaintext into distinct ciphertext', async () => {
      const key = await generateAesKey();
      const plaintext = stringToBytes('Sensitive file plaintext');
      const { ciphertext, iv } = await aesEncrypt(key, plaintext);

      expect(ciphertext).toBeDefined();
      expect(iv).toHaveLength(12);
      expect(ciphertext).not.toEqual(plaintext);
    });

    it('successfully decrypts back to original plaintext', async () => {
      const key = await generateAesKey();
      const original = 'Zero-Knowledge E2EE Verification Payload 12345!@#$%';
      const plaintext = stringToBytes(original);
      const { ciphertext, iv } = await aesEncrypt(key, plaintext);

      const decrypted = await aesDecrypt(key, ciphertext, iv);
      expect(bytesToString(decrypted)).toBe(original);
    });

    it('fails decryption with wrong key', async () => {
      const key1 = await generateAesKey();
      const key2 = await generateAesKey();
      const plaintext = stringToBytes('Secret message');
      const { ciphertext, iv } = await aesEncrypt(key1, plaintext);

      await expect(aesDecrypt(key2, ciphertext, iv)).rejects.toThrow();
    });

    it('fails decryption with bit-flipped ciphertext (GCM authentication integrity)', async () => {
      const key = await generateAesKey();
      const plaintext = stringToBytes('Authenticity check payload');
      const { ciphertext, iv } = await aesEncrypt(key, plaintext);

      // Tamper with a single byte in ciphertext
      const tampered = new Uint8Array(ciphertext);
      tampered[5] ^= 0x01;

      await expect(aesDecrypt(key, tampered, iv)).rejects.toThrow();
    });

    it('fails decryption with modified IV', async () => {
      const key = await generateAesKey();
      const plaintext = stringToBytes('IV integrity check');
      const { ciphertext, iv } = await aesEncrypt(key, plaintext);

      const tamperedIv = new Uint8Array(iv);
      tamperedIv[0] ^= 0x01;

      await expect(aesDecrypt(key, ciphertext, tamperedIv)).rejects.toThrow();
    });

    it('enforces Additional Authenticated Data (AAD) chunk index binding', async () => {
      const key = await generateAesKey();
      const chunkData = stringToBytes('Chunk #0 payload');
      const aadChunk0 = uint32ToBytes(0);
      const aadChunk1 = uint32ToBytes(1);

      const { ciphertext, iv } = await aesEncrypt(key, chunkData, aadChunk0);

      // Decrypting with correct AAD succeeds
      const decrypted = await aesDecrypt(key, ciphertext, iv, aadChunk0);
      expect(bytesToString(decrypted)).toBe('Chunk #0 payload');

      // Decrypting with swapped/modified AAD (e.g. chunk index 1) MUST fail
      await expect(aesDecrypt(key, ciphertext, iv, aadChunk1)).rejects.toThrow();
    });

    it('produces unique IVs and ciphertexts for identical plaintext (no nonce reuse)', async () => {
      const key = await generateAesKey();
      const plaintext = stringToBytes('Same exact plaintext');

      const enc1 = await aesEncrypt(key, plaintext);
      const enc2 = await aesEncrypt(key, plaintext);

      expect(toBase64(enc1.iv)).not.toBe(toBase64(enc2.iv));
      expect(toBase64(enc1.ciphertext)).not.toBe(toBase64(enc2.ciphertext));
    });

    it('exports and re-imports AES key accurately', async () => {
      const key = await generateAesKey();
      const raw = await exportAesKey(key);
      expect(raw).toHaveLength(32); // 256 bits

      const imported = await importAesKey(raw);
      const plaintext = stringToBytes('Export import verification');
      const { ciphertext, iv } = await aesEncrypt(imported, plaintext);
      const decrypted = await aesDecrypt(key, ciphertext, iv);
      expect(bytesToString(decrypted)).toBe('Export import verification');
    });
  });

  describe('RSA-OAEP 3072-bit Key Wrapping', () => {
    it('generates 3072-bit RSA keypair, wraps, and unwraps AES DEK', async () => {
      const rsaPair = await generateRsaKeyPair();
      const dek = await generateAesKey();

      const wrappedKeyBase64 = await rsaWrapKey(dek, rsaPair.publicKey);
      expect(typeof wrappedKeyBase64).toBe('string');
      expect(wrappedKeyBase64.length).toBeGreaterThan(100);

      const unwrappedDek = await rsaUnwrapKey(wrappedKeyBase64, rsaPair.privateKey);

      // Verify unwrapped DEK works for encryption/decryption
      const plaintext = stringToBytes('Payload for DEK verification');
      const enc = await aesEncrypt(dek, plaintext);
      const dec = await aesDecrypt(unwrappedDek, enc.ciphertext, enc.iv);
      expect(bytesToString(dec)).toBe('Payload for DEK verification');
    });

    it('exports and imports RSA public and private keys (SPKI/PKCS8)', async () => {
      const rsaPair = await generateRsaKeyPair();

      const pubBase64 = await exportPublicKey(rsaPair.publicKey);
      const privBase64 = await exportPrivateKey(rsaPair.privateKey);

      expect(typeof pubBase64).toBe('string');
      expect(typeof privBase64).toBe('string');

      const importedPub = await importPublicKey(pubBase64);
      const importedPriv = await importPrivateKey(privBase64);

      const dek = await generateAesKey();
      const wrapped = await rsaWrapKey(dek, importedPub);
      const unwrapped = await rsaUnwrapKey(wrapped, importedPriv);

      const plaintext = stringToBytes('Round-trip key import test');
      const enc = await aesEncrypt(unwrapped, plaintext);
      const dec = await aesDecrypt(dek, enc.ciphertext, enc.iv);
      expect(bytesToString(dec)).toBe('Round-trip key import test');
    });
  });

  describe('Key Derivation (PBKDF2 & HKDF)', () => {
    it('derives master key and auth key deterministically for identical inputs', async () => {
      const password = 'CorrectHorseBatteryStaple123!';
      const salt = generateSalt();

      const { masterKey: m1, authKey: a1 } = await deriveAuthKey(password, salt, 600_000);
      const { masterKey: m2, authKey: a2 } = await deriveAuthKey(password, salt, 600_000);

      expect(toBase64(a1)).toBe(toBase64(a2));

      // Different salt produces completely different auth key
      const salt2 = generateSalt();
      const { authKey: a3 } = await deriveAuthKey(password, salt2, 600_000);
      expect(toBase64(a1)).not.toBe(toBase64(a3));
    });

    it('enforces domain separation via HKDF context strings', async () => {
      const password = 'StrongPassword!2026';
      const salt = generateSalt();
      const masterKey = await deriveMasterKey(password, salt, 600_000);

      const authBits = await deriveBitsWithHkdf(masterKey, HKDF_CONTEXT.AUTH);
      const privKeyWrapBits = await deriveBitsWithHkdf(masterKey, HKDF_CONTEXT.PRIVATE_KEY_WRAP);
      const recoveryBits = await deriveBitsWithHkdf(masterKey, HKDF_CONTEXT.RECOVERY_WRAP);

      expect(toBase64(authBits)).not.toBe(toBase64(privKeyWrapBits));
      expect(toBase64(authBits)).not.toBe(toBase64(recoveryBits));
      expect(toBase64(privKeyWrapBits)).not.toBe(toBase64(recoveryBits));
    });

    it('rejects PBKDF2 iterations below the 600,000 security baseline', async () => {
      const salt = generateSalt();
      await expect(deriveMasterKey('pass', salt, 599_999)).rejects.toThrow(/below minimum/);
    });
  });

  describe('User Private Key Lifecycle & Recovery Key', () => {
    it('wraps and unwraps private key under master key', async () => {
      const password = 'UserSecureMasterPassword#99';
      const salt = generateSalt();
      const { masterKey } = await deriveAuthKey(password, salt, 600_000);

      const rsaPair = await generateRsaKeyPair();
      const { wrappedPrivateKeyBase64, wrappedPrivateKeyIvBase64 } = await wrapPrivateKey(
        rsaPair.privateKey,
        masterKey
      );

      const unwrappedPrivKey = await unwrapPrivateKey(
        wrappedPrivateKeyBase64,
        wrappedPrivateKeyIvBase64,
        masterKey
      );

      // Verify functionality of unwrapped private key
      const dek = await generateAesKey();
      const wrappedDek = await rsaWrapKey(dek, rsaPair.publicKey);
      const unwrappedDek = await rsaUnwrapKey(wrappedDek, unwrappedPrivKey);

      const plaintext = stringToBytes('Lifecycle private key wrap test');
      const enc = await aesEncrypt(dek, plaintext);
      const dec = await aesDecrypt(unwrappedDek, enc.ciphertext, enc.iv);
      expect(bytesToString(dec)).toBe('Lifecycle private key wrap test');
    });

    it('wraps and unwraps private key under 256-bit recovery key', async () => {
      const rsaPair = await generateRsaKeyPair();
      const recoveryKey = generateRecoveryKey();
      expect(recoveryKey).toHaveLength(32);

      const { recoveryWrappedPrivateKeyBase64, recoveryWrappedKeyIvBase64 } =
        await wrapPrivateKeyWithRecoveryKey(rsaPair.privateKey, recoveryKey);

      const unwrappedPrivKey = await unwrapPrivateKeyWithRecoveryKey(
        recoveryWrappedPrivateKeyBase64,
        recoveryWrappedKeyIvBase64,
        recoveryKey
      );

      const dek = await generateAesKey();
      const wrappedDek = await rsaWrapKey(dek, rsaPair.publicKey);
      const unwrappedDek = await rsaUnwrapKey(wrappedDek, unwrappedPrivKey);

      const plaintext = stringToBytes('Recovery key recovery test');
      const enc = await aesEncrypt(dek, plaintext);
      const dec = await aesDecrypt(unwrappedDek, enc.ciphertext, enc.iv);
      expect(bytesToString(dec)).toBe('Recovery key recovery test');
    });

    it('fails to unwrap private key with wrong recovery key', async () => {
      const rsaPair = await generateRsaKeyPair();
      const recoveryKey1 = generateRecoveryKey();
      const recoveryKey2 = generateRecoveryKey();

      const { recoveryWrappedPrivateKeyBase64, recoveryWrappedKeyIvBase64 } =
        await wrapPrivateKeyWithRecoveryKey(rsaPair.privateKey, recoveryKey1);

      await expect(
        unwrapPrivateKeyWithRecoveryKey(
          recoveryWrappedPrivateKeyBase64,
          recoveryWrappedKeyIvBase64,
          recoveryKey2
        )
      ).rejects.toThrow();
    });
  });

  describe('Share Link Key Derivation', () => {
    it('derives share link key without password', async () => {
      const linkSecret = generateRecoveryKey(); // 32 bytes
      const key1 = await deriveShareLinkKey(linkSecret);
      const key2 = await deriveShareLinkKey(linkSecret);

      const plaintext = stringToBytes('Public link data');
      const enc = await aesEncrypt(key1, plaintext);
      const dec = await aesDecrypt(key2, enc.ciphertext, enc.iv);
      expect(bytesToString(dec)).toBe('Public link data');
    });

    it('derives share link key with password protection and rejects wrong password', async () => {
      const linkSecret = generateRecoveryKey();
      const correctPassword = 'ShareLinkSecretPassword!2026';
      const wrongPassword = 'WrongPassword!';

      const keyCorrect = await deriveShareLinkKey(linkSecret, correctPassword);
      const keyWrong = await deriveShareLinkKey(linkSecret, wrongPassword);

      const plaintext = stringToBytes('Password-protected link data');
      const enc = await aesEncrypt(keyCorrect, plaintext);

      // Decrypting with correct key succeeds
      const dec = await aesDecrypt(keyCorrect, enc.ciphertext, enc.iv);
      expect(bytesToString(dec)).toBe('Password-protected link data');

      // Decrypting with wrong key fails
      await expect(aesDecrypt(keyWrong, enc.ciphertext, enc.iv)).rejects.toThrow();
    });
  });

  describe('File Manifest & Chunk Integrity', () => {
    it('builds, encrypts, and decrypts file manifest cleanly', async () => {
      const dek = await generateAesKey();
      const manifest = buildManifest('financial-report-2026.pdf', 'application/pdf', 16777216, [
        {
          index: 0,
          ivBase64: toBase64(generateIv()),
          cipherTextSha256Base64: toBase64(generateSalt()),
          cipherTextLength: 8388624,
        },
        {
          index: 1,
          ivBase64: toBase64(generateIv()),
          cipherTextSha256Base64: toBase64(generateSalt()),
          cipherTextLength: 8388624,
        },
      ]);

      const { ciphertext, iv } = await encryptManifest(manifest, dek);
      const decrypted = await decryptManifest(ciphertext, iv, dek);

      expect(decrypted.originalFileName).toBe('financial-report-2026.pdf');
      expect(decrypted.originalMimeType).toBe('application/pdf');
      expect(decrypted.originalSizeBytes).toBe(16777216);
      expect(decrypted.chunks).toHaveLength(2);
      expect(decrypted.chunks[0]?.index).toBe(0);
      expect(decrypted.chunks[1]?.index).toBe(1);
    });

    it('encodes and decodes base64url without character loss', () => {
      const originalBytes = generateRecoveryKey();
      const b64url = toBase64Url(originalBytes);
      expect(b64url).not.toContain('+');
      expect(b64url).not.toContain('/');
      expect(b64url).not.toContain('=');

      const restored = fromBase64Url(b64url);
      expect(toBase64(restored)).toBe(toBase64(originalBytes));
    });
  });
});
