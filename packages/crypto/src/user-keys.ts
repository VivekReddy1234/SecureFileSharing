/**
 * High-level user key management: wrapping and unwrapping the RSA-OAEP private key
 * using AES-256-GCM under the master key (or recovery key).
 */

import { aesEncrypt, aesDecrypt } from './aes';
import { exportPrivateKey, importPrivateKey } from './rsa';
import { derivePrivateKeyWrappingKey, deriveRecoveryWrappingKey } from './kdf';
import { toBase64, fromBase64, stringToBytes, bytesToString } from './random';

/**
 * Wrap (encrypt) the user's RSA private key under their master key.
 *
 * Derives the wrapping key via HKDF(masterKey, "ciphervault-privkey-wrap-v1"),
 * exports the private key to PKCS8 base64, and encrypts it using AES-256-GCM.
 */
export async function wrapPrivateKey(
  privateKey: CryptoKey,
  masterKey: CryptoKey
): Promise<{ wrappedPrivateKeyBase64: string; wrappedPrivateKeyIvBase64: string }> {
  const wrappingKey = await derivePrivateKeyWrappingKey(masterKey);
  const privateKeyBase64 = await exportPrivateKey(privateKey);
  const result = await aesEncrypt(wrappingKey, stringToBytes(privateKeyBase64));

  return {
    wrappedPrivateKeyBase64: toBase64(result.ciphertext),
    wrappedPrivateKeyIvBase64: toBase64(result.iv),
  };
}

/**
 * Unwrap (decrypt) the user's RSA private key using their master key.
 *
 * Decrypts the PKCS8 ciphertext with AES-256-GCM, then imports as an RSA-OAEP private key.
 */
export async function unwrapPrivateKey(
  wrappedPrivateKeyBase64: string,
  wrappedPrivateKeyIvBase64: string,
  masterKey: CryptoKey
): Promise<CryptoKey> {
  const wrappingKey = await derivePrivateKeyWrappingKey(masterKey);
  const ciphertext = fromBase64(wrappedPrivateKeyBase64);
  const iv = fromBase64(wrappedPrivateKeyIvBase64);

  const decryptedBytes = await aesDecrypt(wrappingKey, ciphertext, iv);
  const privateKeyBase64 = bytesToString(decryptedBytes);

  return importPrivateKey(privateKeyBase64);
}

/**
 * Wrap the user's RSA private key a second time under the one-time recovery key.
 */
export async function wrapPrivateKeyWithRecoveryKey(
  privateKey: CryptoKey,
  recoveryKeyBytes: Uint8Array
): Promise<{ recoveryWrappedPrivateKeyBase64: string; recoveryWrappedKeyIvBase64: string }> {
  const wrappingKey = await deriveRecoveryWrappingKey(recoveryKeyBytes);
  const privateKeyBase64 = await exportPrivateKey(privateKey);
  const result = await aesEncrypt(wrappingKey, stringToBytes(privateKeyBase64));

  return {
    recoveryWrappedPrivateKeyBase64: toBase64(result.ciphertext),
    recoveryWrappedKeyIvBase64: toBase64(result.iv),
  };
}

/**
 * Unwrap the user's RSA private key using the one-time recovery key.
 */
export async function unwrapPrivateKeyWithRecoveryKey(
  recoveryWrappedPrivateKeyBase64: string,
  recoveryWrappedKeyIvBase64: string,
  recoveryKeyBytes: Uint8Array
): Promise<CryptoKey> {
  const wrappingKey = await deriveRecoveryWrappingKey(recoveryKeyBytes);
  const ciphertext = fromBase64(recoveryWrappedPrivateKeyBase64);
  const iv = fromBase64(recoveryWrappedKeyIvBase64);

  const decryptedBytes = await aesDecrypt(wrappingKey, ciphertext, iv);
  const privateKeyBase64 = bytesToString(decryptedBytes);

  return importPrivateKey(privateKeyBase64);
}
