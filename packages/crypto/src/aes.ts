/**
 * AES-256-GCM encryption/decryption using Web Crypto API.
 *
 * Design invariants:
 * - Every encryption generates a fresh 96-bit IV via crypto.getRandomValues — NEVER reused.
 * - 128-bit authentication tag (GCM default in Web Crypto).
 * - Additional Authenticated Data (AAD) is supported and used for chunk binding.
 * - The IV is returned alongside the ciphertext — the caller is responsible for storing it.
 */

import { generateIv } from './random';

/** Result of an AES-256-GCM encryption operation. */
export interface AesEncryptResult {
  /** Ciphertext with appended 128-bit auth tag */
  ciphertext: Uint8Array;
  /** The 96-bit IV used for this encryption — must be stored for decryption */
  iv: Uint8Array;
}

/**
 * Generate a fresh AES-256 key for file encryption (DEK).
 * Each file gets its own DEK — never reused across files.
 */
export async function generateAesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // extractable — needed for key wrapping/export
    ['encrypt', 'decrypt']
  );
}

/**
 * Import raw bytes as an AES-256-GCM CryptoKey.
 * Used when unwrapping a DEK from its wrapped form.
 */
export async function importAesKey(
  rawKey: Uint8Array,
  extractable = true
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    rawKey as BufferSource,
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt']
  );
}

/**
 * Export an AES-256-GCM CryptoKey to raw bytes.
 */
export async function exportAesKey(key: CryptoKey): Promise<Uint8Array> {
  const rawKey = await crypto.subtle.exportKey('raw', key);
  return new Uint8Array(rawKey);
}

/**
 * Encrypt data with AES-256-GCM.
 *
 * CRITICAL: A fresh random IV is generated for EVERY call — never reused.
 *
 * @param key - AES-256-GCM key
 * @param plaintext - Data to encrypt
 * @param additionalData - Optional AAD bound into the GCM auth tag.
 *   For file chunks: AAD = fileId || chunkIndex (prevents cross-file/cross-chunk splicing).
 */
export async function aesEncrypt(
  key: CryptoKey,
  plaintext: Uint8Array,
  additionalData?: Uint8Array
): Promise<AesEncryptResult> {
  // SECURITY: Fresh IV for every encryption — this is non-negotiable for GCM security
  const iv = generateIv();

  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: iv as BufferSource,
    tagLength: 128, // 128-bit authentication tag
  };

  if (additionalData) {
    params.additionalData = additionalData as BufferSource;
  }

  const ciphertextBuffer = await crypto.subtle.encrypt(params, key, plaintext as BufferSource);

  return {
    ciphertext: new Uint8Array(ciphertextBuffer),
    iv,
  };
}

/**
 * Decrypt data with AES-256-GCM.
 *
 * @param key - AES-256-GCM key (must match the key used for encryption)
 * @param ciphertext - Ciphertext with appended 128-bit auth tag
 * @param iv - The exact IV used during encryption
 * @param additionalData - The exact AAD used during encryption (if any).
 *   If the AAD doesn't match, GCM authentication will fail — this is by design
 *   and prevents chunk reordering/splicing attacks.
 * @throws {DOMException} if authentication fails (wrong key, tampered ciphertext, wrong AAD, wrong IV)
 */
export async function aesDecrypt(
  key: CryptoKey,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: iv as BufferSource,
    tagLength: 128,
  };

  if (additionalData) {
    params.additionalData = additionalData as BufferSource;
  }

  const plaintextBuffer = await crypto.subtle.decrypt(params, key, ciphertext as BufferSource);
  return new Uint8Array(plaintextBuffer);
}

/**
 * Encrypt data with AES-256-GCM using a raw key (bytes).
 * Convenience wrapper that imports the key first.
 */
export async function aesEncryptWithRawKey(
  rawKey: Uint8Array,
  plaintext: Uint8Array,
  additionalData?: Uint8Array
): Promise<AesEncryptResult> {
  const key = await importAesKey(rawKey, false);
  return aesEncrypt(key, plaintext, additionalData);
}

/**
 * Decrypt data with AES-256-GCM using a raw key (bytes).
 * Convenience wrapper that imports the key first.
 */
export async function aesDecryptWithRawKey(
  rawKey: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const key = await importAesKey(rawKey, false);
  return aesDecrypt(key, ciphertext, iv, additionalData);
}
