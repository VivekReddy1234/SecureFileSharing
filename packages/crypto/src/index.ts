/**
 * CipherVault Crypto Module
 *
 * Thin, well-tested wrappers around the Web Crypto API.
 * All cryptographic operations are performed via crypto.subtle — no custom crypto.
 *
 * This module is used by both the browser (apps/web) and potentially
 * Node.js tests (Node.js 19+ provides Web Crypto API natively).
 */

// Random and encoding utilities
export {
  generateRandomBytes,
  generateIv,
  generateSalt,
  generateRecoveryKey,
  toBase64,
  fromBase64,
  toBase64Url,
  fromBase64Url,
  concatBytes,
  stringToBytes,
  bytesToString,
  uint32ToBytes,
} from './random';

// SHA-256 hashing
export { sha256, sha256Base64, sha256Hex } from './hash';

// AES-256-GCM encryption
export {
  generateAesKey,
  importAesKey,
  exportAesKey,
  aesEncrypt,
  aesDecrypt,
  aesEncryptWithRawKey,
  aesDecryptWithRawKey,
  type AesEncryptResult,
} from './aes';

// RSA-OAEP key management
export {
  generateRsaKeyPair,
  exportPublicKey,
  importPublicKey,
  exportPrivateKey,
  importPrivateKey,
  importPrivateKeyFromBytes,
  rsaWrapKey,
  rsaUnwrapKey,
  exportRsaKeyPair,
  type RsaKeyPair,
  type ExportedRsaKeyPair,
} from './rsa';

// Key derivation (PBKDF2, HKDF)
export {
  HKDF_CONTEXT,
  MIN_KDF_ITERATIONS,
  deriveMasterKey,
  deriveKeyWithHkdf,
  deriveBitsWithHkdf,
  deriveAuthKey,
  derivePrivateKeyWrappingKey,
  deriveRecoveryWrappingKey,
  deriveShareLinkKey,
} from './kdf';

// File manifest
export {
  CHUNK_SIZE_BYTES,
  buildManifest,
  encryptManifest,
  decryptManifest,
  calculateChunkCount,
  getChunkRange,
  type FileManifest,
  type ChunkInfo,
} from './manifest';

// High-level user key wrapping/unwrapping
export {
  wrapPrivateKey,
  unwrapPrivateKey,
  wrapPrivateKeyWithRecoveryKey,
  unwrapPrivateKeyWithRecoveryKey,
} from './user-keys';
