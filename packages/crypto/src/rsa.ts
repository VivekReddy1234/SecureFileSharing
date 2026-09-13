/**
 * RSA-OAEP key generation, export, import, wrap, and unwrap using Web Crypto API.
 *
 * Design choices:
 * - 3072-bit modulus: provides ~128-bit security level, recommended through 2030+
 * - SHA-256 for both hash and MGF1
 * - Used ONLY for key wrapping (encrypting DEKs for per-user access) — never for bulk data
 * - Maximum payload for RSA-OAEP-3072-SHA256: 318 bytes (more than enough for 32-byte AES keys)
 */

import { toBase64, fromBase64 } from './random';

/** RSA key pair as CryptoKey objects. */
export interface RsaKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/** RSA key pair exported to base64 strings for storage. */
export interface ExportedRsaKeyPair {
  /** SPKI-encoded public key, base64 */
  publicKeyBase64: string;
  /** PKCS8-encoded private key, base64 */
  privateKeyBase64: string;
}

const RSA_ALGORITHM: RsaHashedKeyGenParams = {
  name: 'RSA-OAEP',
  modulusLength: 3072,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
  hash: 'SHA-256',
};

const RSA_IMPORT_ALGORITHM: RsaHashedImportParams = {
  name: 'RSA-OAEP',
  hash: 'SHA-256',
};

/**
 * Generate an RSA-OAEP 3072-bit key pair.
 * Called once at user registration; the private key is then wrapped and stored.
 *
 * NOTE: This is CPU-intensive (~500ms-1500ms on mobile).
 * In the browser, run inside a Web Worker to avoid blocking the UI thread.
 */
export async function generateRsaKeyPair(): Promise<RsaKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    RSA_ALGORITHM,
    true, // extractable — we need to export the public key and wrap the private key
    ['wrapKey', 'unwrapKey']
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

/**
 * Export an RSA public key to base64 (SPKI format).
 * This is stored server-side in the clear — it's not secret.
 */
export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('spki', publicKey);
  return toBase64(new Uint8Array(exported));
}

/**
 * Import an RSA public key from base64 (SPKI format).
 * Used when wrapping a DEK for another user.
 */
export async function importPublicKey(publicKeyBase64: string): Promise<CryptoKey> {
  const keyData = fromBase64(publicKeyBase64);
  return crypto.subtle.importKey(
    'spki',
    keyData as BufferSource,
    RSA_IMPORT_ALGORITHM,
    true,
    ['wrapKey']
  );
}

/**
 * Export an RSA private key to base64 (PKCS8 format).
 * The exported key should be immediately encrypted — never stored in the clear.
 */
export async function exportPrivateKey(privateKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('pkcs8', privateKey);
  return toBase64(new Uint8Array(exported));
}

/**
 * Import an RSA private key from base64 (PKCS8 format).
 * Used after unwrapping the stored private key from its AES-GCM encryption.
 */
export async function importPrivateKey(privateKeyBase64: string): Promise<CryptoKey> {
  const keyData = fromBase64(privateKeyBase64);
  return crypto.subtle.importKey(
    'pkcs8',
    keyData as BufferSource,
    RSA_IMPORT_ALGORITHM,
    false, // non-extractable — the unwrapped private key should not be re-exportable
    ['unwrapKey']
  );
}

/**
 * Import an RSA private key from raw bytes (PKCS8 format).
 */
export async function importPrivateKeyFromBytes(keyData: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'pkcs8',
    keyData as BufferSource,
    RSA_IMPORT_ALGORITHM,
    false,
    ['unwrapKey']
  );
}

/**
 * Wrap (encrypt) an AES key using RSA-OAEP public key.
 * Used to create a per-user copy of a file's DEK.
 *
 * @param aesKey - The AES-256-GCM DEK to wrap
 * @param publicKey - The recipient's RSA-OAEP public key
 * @returns Wrapped key as base64 string
 */
export async function rsaWrapKey(
  aesKey: CryptoKey,
  publicKey: CryptoKey
): Promise<string> {
  const wrappedBuffer = await crypto.subtle.wrapKey(
    'raw',
    aesKey,
    publicKey,
    { name: 'RSA-OAEP' }
  );
  return toBase64(new Uint8Array(wrappedBuffer));
}

/**
 * Unwrap (decrypt) an AES key using RSA-OAEP private key.
 * Used when accessing a file — retrieves the DEK from the user's FileKeyGrant.
 *
 * @param wrappedKeyBase64 - The wrapped key from FileKeyGrant.wrappedKey
 * @param privateKey - The user's RSA-OAEP private key (unwrapped in memory from login)
 * @returns The unwrapped AES-256-GCM DEK as a CryptoKey
 */
export async function rsaUnwrapKey(
  wrappedKeyBase64: string,
  privateKey: CryptoKey
): Promise<CryptoKey> {
  const wrappedKey = fromBase64(wrappedKeyBase64);
  return crypto.subtle.unwrapKey(
    'raw',
    wrappedKey as BufferSource,
    privateKey,
    { name: 'RSA-OAEP' },
    { name: 'AES-GCM', length: 256 },
    true, // extractable — may need to re-wrap for sharing
    ['encrypt', 'decrypt']
  );
}

/**
 * Export the RSA key pair to base64 strings.
 * Both SPKI (public) and PKCS8 (private) formats.
 */
export async function exportRsaKeyPair(keyPair: RsaKeyPair): Promise<ExportedRsaKeyPair> {
  const [publicKeyBase64, privateKeyBase64] = await Promise.all([
    exportPublicKey(keyPair.publicKey),
    exportPrivateKey(keyPair.privateKey),
  ]);
  return { publicKeyBase64, privateKeyBase64 };
}
