/**
 * SHA-256 hashing utilities for integrity verification.
 * Uses the native Web Crypto API — never a custom implementation.
 */

import { toBase64 } from './random';

/**
 * Compute SHA-256 hash of the given data.
 * Returns raw bytes (Uint8Array).
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return new Uint8Array(hashBuffer);
}

/**
 * Compute SHA-256 hash and return as base64 string.
 * Used for ciphertext integrity verification in the manifest.
 */
export async function sha256Base64(data: Uint8Array): Promise<string> {
  const hash = await sha256(data);
  return toBase64(hash);
}

/**
 * Compute SHA-256 hash and return as hex string.
 * Used for refresh token hashing (stored in DB as hex for readability).
 */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  const hash = await sha256(data);
  return Array.from(hash)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
