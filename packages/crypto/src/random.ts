/**
 * Secure random value generation using Web Crypto API.
 * All random generation goes through crypto.getRandomValues — never Math.random().
 */

/**
 * Generates cryptographically secure random bytes.
 * Uses crypto.getRandomValues which is available in both browser and Node.js 19+.
 */
export function generateRandomBytes(length: number): Uint8Array {
  const buffer = new Uint8Array(length);
  crypto.getRandomValues(buffer);
  return buffer;
}

/** Generate a fresh 96-bit (12-byte) IV for AES-256-GCM. */
export function generateIv(): Uint8Array {
  return generateRandomBytes(12);
}

/** Generate a 16-byte salt for PBKDF2. */
export function generateSalt(): Uint8Array {
  return generateRandomBytes(16);
}

/** Generate a 256-bit (32-byte) random key as raw bytes (e.g., for recovery key). */
export function generateRecoveryKey(): Uint8Array {
  return generateRandomBytes(32);
}

/**
 * Encode bytes to base64url (URL-safe base64 without padding).
 * Used for URL fragments, token values, etc.
 */
export function toBase64Url(bytes: Uint8Array): string {
  const base64 = toBase64(bytes);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/**
 * Decode base64url string back to bytes.
 */
export function fromBase64Url(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return fromBase64(base64);
}

/** Encode bytes to standard base64. */
export function toBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

/** Decode standard base64 string to bytes. */
export function fromBase64(str: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(str, 'base64');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Concatenate two Uint8Arrays.
 * Used for building AAD (fileId || chunkIndex) and similar constructions.
 */
export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

/** Convert a string to UTF-8 bytes. */
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/** Convert UTF-8 bytes to a string. */
export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Convert a 32-bit unsigned integer to 4 bytes (big-endian).
 * Used for encoding chunk indexes in AAD.
 */
export function uint32ToBytes(n: number): Uint8Array {
  const bytes = new Uint8Array(4);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, n, false);
  return bytes;
}
