/**
 * Key Derivation Functions: PBKDF2 and HKDF via Web Crypto API.
 *
 * Design invariants:
 * - PBKDF2 is used for password → master key derivation (client-side only)
 * - HKDF is used for context-separated key derivation from the master key
 * - Context strings prevent key reuse across different purposes:
 *   "ciphervault-auth-v1" → authentication key
 *   "ciphervault-privkey-wrap-v1" → private key wrapping key
 *   "ciphervault-recovery-wrap-v1" → recovery key wrapping key
 *   "ciphervault-sharelink-v1" → share link key derivation
 * - Minimum 600,000 PBKDF2 iterations (OWASP 2023 baseline)
 */

import { stringToBytes } from './random';

/** HKDF context strings — never change these without a migration plan */
export const HKDF_CONTEXT = {
  AUTH: 'ciphervault-auth-v1',
  PRIVATE_KEY_WRAP: 'ciphervault-privkey-wrap-v1',
  RECOVERY_WRAP: 'ciphervault-recovery-wrap-v1',
  SHARE_LINK: 'ciphervault-sharelink-v1',
} as const;

/** Minimum PBKDF2 iterations — OWASP 2023 baseline for PBKDF2-HMAC-SHA256 */
export const MIN_KDF_ITERATIONS = 600_000;

/**
 * Derive a master key from a password using PBKDF2-HMAC-SHA256.
 *
 * This key NEVER leaves the browser. It is used as the root of the key hierarchy:
 * - HKDF(masterKey, "ciphervault-auth-v1") → authKey (sent to server for authentication)
 * - HKDF(masterKey, "ciphervault-privkey-wrap-v1") → wrapping key for the RSA private key
 *
 * @param password - User's plaintext password (never sent to server)
 * @param salt - 16-byte random salt (stored server-side in User.authSalt — not secret)
 * @param iterations - Number of PBKDF2 iterations (stored per-user for upgradability)
 */
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  iterations: number
): Promise<CryptoKey> {
  if (iterations < MIN_KDF_ITERATIONS) {
    throw new Error(
      `PBKDF2 iterations (${iterations}) below minimum (${MIN_KDF_ITERATIONS}). ` +
      `This would weaken the key derivation — refusing to proceed.`
    );
  }

  // Import the password as a CryptoKey for PBKDF2
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    stringToBytes(password) as BufferSource,
    'PBKDF2',
    false, // not extractable
    ['deriveKey', 'deriveBits']
  );

  // Derive 256-bit master key bits via PBKDF2
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    256
  );

  // Import derived bits as an HKDF key for subsequent domain-separated derivations
  return crypto.subtle.importKey(
    'raw',
    bits,
    'HKDF',
    false,
    ['deriveKey', 'deriveBits']
  );
}

/**
 * Derive a purpose-specific key from the master key using HKDF-SHA256.
 *
 * The context string (info parameter) ensures that keys derived for different
 * purposes are cryptographically independent — knowing one does not help
 * compute another.
 *
 * @param masterKey - The PBKDF2-derived master key (CryptoKey)
 * @param context - HKDF info string identifying the key's purpose
 * @param keyUsage - What the derived key will be used for
 */
export async function deriveKeyWithHkdf(
  masterKey: CryptoKey,
  context: string,
  keyUsage: KeyUsage[] = ['encrypt', 'decrypt']
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      // Salt is optional for HKDF — we use an empty salt because context separation
      // is handled by the info parameter, and the input key material (masterKey)
      // already has high entropy from PBKDF2
      salt: new Uint8Array(0) as BufferSource,
      info: stringToBytes(context) as BufferSource,
    },
    masterKey,
    { name: 'AES-GCM', length: 256 },
    true, // extractable — authKey needs to be exported as bytes for the server
    keyUsage
  );
}

/**
 * Derive raw bytes from the master key using HKDF-SHA256.
 * Used when the derived value needs to be sent as raw bytes (e.g., authKey to server).
 */
export async function deriveBitsWithHkdf(
  masterKey: CryptoKey,
  context: string,
  bitLength: number = 256
): Promise<Uint8Array> {
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0) as BufferSource,
      info: stringToBytes(context) as BufferSource,
    },
    masterKey,
    bitLength
  );
  return new Uint8Array(bits);
}

/**
 * Complete auth key derivation flow: password + salt → masterKey → authKey.
 *
 * The authKey is what gets sent to the server (over TLS) instead of the password.
 * The server Argon2id-hashes it and stores the hash — this means even a full DB
 * compromise doesn't expose the master key or anything that can decrypt files.
 *
 * @returns authKey as Uint8Array (to be sent to server as base64)
 */
export async function deriveAuthKey(
  password: string,
  salt: Uint8Array,
  iterations: number
): Promise<{ masterKey: CryptoKey; authKey: Uint8Array }> {
  const masterKey = await deriveMasterKey(password, salt, iterations);
  const authKey = await deriveBitsWithHkdf(masterKey, HKDF_CONTEXT.AUTH);
  return { masterKey, authKey };
}

/**
 * Derive the wrapping key for the user's RSA private key.
 * Used to encrypt/decrypt the private key stored on the server.
 */
export async function derivePrivateKeyWrappingKey(
  masterKey: CryptoKey
): Promise<CryptoKey> {
  return deriveKeyWithHkdf(masterKey, HKDF_CONTEXT.PRIVATE_KEY_WRAP);
}

/**
 * Derive a wrapping key from the recovery key.
 * Used to wrap the private key a second time for account recovery.
 */
export async function deriveRecoveryWrappingKey(
  recoveryKeyBytes: Uint8Array
): Promise<CryptoKey> {
  // Import the recovery key as HKDF input
  const recoveryKey = await crypto.subtle.importKey(
    'raw',
    recoveryKeyBytes as BufferSource,
    'HKDF',
    false,
    ['deriveKey', 'deriveBits']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0) as BufferSource,
      info: stringToBytes(HKDF_CONTEXT.RECOVERY_WRAP) as BufferSource,
    },
    recoveryKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Derive a wrapping key for share link DEK wrapping.
 *
 * The linkSecret lives only in the URL fragment (never sent to server).
 * If a password is set, it is mixed in via PBKDF2 + HKDF to form the final key.
 *
 * @param linkSecret - Random 256-bit value from the URL fragment
 * @param password - Optional password for the share link
 */
export async function deriveShareLinkKey(
  linkSecret: Uint8Array,
  password?: string
): Promise<CryptoKey> {
  let keyMaterial: Uint8Array;

  if (password) {
    // Mix password into the key material via PBKDF2
    // The linkSecret serves as the salt for PBKDF2 in this context
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      stringToBytes(password) as BufferSource,
      'PBKDF2',
      false,
      ['deriveBits']
    );

    const passwordDerivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: linkSecret as BufferSource,
        iterations: MIN_KDF_ITERATIONS,
        hash: 'SHA-256',
      },
      passwordKey,
      256
    );

    // Concatenate linkSecret + password-derived bits for HKDF input
    const combined = new Uint8Array(linkSecret.length + 32);
    combined.set(linkSecret, 0);
    combined.set(new Uint8Array(passwordDerivedBits), linkSecret.length);
    keyMaterial = combined;
  } else {
    keyMaterial = linkSecret;
  }

  // Final HKDF derivation with share link context
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    keyMaterial as BufferSource,
    'HKDF',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0) as BufferSource,
      info: stringToBytes(HKDF_CONTEXT.SHARE_LINK) as BufferSource,
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}
