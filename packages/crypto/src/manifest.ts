/**
 * File manifest encryption and decryption.
 *
 * The manifest contains the file's original name, MIME type, size, and chunk map.
 * It is encrypted with the file's DEK and stored in Postgres — not S3.
 * This allows file listing without S3 round-trips, and ensures the server
 * CANNOT see original filenames or MIME types.
 */

import { aesEncrypt, aesDecrypt, type AesEncryptResult } from './aes';
import { stringToBytes, bytesToString } from './random';

/** A single chunk's metadata in the manifest. */
export interface ChunkInfo {
  /** Zero-based chunk index */
  index: number;
  /** Base64-encoded IV used for this chunk's AES-256-GCM encryption */
  ivBase64: string;
  /** Base64-encoded SHA-256 of the chunk's ciphertext (for pre-decryption integrity check) */
  cipherTextSha256Base64: string;
  /** Size of the chunk's ciphertext in bytes (including the 16-byte GCM auth tag) */
  cipherTextLength: number;
}

/** The file manifest structure — encrypted before storage. */
export interface FileManifest {
  /** Schema version for forward compatibility */
  version: 1;
  /** Algorithm used for chunk encryption */
  algorithm: 'AES-256-GCM';
  /** Chunk size in bytes (8 MiB = 8388608) */
  chunkSizeBytes: number;
  /** Original filename (visible only after client-side decryption) */
  originalFileName: string;
  /** Original MIME type (visible only after client-side decryption) */
  originalMimeType: string;
  /** Original file size in bytes */
  originalSizeBytes: number;
  /** Per-chunk encryption metadata */
  chunks: ChunkInfo[];
}

/** Default chunk size: 8 MiB (matches S3 multipart minimum with headroom) */
export const CHUNK_SIZE_BYTES = 8_388_608;

/**
 * Build a manifest object from file metadata and chunk information.
 */
export function buildManifest(
  originalFileName: string,
  originalMimeType: string,
  originalSizeBytes: number,
  chunks: ChunkInfo[]
): FileManifest {
  return {
    version: 1,
    algorithm: 'AES-256-GCM',
    chunkSizeBytes: CHUNK_SIZE_BYTES,
    originalFileName,
    originalMimeType,
    originalSizeBytes,
    chunks,
  };
}

/**
 * Encrypt a file manifest with the file's DEK.
 * The encrypted manifest is stored in Postgres (File.encryptedManifest).
 */
export async function encryptManifest(
  manifest: FileManifest,
  dek: CryptoKey
): Promise<AesEncryptResult> {
  const manifestJson = JSON.stringify(manifest);
  const manifestBytes = stringToBytes(manifestJson);
  return aesEncrypt(dek, manifestBytes);
}

/**
 * Decrypt a file manifest using the file's DEK.
 * Returns the parsed manifest with original filename, MIME type, etc.
 */
export async function decryptManifest(
  encryptedManifest: Uint8Array,
  manifestIv: Uint8Array,
  dek: CryptoKey
): Promise<FileManifest> {
  const manifestBytes = await aesDecrypt(dek, encryptedManifest, manifestIv);
  const manifestJson = bytesToString(manifestBytes);
  return JSON.parse(manifestJson) as FileManifest;
}

/**
 * Calculate the number of chunks for a given file size.
 */
export function calculateChunkCount(fileSizeBytes: number): number {
  return Math.ceil(fileSizeBytes / CHUNK_SIZE_BYTES);
}

/**
 * Calculate the byte range for a specific chunk.
 * Returns [startByte, endByte) — endByte is exclusive.
 */
export function getChunkRange(
  chunkIndex: number,
  totalFileSize: number
): { start: number; end: number } {
  const start = chunkIndex * CHUNK_SIZE_BYTES;
  const end = Math.min(start + CHUNK_SIZE_BYTES, totalFileSize);
  return { start, end };
}
