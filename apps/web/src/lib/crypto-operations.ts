import {
  generateAesKey,
  aesEncrypt,
  aesDecrypt,
  rsaWrapKey,
  rsaUnwrapKey,
  importPublicKey,
  deriveShareLinkKey,
  buildManifest,
  encryptManifest,
  decryptManifest,
  sha256Base64,
  toBase64,
  fromBase64,
  toBase64Url,
  fromBase64Url,
  generateRandomBytes,
  uint32ToBytes,
  CHUNK_SIZE_BYTES,
  type FileManifest,
  type ChunkInfo,
} from '@ciphervault/crypto';

export interface EncryptedChunkData {
  index: number;
  ciphertext: Uint8Array;
  ivBase64: string;
  cipherTextSha256Base64: string;
}

export interface EncryptedFileResult {
  dek: CryptoKey;
  chunks: EncryptedChunkData[];
  manifest: FileManifest;
  encryptedManifestBase64: string;
  manifestIvBase64: string;
  totalCiphertextSize: number;
}

/**
 * Encrypt a file chunk by chunk (8 MiB chunks) using AES-256-GCM.
 * Memory bounded — processes one chunk at a time.
 */
export async function encryptFile(
  file: File,
  onProgress?: (stage: 'encrypting', percent: number) => void
): Promise<EncryptedFileResult> {
  const dek = await generateAesKey();
  const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE_BYTES));
  const chunkInfos: ChunkInfo[] = [];
  const chunks: EncryptedChunkData[] = [];
  let totalCiphertextSize = 0;

  for (let i = 0; i < totalChunks; i++) {
    onProgress?.('encrypting', Math.round((i / totalChunks) * 100));

    const start = i * CHUNK_SIZE_BYTES;
    const end = Math.min(start + CHUNK_SIZE_BYTES, file.size);
    const chunkBlob = file.slice(start, end);
    const chunkArrayBuffer = await chunkBlob.arrayBuffer();
    const plaintext = new Uint8Array(chunkArrayBuffer);

    // AAD binds chunk index to prevent chunk reordering/splicing
    const aad = uint32ToBytes(i);
    const encResult = await aesEncrypt(dek, plaintext, aad);

    const hashBase64 = await sha256Base64(encResult.ciphertext);
    const ivBase64 = toBase64(encResult.iv);

    chunkInfos.push({
      index: i,
      ivBase64,
      cipherTextSha256Base64: hashBase64,
      cipherTextLength: encResult.ciphertext.length,
    });

    chunks.push({
      index: i,
      ciphertext: encResult.ciphertext,
      ivBase64,
      cipherTextSha256Base64: hashBase64,
    });

    totalCiphertextSize += encResult.ciphertext.length;
  }

  onProgress?.('encrypting', 100);

  const manifest = buildManifest(
    file.name,
    file.type || 'application/octet-stream',
    file.size,
    chunkInfos
  );

  const encManifestResult = await encryptManifest(manifest, dek);

  return {
    dek,
    chunks,
    manifest,
    encryptedManifestBase64: toBase64(encManifestResult.ciphertext),
    manifestIvBase64: toBase64(encManifestResult.iv),
    totalCiphertextSize,
  };
}

/**
 * Decrypt a single chunk given ciphertext, IV, chunkIndex, and DEK.
 */
export async function decryptChunk(
  ciphertext: Uint8Array,
  ivBase64: string,
  chunkIndex: number,
  dek: CryptoKey
): Promise<Uint8Array> {
  const iv = fromBase64(ivBase64);
  const aad = uint32ToBytes(chunkIndex);
  return aesDecrypt(dek, ciphertext, iv, aad);
}

/**
 * Decrypt all chunks and reassemble into a browser Blob with original filename/type.
 */
export async function decryptFile(
  encryptedChunks: Uint8Array[],
  manifest: FileManifest,
  dek: CryptoKey,
  onProgress?: (percent: number) => void
): Promise<Blob> {
  const decryptedParts: Uint8Array[] = [];

  for (let i = 0; i < encryptedChunks.length; i++) {
    onProgress?.(Math.round((i / encryptedChunks.length) * 100));
    const chunkInfo = manifest.chunks[i];
    if (!chunkInfo) throw new Error(`Missing chunk info for chunk ${i}`);

    const ciphertext = encryptedChunks[i]!;
    const decrypted = await decryptChunk(ciphertext, chunkInfo.ivBase64, i, dek);
    decryptedParts.push(decrypted);
  }

  onProgress?.(100);
  return new Blob(decryptedParts as unknown as BlobPart[], { type: manifest.originalMimeType });
}

/**
 * Wrap a file's DEK with a recipient's RSA-OAEP public key.
 */
export async function wrapDekForUser(
  dek: CryptoKey,
  recipientPublicKeyBase64: string
): Promise<string> {
  const recipientPublicKey = await importPublicKey(recipientPublicKeyBase64);
  return rsaWrapKey(dek, recipientPublicKey);
}

/**
 * Unwrap a file's DEK using the current user's RSA-OAEP private key.
 */
export async function unwrapDek(
  wrappedKeyBase64: string,
  userPrivateKey: CryptoKey
): Promise<CryptoKey> {
  return rsaUnwrapKey(wrappedKeyBase64, userPrivateKey);
}

/**
 * Generate share link secret (random 256-bit) and derive its wrapping key.
 */
export async function createShareLinkKeys(password?: string): Promise<{
  linkSecret: Uint8Array;
  linkSecretBase64Url: string;
  wrappingKey: CryptoKey;
}> {
  const linkSecret = generateRandomBytes(32);
  const wrappingKey = await deriveShareLinkKey(linkSecret, password);
  return {
    linkSecret,
    linkSecretBase64Url: toBase64Url(linkSecret),
    wrappingKey,
  };
}

/**
 * Unwrap a DEK from a share link using the URL fragment secret (+ optional password).
 */
export async function unwrapShareLinkDek(
  wrappedKeyBase64: string,
  linkSecretBase64Url: string,
  password?: string
): Promise<CryptoKey> {
  const linkSecret = fromBase64Url(linkSecretBase64Url);
  const wrappingKey = await deriveShareLinkKey(linkSecret, password);

  // The wrappedKey stored in DB for share link is wrapped with wrappingKey (AES-256-GCM)
  // Format: [12-byte IV][ciphertext]
  const rawBytes = fromBase64(wrappedKeyBase64);
  const iv = rawBytes.slice(0, 12);
  const ciphertext = rawBytes.slice(12);

  const rawDek = await aesDecrypt(wrappingKey, ciphertext, iv);
  const { importAesKey } = await import('@ciphervault/crypto');
  return importAesKey(rawDek, true);
}

/**
 * Wrap a DEK for a share link using AES-256-GCM.
 * Output: base64(IV + ciphertext)
 */
export async function wrapDekForShareLink(
  dek: CryptoKey,
  wrappingKey: CryptoKey
): Promise<string> {
  const { exportAesKey } = await import('@ciphervault/crypto');
  const rawDek = await exportAesKey(dek);
  const result = await aesEncrypt(wrappingKey, rawDek);

  const combined = new Uint8Array(result.iv.length + result.ciphertext.length);
  combined.set(result.iv, 0);
  combined.set(result.ciphertext, result.iv.length);

  return toBase64(combined);
}

export { decryptManifest };
