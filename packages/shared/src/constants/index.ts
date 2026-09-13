/**
 * Security & File Architecture Constants for CipherVault
 */

export const CHUNK_SIZE_BYTES = 8388608; // 8 MB chunk size
export const MAX_CHUNKS = 10000; // Maximum number of chunks allowed per file
export const MAX_FILE_SIZE_BYTES = 5368709120; // 5 GB max file size (5 * 1024 * 1024 * 1024)

export const MIN_KDF_ITERATIONS = 600000;
export const DEFAULT_KDF_ITERATIONS = 600000;

export const ACCESS_TOKEN_TTL_MINUTES = 15;
export const REFRESH_TOKEN_TTL_DAYS = 30;

export const CSRF_HEADER_NAME = 'x-requested-with';
export const CSRF_HEADER_VALUE = 'CipherVault';

export const DEFAULT_PAGE_LIMIT = 20;
export const MAX_PAGE_LIMIT = 100;

export const CRYPTO_ALGORITHM = 'AES-256-GCM';
export const KEY_EXCHANGE_ALGORITHM = 'RSA-OAEP-3072';
export const DIGEST_ALGORITHM = 'SHA-256';
