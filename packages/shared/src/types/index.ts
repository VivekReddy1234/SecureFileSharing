/**
 * CipherVault Shared Types
 * Production-grade end-to-end encrypted file sharing platform
 *
 * These types encode the security model from SECURITY.md Section 3.
 * Names deliberately match the Prisma schema for clarity.
 */

// ──── Enums ────

export enum UserRole {
  USER = 'USER',
  ADMIN = 'ADMIN',
}

export enum FileStatus {
  PENDING = 'PENDING',
  COMPLETE = 'COMPLETE',
  FAILED = 'FAILED',
  DELETED = 'DELETED',
}

// ──── Audit Events ────

export type AuditEventType =
  | 'REGISTER'
  | 'LOGIN'
  | 'FAILED_LOGIN'
  | 'LOGOUT'
  | 'TOKEN_REFRESH'
  | 'TOKEN_REUSE_DETECTED'
  | 'FILE_UPLOAD'
  | 'FILE_DOWNLOAD'
  | 'FILE_DELETE'
  | 'FILE_SHARE'
  | 'SHARE_REVOKED'
  | 'SHARE_LINK_CREATED'
  | 'SHARE_LINK_ACCESSED'
  | 'SHARE_LINK_REVOKED'
  | 'PERMISSION_CHANGED'
  | 'PASSWORD_CHANGED'
  | 'UNAUTHORIZED_ACCESS_ATTEMPT'
  | 'ACCOUNT_DISABLED'
  | 'ACCOUNT_ENABLED';

// ──── API Response Shape ────

export interface ApiError {
  code: string;
  message: string;
  requestId: string;
  details?: Record<string, unknown>;
}

export interface PaginationParams {
  cursor?: string;
  limit: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  nextCursor: string | null;
  hasMore: boolean;
}

// ──── Authentication ────

/** GET /auth/salt — returns salt + iterations for client-side key derivation */
export interface AuthSaltResponse {
  authSaltBase64: string;
  kdfIterations: number;
}

/** POST /auth/register */
export interface AuthRegisterRequest {
  email: string;
  /** Base64-encoded authKey = HKDF(masterKey, "ciphervault-auth-v1") */
  authKeyBase64: string;
  /** Base64-encoded PBKDF2 salt (16 bytes) */
  authSaltBase64: string;
  kdfIterations: number;
  /** Base64-encoded RSA-OAEP 3072 public key (SPKI format) */
  publicKeyBase64: string;
  /** Base64-encoded AES-GCM encrypted RSA private key */
  wrappedPrivateKeyBase64: string;
  /** Base64-encoded IV used to encrypt the private key */
  wrappedPrivateKeyIvBase64: string;
  /** Base64-encoded private key wrapped under recovery key (optional) */
  recoveryWrappedPrivateKeyBase64?: string;
  /** Base64-encoded IV for recovery-wrapped private key */
  recoveryWrappedKeyIvBase64?: string;
}

/** POST /auth/login */
export interface AuthLoginRequest {
  email: string;
  /** Base64-encoded authKey */
  authKeyBase64: string;
}

export interface AuthLoginResponse {
  accessToken: string;
  user: {
    id: string;
    email: string;
    role: UserRole;
    publicKeyBase64: string;
    wrappedPrivateKeyBase64: string;
    wrappedPrivateKeyIvBase64: string;
  };
}

/** POST /auth/refresh — refresh token is in httpOnly cookie */
export interface AuthRefreshResponse {
  accessToken: string;
}

/** POST /auth/change-password */
export interface AuthChangePasswordRequest {
  /** Current authKey for verification */
  currentAuthKeyBase64: string;
  /** New authKey derived from new password */
  newAuthKeyBase64: string;
  /** New PBKDF2 salt */
  newAuthSaltBase64: string;
  newKdfIterations: number;
  /** Private key re-wrapped under new masterKey-derived wrapping key */
  newWrappedPrivateKeyBase64: string;
  newWrappedPrivateKeyIvBase64: string;
}

// ──── User ────

export interface UserPublicInfo {
  id: string;
  email: string;
  publicKeyBase64: string;
}

export interface UserProfile {
  id: string;
  email: string;
  role: UserRole;
  createdAt: string;
}

// ──── File Upload/Download ────

/** POST /files/init-upload */
export interface FileInitUploadRequest {
  /** Total ciphertext size in bytes */
  totalSizeBytes: number;
  /** Number of encrypted chunks */
  chunkCount: number;
  /** Base64-encoded encrypted manifest (AES-GCM under DEK) */
  encryptedManifestBase64: string;
  /** Base64-encoded IV for manifest encryption */
  manifestIvBase64: string;
  /** Base64-encoded DEK wrapped with owner's RSA-OAEP public key */
  wrappedKeyBase64: string;
}

export interface FileInitUploadResponse {
  fileId: string;
  s3Key: string;
  uploadId: string;
  presignedUrls: PresignedPartUrl[];
}

export interface PresignedPartUrl {
  partNumber: number;
  url: string;
  expiresAt: string;
}

/** POST /files/:id/complete-upload */
export interface FileCompleteUploadRequest {
  uploadId: string;
  parts: CompletedPart[];
}

export interface CompletedPart {
  partNumber: number;
  etag: string;
}

export interface FileCompleteUploadResponse {
  id: string;
  status: FileStatus;
  sizeBytes: string; // BigInt serialized as string
  createdAt: string;
}

/** GET /files/:id */
export interface FileMetadataResponse {
  id: string;
  ownerId: string;
  status: FileStatus;
  sizeBytes: string;
  encryptedManifestBase64: string;
  manifestIvBase64: string;
  wrappedKeyBase64: string;
  createdAt: string;
  updatedAt: string;
}

/** GET /files (paginated list) */
export interface FileListItem {
  id: string;
  ownerId: string;
  status: FileStatus;
  sizeBytes: string;
  encryptedManifestBase64: string;
  manifestIvBase64: string;
  wrappedKeyBase64: string;
  createdAt: string;
  /** Whether the current user is the owner */
  isOwner: boolean;
}

/** GET /files/:id/download-url */
export interface FileDownloadUrlResponse {
  downloadUrl: string;
  expiresAt: string;
}

// ──── Sharing ────

/** POST /files/:id/shares */
export interface ShareCreateRequest {
  recipientEmail: string;
  /** DEK wrapped with recipient's RSA-OAEP public key (done client-side) */
  wrappedKeyBase64: string;
  canView: boolean;
  canDownload: boolean;
  canReshare: boolean;
  expiresAt?: string;
}

export interface ShareResponse {
  id: string;
  fileId: string;
  granteeUserId: string;
  canView: boolean;
  canDownload: boolean;
  canReshare: boolean;
  createdAt: string;
  expiresAt: string | null;
}

/** POST /files/:id/share-links */
export interface ShareLinkCreateRequest {
  /** DEK wrapped with key derived from linkSecret (+ optional password) */
  wrappedKeyBase64: string;
  canDownload: boolean;
  maxUses?: number;
  expiresAt?: string;
  /** Argon2id hash of password — UX gate only, not real crypto gate */
  passwordHash?: string;
}

export interface ShareLinkCreateResponse {
  id: string;
  createdAt: string;
  expiresAt: string | null;
  maxUses: number | null;
}

/** GET /share-links/:id (public access) */
export interface ShareLinkAccessResponse {
  wrappedKeyBase64: string;
  encryptedManifestBase64: string;
  manifestIvBase64: string;
  fileId: string;
  canDownload: boolean;
  requiresPassword: boolean;
}

// ──── Audit ────

export interface AuditLogEntry {
  id: string;
  userId: string | null;
  eventType: AuditEventType;
  resourceId: string | null;
  success: boolean;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: string;
}

// ──── Admin ────

export interface AdminUserListItem {
  id: string;
  email: string;
  role: UserRole;
  isDisabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface AdminUserUpdateRequest {
  isDisabled?: boolean;
  role?: UserRole;
}
