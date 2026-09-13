/**
 * CipherVault Zod Validation Schemas
 *
 * Every API request body/query/param is validated through these schemas.
 * Unknown fields are rejected (strict mode) to prevent parameter pollution.
 */

import { z } from 'zod';

// ──── Primitive validators ────

/**
 * Base64 string validation — allows standard base64 with padding.
 * We don't use a regex-only check because base64 payloads can be very large
 * (encrypted manifests, wrapped keys). Length constraints are on the
 * decoded content, not the encoded string.
 */
export const base64Schema = z
  .string()
  .min(1, 'Base64 string cannot be empty');

export const uuidSchema = z.string().uuid('Must be a valid UUID');

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .email('Invalid email address')
  .max(255, 'Email cannot exceed 255 characters');

// ──── Pagination ────

export const paginationSchema = z.object({
  cursor: z.string().uuid().optional(),
  limit: z.coerce
    .number()
    .int()
    .min(1, 'Limit must be at least 1')
    .max(100, 'Limit cannot exceed 100')
    .default(20),
}).strict();

// ──── Auth Schemas ────

export const authSaltQuerySchema = z.object({
  email: emailSchema,
}).strict();

export const authRegisterSchema = z.object({
  email: emailSchema,
  authKeyBase64: base64Schema,
  authSaltBase64: base64Schema,
  kdfIterations: z.number().int().min(600_000, 'KDF iterations must be at least 600,000'),
  publicKeyBase64: base64Schema,
  wrappedPrivateKeyBase64: base64Schema,
  wrappedPrivateKeyIvBase64: base64Schema,
  recoveryWrappedPrivateKeyBase64: base64Schema.optional(),
  recoveryWrappedKeyIvBase64: base64Schema.optional(),
}).strict();

export const authLoginSchema = z.object({
  email: emailSchema,
  authKeyBase64: base64Schema,
}).strict();

export const authChangePasswordSchema = z.object({
  currentAuthKeyBase64: base64Schema,
  newAuthKeyBase64: base64Schema,
  newAuthSaltBase64: base64Schema,
  newKdfIterations: z.number().int().min(600_000),
  newWrappedPrivateKeyBase64: base64Schema,
  newWrappedPrivateKeyIvBase64: base64Schema,
}).strict();

// ──── File Schemas ────

export const fileInitUploadSchema = z.object({
  totalSizeBytes: z.number().int().positive('File size must be positive'),
  chunkCount: z.number().int().min(1).max(10_000, 'Max 10,000 chunks'),
  encryptedManifestBase64: base64Schema,
  manifestIvBase64: base64Schema,
  wrappedKeyBase64: base64Schema,
}).strict();

export const completedPartSchema = z.object({
  partNumber: z.number().int().min(1).max(10_000),
  etag: z.string().min(1),
}).strict();

export const fileCompleteUploadSchema = z.object({
  uploadId: z.string().min(1),
  parts: z.array(completedPartSchema).min(1).max(10_000),
}).strict();

export const fileIdParamSchema = z.object({
  id: uuidSchema,
}).strict();

// ──── Share Schemas ────

export const shareCreateSchema = z.object({
  recipientEmail: emailSchema,
  wrappedKeyBase64: base64Schema,
  canView: z.boolean().default(true),
  canDownload: z.boolean().default(true),
  canReshare: z.boolean().default(false),
  expiresAt: z.string().datetime().optional(),
}).strict();

export const shareLinkCreateSchema = z.object({
  wrappedKeyBase64: base64Schema,
  canDownload: z.boolean().default(true),
  maxUses: z.number().int().positive().optional(),
  expiresAt: z.string().datetime().optional(),
  passwordHash: z.string().optional(),
}).strict();

export const shareLinkAccessSchema = z.object({
  password: z.string().optional(),
}).strict();

export const shareIdParamSchema = z.object({
  id: uuidSchema,
}).strict();

// ──── Admin Schemas ────

export const adminUserUpdateSchema = z.object({
  isDisabled: z.boolean().optional(),
  role: z.enum(['USER', 'ADMIN']).optional(),
}).strict();

export const adminUserIdParamSchema = z.object({
  id: uuidSchema,
}).strict();
