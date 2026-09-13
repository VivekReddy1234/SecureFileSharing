import { describe, it, expect } from 'vitest';
import {
  authRegisterSchema,
  authLoginSchema,
  fileInitUploadSchema,
  shareCreateSchema,
  shareLinkCreateSchema,
  adminUserUpdateSchema,
  emailSchema,
  uuidSchema,
  paginationSchema,
} from '../schemas';

describe('Shared Zod Schemas Validation Tests', () => {
  describe('Primitive Schemas', () => {
    it('validates and normalizes valid email addresses', () => {
      expect(emailSchema.parse('  Alice@Example.COM  ')).toBe('alice@example.com');
      expect(() => emailSchema.parse('not-an-email')).toThrow();
      expect(() => emailSchema.parse('')).toThrow();
    });

    it('validates UUIDs and rejects invalid formats', () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      expect(uuidSchema.parse(validUuid)).toBe(validUuid);
      expect(() => uuidSchema.parse('invalid-uuid')).toThrow();
      expect(() => uuidSchema.parse('12345')).toThrow();
    });

    it('validates and clamps pagination query parameters', () => {
      const parsedDefault = paginationSchema.parse({});
      expect(parsedDefault.limit).toBe(20);

      const parsedCustom = paginationSchema.parse({ limit: '50' });
      expect(parsedCustom.limit).toBe(50);

      // Rejects limit exceeding 100
      expect(() => paginationSchema.parse({ limit: '150' })).toThrow();
      // Rejects limit < 1
      expect(() => paginationSchema.parse({ limit: '0' })).toThrow();
    });
  });

  describe('Auth Schemas', () => {
    it('accepts valid registration payload and rejects below-minimum KDF iterations', () => {
      const validPayload = {
        email: 'bob@example.com',
        authKeyBase64: 'YXV0aEtleQ==',
        authSaltBase64: 'c2FsdEJhc2U2NA==',
        kdfIterations: 600_000,
        publicKeyBase64: 'cHVibGljS2V5',
        wrappedPrivateKeyBase64: 'd3JhcHBlZFByaXZhdGVLZXk=',
        wrappedPrivateKeyIvBase64: 'aXYxMjM0',
      };

      expect(authRegisterSchema.parse(validPayload)).toBeDefined();

      // Reject weak KDF iterations
      expect(() =>
        authRegisterSchema.parse({
          ...validPayload,
          kdfIterations: 100_000,
        })
      ).toThrow();
    });

    it('strictly rejects unknown fields (defense against parameter pollution)', () => {
      const payloadWithInjectedField = {
        email: 'alice@example.com',
        authKeyBase64: 'YXV0aEtleQ==',
        isAdmin: true, // INJECTED
      };

      expect(() => authLoginSchema.parse(payloadWithInjectedField)).toThrow();
    });
  });

  describe('File Upload & Sharing Schemas', () => {
    it('validates file upload initialization', () => {
      const validInit = {
        totalSizeBytes: 1048576,
        chunkCount: 1,
        encryptedManifestBase64: 'bWFuaWZlc3Q=',
        manifestIvBase64: 'aXYxMjM0',
        wrappedKeyBase64: 'd3JhcHBlZEtleQ==',
      };

      expect(fileInitUploadSchema.parse(validInit)).toBeDefined();

      // Rejects non-positive file size
      expect(() =>
        fileInitUploadSchema.parse({
          ...validInit,
          totalSizeBytes: 0,
        })
      ).toThrow();

      // Rejects chunkCount > 10,000 (S3 limit)
      expect(() =>
        fileInitUploadSchema.parse({
          ...validInit,
          chunkCount: 10_001,
        })
      ).toThrow();
    });

    it('validates direct share creation and defaults boolean permissions', () => {
      const share = shareCreateSchema.parse({
        recipientEmail: 'colleague@company.org',
        wrappedKeyBase64: 'd3JhcHBlZEtleQ==',
      });

      expect(share.canView).toBe(true);
      expect(share.canDownload).toBe(true);
      expect(share.canReshare).toBe(false);
    });

    it('validates public share link creation with optional password and expiry', () => {
      const link = shareLinkCreateSchema.parse({
        wrappedKeyBase64: 'd3JhcHBlZEtleQ==',
        maxUses: 5,
        expiresAt: '2026-12-31T23:59:59.000Z',
      });

      expect(link.maxUses).toBe(5);
      expect(link.canDownload).toBe(true);
    });

    it('validates admin user update schema for role and disable toggles', () => {
      const update = adminUserUpdateSchema.parse({
        isDisabled: true,
        role: 'ADMIN',
      });
      expect(update.isDisabled).toBe(true);
      expect(update.role).toBe('ADMIN');

      // Rejects invalid role string
      expect(() =>
        adminUserUpdateSchema.parse({
          role: 'SUPERADMIN',
        })
      ).toThrow();
    });
  });
});
