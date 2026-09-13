import { describe, it, expect, vi, beforeEach } from 'vitest';
import { assertFileAccess, assertFileOwnership } from '../../services/authorization.service';
import { prisma } from '../../config/database';
import { ForbiddenError, NotFoundError } from '../../types/errors';
import { verifyAccessToken } from '../../services/auth.service';

vi.mock('../../config/database', () => ({
  prisma: {
    file: {
      findUnique: vi.fn(),
    },
    fileKeyGrant: {
      findUnique: vi.fn(),
    },
    fileShare: {
      findUnique: vi.fn(),
    },
    auditLog: {
      create: vi.fn().mockResolvedValue({}),
    },
  },
}));

vi.mock('../../config/logger', () => ({
  logger: {
    error: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
  },
}));

describe('Security & Authorization Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.JWT_SECRET = 'a-super-secret-jwt-key-with-over-32-chars-for-test!';
    process.env.ACCESS_TOKEN_TTL_MINUTES = '15';
  });

  describe('IDOR & Access Control (assertFileAccess & assertFileOwnership)', () => {
    const ownerId = 'user-owner-uuid';
    const attackerId = 'user-attacker-uuid';
    const legitimateGranteeId = 'user-grantee-uuid';
    const fileId = 'file-target-uuid';

    it('allows owner full access to file', async () => {
      vi.mocked(prisma.file.findUnique).mockResolvedValueOnce({
        id: fileId,
        ownerId: ownerId,
        s3Key: 'files/s3-key',
        encryptedManifest: Buffer.from('manifest'),
        manifestIv: 'iv',
        sizeBytes: BigInt(1000),
        status: 'COMPLETE',
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null,
        s3UploadId: null,
      });

      vi.mocked(prisma.fileKeyGrant.findUnique).mockResolvedValueOnce({
        id: 'grant-1',
        fileId,
        userId: ownerId,
        wrappedKey: 'wrapped-dek-for-owner',
        grantedByUserId: ownerId,
        grantedAt: new Date(),
      });

      const result = await assertFileAccess(ownerId, fileId, 'download');
      expect(result.isOwner).toBe(true);
      expect(result.wrappedKey).toBe('wrapped-dek-for-owner');
    });

    it('IDOR: blocks unshared user (attacker) from accessing another user file', async () => {
      vi.mocked(prisma.file.findUnique).mockResolvedValueOnce({
        id: fileId,
        ownerId: ownerId,
        s3Key: 'files/s3-key',
        encryptedManifest: Buffer.from('manifest'),
        manifestIv: 'iv',
        sizeBytes: BigInt(1000),
        status: 'COMPLETE',
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null,
        s3UploadId: null,
      });

      // No share exists for attacker
      vi.mocked(prisma.fileShare.findUnique).mockResolvedValueOnce(null);

      await expect(assertFileAccess(attackerId, fileId, 'view')).rejects.toThrow(ForbiddenError);
    });

    it('blocks user when share has been revoked', async () => {
      vi.mocked(prisma.file.findUnique).mockResolvedValueOnce({
        id: fileId,
        ownerId: ownerId,
        s3Key: 'files/s3-key',
        encryptedManifest: Buffer.from('manifest'),
        manifestIv: 'iv',
        sizeBytes: BigInt(1000),
        status: 'COMPLETE',
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null,
        s3UploadId: null,
      });

      vi.mocked(prisma.fileShare.findUnique).mockResolvedValueOnce({
        id: 'share-1',
        fileId,
        granteeUserId: legitimateGranteeId,
        canView: true,
        canDownload: true,
        canReshare: false,
        createdByUserId: ownerId,
        createdAt: new Date(),
        expiresAt: null,
        revokedAt: new Date(), // REVOKED
      });

      await expect(assertFileAccess(legitimateGranteeId, fileId, 'download')).rejects.toThrow(
        ForbiddenError
      );
    });

    it('blocks user when share has expired', async () => {
      vi.mocked(prisma.file.findUnique).mockResolvedValueOnce({
        id: fileId,
        ownerId: ownerId,
        s3Key: 'files/s3-key',
        encryptedManifest: Buffer.from('manifest'),
        manifestIv: 'iv',
        sizeBytes: BigInt(1000),
        status: 'COMPLETE',
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null,
        s3UploadId: null,
      });

      const pastDate = new Date(Date.now() - 10000);
      vi.mocked(prisma.fileShare.findUnique).mockResolvedValueOnce({
        id: 'share-1',
        fileId,
        granteeUserId: legitimateGranteeId,
        canView: true,
        canDownload: true,
        canReshare: false,
        createdByUserId: ownerId,
        createdAt: new Date(),
        expiresAt: pastDate, // EXPIRED
        revokedAt: null,
      });

      await expect(assertFileAccess(legitimateGranteeId, fileId, 'download')).rejects.toThrow(
        ForbiddenError
      );
    });

    it('enforces granular permission: view-only grantee blocked from downloading', async () => {
      vi.mocked(prisma.file.findUnique).mockResolvedValueOnce({
        id: fileId,
        ownerId: ownerId,
        s3Key: 'files/s3-key',
        encryptedManifest: Buffer.from('manifest'),
        manifestIv: 'iv',
        sizeBytes: BigInt(1000),
        status: 'COMPLETE',
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null,
        s3UploadId: null,
      });

      vi.mocked(prisma.fileShare.findUnique).mockResolvedValueOnce({
        id: 'share-1',
        fileId,
        granteeUserId: legitimateGranteeId,
        canView: true,
        canDownload: false, // NO DOWNLOAD PERMISSION
        canReshare: false,
        createdByUserId: ownerId,
        createdAt: new Date(),
        expiresAt: null,
        revokedAt: null,
      });

      await expect(assertFileAccess(legitimateGranteeId, fileId, 'download')).rejects.toThrow(
        /Download access denied/
      );
    });

    it('assertFileOwnership throws when non-owner attempts destructive action', async () => {
      vi.mocked(prisma.file.findUnique).mockResolvedValueOnce({
        id: fileId,
        ownerId: ownerId,
        s3Key: 'files/s3-key',
        encryptedManifest: Buffer.from('manifest'),
        manifestIv: 'iv',
        sizeBytes: BigInt(1000),
        status: 'COMPLETE',
        createdAt: new Date(),
        updatedAt: new Date(),
        deletedAt: null,
        s3UploadId: null,
      });

      await expect(assertFileOwnership(attackerId, fileId)).rejects.toThrow(ForbiddenError);
    });

    it('throws NotFoundError if file does not exist', async () => {
      vi.mocked(prisma.file.findUnique).mockResolvedValueOnce(null);

      await expect(assertFileAccess(ownerId, 'non-existent-id', 'view')).rejects.toThrow(
        NotFoundError
      );
    });
  });

  describe('JWT Security & Tampering Resistance', () => {
    it('rejects expired tokens', async () => {
      // Create a token that expires in -1 second
      const { SignJWT } = await import('jose');
      const secret = new TextEncoder().encode(process.env.JWT_SECRET);
      const expiredToken = await new SignJWT({ id: 'user-1', email: 'a@b.com', role: 'USER' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt(Math.floor(Date.now() / 1000) - 100)
        .setExpirationTime(Math.floor(Date.now() / 1000) - 1)
        .sign(secret);

      await expect(verifyAccessToken(expiredToken)).rejects.toThrow();
    });

    it('rejects tokens signed with different secret', async () => {
      const { SignJWT } = await import('jose');
      const wrongSecret = new TextEncoder().encode('completely-different-secret-key-123456!');
      const foreignToken = await new SignJWT({ id: 'user-1', email: 'a@b.com', role: 'USER' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('15m')
        .sign(wrongSecret);

      await expect(verifyAccessToken(foreignToken)).rejects.toThrow();
    });

    it('rejects token signed with alg: none', async () => {
      // In jose, algorithms: ['HS256'] is explicitly enforced in verifyAccessToken
      const maliciousPayload = Buffer.from(
        JSON.stringify({ alg: 'none', typ: 'JWT' })
      ).toString('base64url');
      const claims = Buffer.from(
        JSON.stringify({ id: 'admin-id', role: 'ADMIN' })
      ).toString('base64url');
      const algNoneToken = `${maliciousPayload}.${claims}.`;

      await expect(verifyAccessToken(algNoneToken)).rejects.toThrow();
    });
  });
});
