import { Router, Request, Response, NextFunction } from 'express';
import { prisma } from '../config/database';
import { requireAuth } from '../middleware/auth.middleware';
import { validateBody, validateParams } from '../middleware/validation.middleware';
import { assertFileOwnership } from '../services/authorization.service';
import { logAuditEvent } from '../services/audit.service';
import * as s3Service from '../services/s3.service';
import {
  shareLinkCreateSchema,
  fileIdParamSchema,
  shareIdParamSchema,
} from '@ciphervault/shared';
import { ForbiddenError, NotFoundError, UnauthorizedError } from '../types/errors';
import * as argon2 from 'argon2';
import { shareLinkPasswordLimiter } from '../middleware/rate-limit.middleware';

export const shareLinkRouter = Router();

// Mounts at /files/:id/share-links
shareLinkRouter.post(
  '/:id/share-links',
  requireAuth,
  validateParams(fileIdParamSchema),
  validateBody(shareLinkCreateSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const fileId = req.params['id'] as string;
      const { wrappedKeyBase64, passwordHash, canDownload, maxUses, expiresAt } = req.body;

      await assertFileOwnership(userId, fileId);

      const shareLink = await prisma.shareLink.create({
        data: {
          fileId,
          wrappedKey: wrappedKeyBase64,
          passwordHash: passwordHash ?? null,
          canDownload: canDownload ?? true,
          maxUses: maxUses ?? null,
          expiresAt: expiresAt ? new Date(expiresAt) : null,
          createdByUserId: userId,
          useCount: 0,
        },
      });

      await logAuditEvent({
        userId,
        eventType: 'SHARE_LINK_CREATED',
        resourceId: shareLink.id,
        success: true,
        ipAddress: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        metadata: { fileId, maxUses, expiresAt },
      });

      res.status(201).json({
        id: shareLink.id,
        createdAt: shareLink.createdAt.toISOString(),
        expiresAt: shareLink.expiresAt?.toISOString() ?? null,
        maxUses: shareLink.maxUses,
      });
    } catch (error) {
      next(error);
    }
  }
);

// Mounts at /share-links/:id
shareLinkRouter.get(
  '/:id',
  shareLinkPasswordLimiter,
  validateParams(shareIdParamSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const linkId = req.params['id'] as string;
      const password = (req.body?.password ?? req.query['password']) as string | undefined;

      const link = await prisma.shareLink.findUnique({
        where: { id: linkId },
        include: { file: true },
      });

      if (!link || link.revokedAt || (link.expiresAt && link.expiresAt < new Date())) {
        throw new NotFoundError('Link not found or expired');
      }

      if (link.maxUses !== null && link.useCount >= link.maxUses) {
        throw new NotFoundError('Link maximum usage reached');
      }

      if (link.passwordHash) {
        if (!password) {
          return res.status(401).json({
            error: {
              code: 'PASSWORD_REQUIRED',
              message: 'Password required to access this share link',
            },
            requiresPassword: true,
          });
        }
        const valid = await argon2.verify(link.passwordHash, password);
        if (!valid) {
          throw new UnauthorizedError('Invalid password for share link');
        }
      }

      await prisma.shareLink.update({
        where: { id: linkId },
        data: { useCount: { increment: 1 } },
      });

      await logAuditEvent({
        userId: null, // Anonymous access
        eventType: 'SHARE_LINK_ACCESSED',
        resourceId: link.id,
        success: true,
        ipAddress: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        metadata: { fileId: link.fileId },
      });

      let downloadUrl: string | null = null;
      let downloadUrlExpiresAt: string | null = null;
      if (link.canDownload) {
        const presigned = await s3Service.generateDownloadUrl(link.file.s3Key);
        downloadUrl = presigned.url;
        downloadUrlExpiresAt = presigned.expiresAt;
      }

      return res.json({
        wrappedKeyBase64: link.wrappedKey,
        encryptedManifestBase64: Buffer.from(link.file.encryptedManifest).toString('base64'),
        manifestIvBase64: link.file.manifestIv,
        fileId: link.fileId,
        canDownload: link.canDownload,
        downloadUrl,
        downloadUrlExpiresAt,
        requiresPassword: !!link.passwordHash,
      });
    } catch (error) {
      return next(error);
    }
  }
);

shareLinkRouter.delete(
  '/:id',
  requireAuth,
  validateParams(shareIdParamSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const linkId = req.params['id'] as string;

      const link = await prisma.shareLink.findUnique({
        where: { id: linkId },
        include: { file: true },
      });

      if (!link) throw new NotFoundError('Share link not found');

      if (link.createdByUserId !== userId && link.file.ownerId !== userId) {
        throw new ForbiddenError('Not authorized to revoke this link');
      }

      await prisma.shareLink.update({
        where: { id: linkId },
        data: { revokedAt: new Date() },
      });

      await logAuditEvent({
        userId,
        eventType: 'SHARE_LINK_REVOKED',
        resourceId: linkId,
        success: true,
        ipAddress: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        metadata: { fileId: link.fileId },
      });

      res.status(204).send();
    } catch (error) {
      next(error);
    }
  }
);
