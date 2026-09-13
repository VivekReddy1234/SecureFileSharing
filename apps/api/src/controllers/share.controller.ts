import { Router, Request, Response, NextFunction } from 'express';
import { prisma } from '../config/database';
import { requireAuth } from '../middleware/auth.middleware';
import { validateBody, validateParams } from '../middleware/validation.middleware';
import { assertFileOwnership } from '../services/authorization.service';
import { logAuditEvent } from '../services/audit.service';
import { shareCreateSchema, fileIdParamSchema, shareIdParamSchema } from '@ciphervault/shared';
import { NotFoundError, ForbiddenError } from '../types/errors';

export const shareRouter = Router();

shareRouter.post(
  '/:id/shares',
  requireAuth,
  validateParams(fileIdParamSchema),
  validateBody(shareCreateSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const fileId = req.params['id'] as string;
      const {
        recipientEmail,
        canView,
        canDownload,
        canReshare,
        wrappedKeyBase64,
        expiresAt,
      } = req.body;

      await assertFileOwnership(userId, fileId);

      const recipient = await prisma.user.findUnique({
        where: { email: recipientEmail.toLowerCase().trim() },
      });
      if (!recipient) {
        throw new NotFoundError('Recipient not found');
      }

      const share = await prisma.$transaction(async (tx) => {
        const newShare = await tx.fileShare.upsert({
          where: {
            fileId_granteeUserId: {
              fileId,
              granteeUserId: recipient.id,
            },
          },
          update: {
            canView,
            canDownload,
            canReshare,
            expiresAt: expiresAt ? new Date(expiresAt) : null,
            revokedAt: null,
          },
          create: {
            fileId,
            granteeUserId: recipient.id,
            canView,
            canDownload,
            canReshare,
            createdByUserId: userId,
            expiresAt: expiresAt ? new Date(expiresAt) : null,
          },
        });

        await tx.fileKeyGrant.upsert({
          where: {
            fileId_userId: {
              fileId,
              userId: recipient.id,
            },
          },
          update: {
            wrappedKey: wrappedKeyBase64,
            grantedByUserId: userId,
          },
          create: {
            fileId,
            userId: recipient.id,
            wrappedKey: wrappedKeyBase64,
            grantedByUserId: userId,
          },
        });

        return newShare;
      });

      await logAuditEvent({
        userId,
        eventType: 'FILE_SHARE',
        resourceId: fileId,
        success: true,
        ipAddress: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        metadata: { granteeUserId: recipient.id },
      });

      res.status(201).json({
        id: share.id,
        fileId: share.fileId,
        granteeUserId: share.granteeUserId,
        canView: share.canView,
        canDownload: share.canDownload,
        canReshare: share.canReshare,
        createdAt: share.createdAt.toISOString(),
        expiresAt: share.expiresAt?.toISOString() ?? null,
      });
    } catch (error) {
      next(error);
    }
  }
);

shareRouter.get(
  '/:id/shares',
  requireAuth,
  validateParams(fileIdParamSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const fileId = req.params['id'] as string;

      await assertFileOwnership(userId, fileId);

      const shares = await prisma.fileShare.findMany({
        where: { fileId, revokedAt: null },
      });

      const userIds = shares.map((s) => s.granteeUserId);
      const users = await prisma.user.findMany({
        where: { id: { in: userIds } },
        select: { id: true, email: true },
      });

      const userMap = new Map(users.map((u) => [u.id, u.email]));

      res.json(
        shares.map((s) => ({
          id: s.id,
          fileId: s.fileId,
          granteeUserId: s.granteeUserId,
          granteeEmail: userMap.get(s.granteeUserId) ?? '',
          canView: s.canView,
          canDownload: s.canDownload,
          canReshare: s.canReshare,
          createdAt: s.createdAt.toISOString(),
          expiresAt: s.expiresAt?.toISOString() ?? null,
        }))
      );
    } catch (error) {
      next(error);
    }
  }
);

const handleRevokeShare = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.user!.id;
    const shareId = req.params['id'] as string;

    const share = await prisma.fileShare.findUnique({
      where: { id: shareId },
      include: { file: true },
    });

    if (!share) throw new NotFoundError('Share not found');

    if (share.file.ownerId !== userId) {
      throw new ForbiddenError('Only the file owner can revoke shares');
    }

    await prisma.$transaction(async (tx) => {
      await tx.fileShare.delete({ where: { id: shareId } });
      await tx.fileKeyGrant.deleteMany({
        where: {
          fileId: share.fileId,
          userId: share.granteeUserId,
        },
      });
    });

    await logAuditEvent({
      userId,
      eventType: 'SHARE_REVOKED',
      resourceId: shareId,
      success: true,
      ipAddress: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
      metadata: { fileId: share.fileId, granteeUserId: share.granteeUserId },
    });

    res.status(204).send();
  } catch (error) {
    next(error);
  }
};

shareRouter.delete(
  '/shares/:id',
  requireAuth,
  validateParams(shareIdParamSchema),
  handleRevokeShare
);

shareRouter.delete(
  '/:id',
  requireAuth,
  validateParams(shareIdParamSchema),
  handleRevokeShare
);
