import { Router, Request, Response, NextFunction } from 'express';
import { prisma } from '../config/database';
import { requireAuth } from '../middleware/auth.middleware';
import { validateBody, validateParams } from '../middleware/validation.middleware';
import { assertFileAccess, assertFileOwnership } from '../services/authorization.service';
import { logAuditEvent } from '../services/audit.service';
import * as s3Service from '../services/s3.service';
import { NotFoundError, ValidationError } from '../types/errors';
import {
  fileInitUploadSchema,
  fileIdParamSchema,
  fileCompleteUploadSchema,
} from '@ciphervault/shared';

export const fileRouter = Router();
const MAX_FILE_SIZE_BYTES = BigInt(process.env.MAX_FILE_SIZE_BYTES || '5368709120'); // Default 5GB

fileRouter.post(
  '/init-upload',
  requireAuth,
  validateBody(fileInitUploadSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const {
        totalSizeBytes,
        chunkCount,
        encryptedManifestBase64,
        manifestIvBase64,
        wrappedKeyBase64,
      } = req.body;

      if (BigInt(totalSizeBytes) > MAX_FILE_SIZE_BYTES) {
        throw new ValidationError('File size exceeds maximum limit');
      }

      const s3Key = s3Service.generateS3Key(userId);
      const uploadId = await s3Service.initiateMultipartUpload(s3Key);
      const presignedUrls = await s3Service.generateUploadPartUrls(
        s3Key,
        uploadId,
        chunkCount
      );

      const file = await prisma.$transaction(async (tx) => {
        const createdFile = await tx.file.create({
          data: {
            ownerId: userId,
            s3Key: s3Key,
            encryptedManifest: Buffer.from(encryptedManifestBase64, 'base64'),
            manifestIv: manifestIvBase64,
            sizeBytes: BigInt(totalSizeBytes),
            status: 'PENDING',
            s3UploadId: uploadId,
          },
        });

        await tx.fileKeyGrant.create({
          data: {
            fileId: createdFile.id,
            userId: userId,
            wrappedKey: wrappedKeyBase64,
            grantedByUserId: userId,
          },
        });

        return createdFile;
      });

      await logAuditEvent({
        userId,
        eventType: 'FILE_UPLOAD',
        resourceId: file.id,
        success: true,
        ipAddress: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        metadata: { status: 'INITIATED' },
      });

      res.status(201).json({
        fileId: file.id,
        s3Key,
        uploadId,
        presignedUrls,
      });
    } catch (error) {
      next(error);
    }
  }
);

fileRouter.post(
  '/:id/complete-upload',
  requireAuth,
  validateParams(fileIdParamSchema),
  validateBody(fileCompleteUploadSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const fileId = req.params['id'] as string;
      const { uploadId, parts } = req.body;

      await assertFileOwnership(userId, fileId);

      const file = await prisma.file.findUnique({ where: { id: fileId } });
      if (!file) throw new NotFoundError('File not found');

      // Complete multipart upload in S3
      await s3Service.completeMultipartUpload(file.s3Key, uploadId, parts);

      const objectExists = await s3Service.headObject(file.s3Key);
      if (!objectExists.exists) {
        throw new ValidationError('S3 object not found or incomplete');
      }

      const updatedFile = await prisma.file.update({
        where: { id: fileId },
        data: {
          status: 'COMPLETE',
          sizeBytes: BigInt(objectExists.contentLength),
        },
      });

      await logAuditEvent({
        userId,
        eventType: 'FILE_UPLOAD',
        resourceId: fileId,
        success: true,
        ipAddress: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        metadata: { status: 'COMPLETED' },
      });

      res.json({
        id: updatedFile.id,
        status: updatedFile.status,
        sizeBytes: updatedFile.sizeBytes.toString(),
        createdAt: updatedFile.createdAt.toISOString(),
      });
    } catch (error) {
      next(error);
    }
  }
);

fileRouter.get(
  '/',
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const cursor = req.query.cursor as string | undefined;
      const limit = Math.min(Math.max(parseInt(req.query.limit as string) || 20, 1), 100);

      const files = await prisma.file.findMany({
        where: {
          OR: [
            { ownerId: userId },
            { keyGrants: { some: { userId: userId } } },
          ],
          status: { not: 'DELETED' },
        },
        take: limit + 1,
        ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
        orderBy: { createdAt: 'desc' },
        include: { keyGrants: { where: { userId } } },
      });

      let nextCursor: string | null = null;
      let items = files;
      if (files.length > limit) {
        const nextItem = files[limit - 1];
        nextCursor = nextItem ? nextItem.id : null;
        items = files.slice(0, limit);
      }

      res.json({
        items: items.map((f) => ({
          id: f.id,
          ownerId: f.ownerId,
          sizeBytes: f.sizeBytes.toString(),
          status: f.status,
          encryptedManifestBase64: Buffer.from(f.encryptedManifest).toString('base64'),
          manifestIvBase64: f.manifestIv,
          createdAt: f.createdAt.toISOString(),
          wrappedKey: f.keyGrants[0]?.wrappedKey ?? '',
          isOwner: f.ownerId === userId,
        })),
        nextCursor,
        hasMore: nextCursor !== null,
      });
    } catch (error) {
      next(error);
    }
  }
);

fileRouter.get(
  '/:id',
  requireAuth,
  validateParams(fileIdParamSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const fileId = req.params['id'] as string;

      const { wrappedKey } = await assertFileAccess(userId, fileId, 'view');

      const file = await prisma.file.findUnique({ where: { id: fileId } });
      if (!file) throw new NotFoundError('File not found');

      res.json({
        id: file.id,
        ownerId: file.ownerId,
        sizeBytes: file.sizeBytes.toString(),
        status: file.status,
        createdAt: file.createdAt.toISOString(),
        updatedAt: file.updatedAt.toISOString(),
        encryptedManifestBase64: Buffer.from(file.encryptedManifest).toString('base64'),
        manifestIvBase64: file.manifestIv,
        wrappedKeyBase64: wrappedKey ?? '',
      });
    } catch (error) {
      next(error);
    }
  }
);

fileRouter.get(
  '/:id/download-url',
  requireAuth,
  validateParams(fileIdParamSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const fileId = req.params['id'] as string;

      await assertFileAccess(userId, fileId, 'download');

      const file = await prisma.file.findUnique({ where: { id: fileId } });
      if (!file) throw new NotFoundError('File not found');

      const { url, expiresAt } = await s3Service.generateDownloadUrl(file.s3Key);

      await logAuditEvent({
        userId,
        eventType: 'FILE_DOWNLOAD',
        resourceId: fileId,
        success: true,
        ipAddress: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
      });

      res.json({ downloadUrl: url, expiresAt });
    } catch (error) {
      next(error);
    }
  }
);

fileRouter.delete(
  '/:id',
  requireAuth,
  validateParams(fileIdParamSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const fileId = req.params['id'] as string;

      await assertFileOwnership(userId, fileId);

      const file = await prisma.file.findUnique({ where: { id: fileId } });
      if (!file) throw new NotFoundError('File not found');

      await prisma.file.update({
        where: { id: fileId },
        data: { status: 'DELETED', deletedAt: new Date() },
      });

      try {
        await s3Service.deleteObject(file.s3Key);
      } catch (e) {
        console.error(`Failed to delete S3 object ${file.s3Key}`, e);
      }

      await logAuditEvent({
        userId,
        eventType: 'FILE_DELETE',
        resourceId: fileId,
        success: true,
        ipAddress: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
      });

      res.status(204).send();
    } catch (error) {
      next(error);
    }
  }
);
