import { prisma } from '../config/database';
import { logAuditEvent } from './audit.service';
import { ForbiddenError, NotFoundError } from '../types/errors';

export async function assertFileAccess(
  userId: string,
  fileId: string,
  requiredPermission: 'view' | 'download'
): Promise<{ isOwner: boolean; wrappedKey?: string }> {
  const file = await prisma.file.findUnique({
    where: { id: fileId }
  });

  if (!file) {
    throw new NotFoundError('File not found');
  }

  if (file.ownerId === userId) {
    const grant = await prisma.fileKeyGrant.findUnique({
      where: {
        fileId_userId: {
          fileId: fileId,
          userId: userId
        }
      }
    });
    return { isOwner: true, wrappedKey: grant?.wrappedKey };
  }

  const share = await prisma.fileShare.findUnique({
    where: {
      fileId_granteeUserId: {
        fileId: fileId,
        granteeUserId: userId
      }
    }
  });

  if (!share || share.revokedAt || (share.expiresAt && share.expiresAt < new Date())) {
    await logAuditEvent({
      userId,
      eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      resourceId: fileId,
      success: false,
      metadata: { reason: 'Share not found, revoked, or expired' }
    });
    throw new ForbiddenError('Access denied');
  }

  if (requiredPermission === 'download' && !share.canDownload) {
    await logAuditEvent({
      userId,
      eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      resourceId: fileId,
      success: false,
      metadata: { reason: 'Download permission required' }
    });
    throw new ForbiddenError('Download access denied');
  }

  const grant = await prisma.fileKeyGrant.findUnique({
    where: {
      fileId_userId: {
        fileId: fileId,
        userId: userId
      }
    }
  });

  if (!grant) {
    await logAuditEvent({
      userId,
      eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      resourceId: fileId,
      success: false,
      metadata: { reason: 'Key grant not found' }
    });
    throw new ForbiddenError('Access denied: missing key grant');
  }

  return { isOwner: false, wrappedKey: grant.wrappedKey };
}

export async function assertFileOwnership(userId: string, fileId: string): Promise<void> {
  const file = await prisma.file.findUnique({
    where: { id: fileId }
  });

  if (!file) {
    throw new NotFoundError('File not found');
  }

  if (file.ownerId !== userId) {
    await logAuditEvent({
      userId,
      eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
      resourceId: fileId,
      success: false,
      metadata: { reason: 'Ownership required' }
    });
    throw new ForbiddenError('Must be file owner');
  }
}
