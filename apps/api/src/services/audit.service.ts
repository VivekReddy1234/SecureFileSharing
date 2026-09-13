import { Prisma } from '@prisma/client';
import { prisma } from '../config/database';
import { logger } from '../config/logger';

export interface AuditEventParams {
  userId?: string | null;
  eventType: string;
  resourceId?: string | null;
  success: boolean;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown> | null;
}

export const logEvent = async (params: AuditEventParams): Promise<void> => {
  try {
    const { userId, eventType, resourceId, success, ipAddress, userAgent, metadata } = params;
    
    const safeMetadata = metadata ? { ...metadata } : undefined;
    if (safeMetadata) {
      const sensitiveKeys = ['authKey', 'jwt', 'password', 'privateKey', 'dek', 'secret', 'token'];
      for (const key of Object.keys(safeMetadata)) {
        if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
          safeMetadata[key] = '[REDACTED]';
        }
      }
    }

    await prisma.auditLog.create({
      data: {
        userId: userId ?? undefined,
        eventType,
        resourceId: resourceId ?? undefined,
        success,
        ipAddress: ipAddress ?? undefined,
        userAgent: userAgent ?? undefined,
        metadata: safeMetadata as Prisma.InputJsonValue | undefined,
      },
    });
  } catch (error) {
    logger.error({ error, params }, 'Failed to write audit log');
  }
};

export const logAuditEvent = logEvent;
