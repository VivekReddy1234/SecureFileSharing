import { Router, Request, Response, NextFunction } from 'express';
import { prisma } from '../config/database';
import { requireAuth } from '../middleware/auth.middleware';

export const auditRouter = Router();

// Mounts at /audit
auditRouter.get(
  '/',
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const cursor = req.query.cursor as string | undefined;
      const limit = Math.min(Math.max(parseInt(req.query.limit as string) || 20, 1), 100);

      const logs = await prisma.auditLog.findMany({
        where: { userId },
        take: limit + 1,
        ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
        orderBy: { createdAt: 'desc' },
      });

      let nextCursor: string | null = null;
      let items = logs;
      if (logs.length > limit) {
        const nextItem = logs[limit - 1];
        nextCursor = nextItem ? nextItem.id : null;
        items = logs.slice(0, limit);
      }

      res.json({
        items: items.map((l) => ({
          id: l.id,
          userId: l.userId,
          eventType: l.eventType,
          resourceId: l.resourceId,
          success: l.success,
          ipAddress: l.ipAddress,
          userAgent: l.userAgent,
          metadata: l.metadata,
          createdAt: l.createdAt.toISOString(),
        })),
        nextCursor,
        hasMore: nextCursor !== null,
      });
    } catch (error) {
      next(error);
    }
  }
);
