import { Router, Request, Response, NextFunction } from 'express';
import { prisma } from '../config/database';
import { requireAuth, requireRole } from '../middleware/auth.middleware';
import { validateBody, validateParams } from '../middleware/validation.middleware';
import { adminUserUpdateSchema, adminUserIdParamSchema } from '@ciphervault/shared';
import { logAuditEvent } from '../services/audit.service';
import { NotFoundError } from '../types/errors';

export const adminRouter = Router();

adminRouter.get(
  '/users',
  requireAuth,
  requireRole('ADMIN'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const cursor = req.query.cursor as string | undefined;
      const limit = Math.min(Math.max(parseInt(req.query.limit as string) || 20, 1), 100);

      const users = await prisma.user.findMany({
        take: limit + 1,
        ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          email: true,
          role: true,
          isDisabled: true,
          createdAt: true,
          updatedAt: true,
        },
      });

      let nextCursor: string | null = null;
      let items = users;
      if (users.length > limit) {
        const nextItem = users[limit - 1];
        nextCursor = nextItem ? nextItem.id : null;
        items = users.slice(0, limit);
      }

      res.json({
        items: items.map((u) => ({
          id: u.id,
          email: u.email,
          role: u.role,
          isDisabled: u.isDisabled,
          createdAt: u.createdAt.toISOString(),
          updatedAt: u.updatedAt.toISOString(),
        })),
        nextCursor,
        hasMore: nextCursor !== null,
      });
    } catch (error) {
      next(error);
    }
  }
);

adminRouter.patch(
  '/users/:id',
  requireAuth,
  requireRole('ADMIN'),
  validateParams(adminUserIdParamSchema),
  validateBody(adminUserUpdateSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.params['id'] as string;
      const adminId = req.user!.id;
      const { isDisabled, role } = req.body;

      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user) throw new NotFoundError('User not found');

      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: {
          ...(isDisabled !== undefined && { isDisabled }),
          ...(role !== undefined && { role }),
        },
      });

      if (isDisabled !== undefined) {
        await logAuditEvent({
          userId: adminId,
          eventType: isDisabled ? 'ACCOUNT_DISABLED' : 'ACCOUNT_ENABLED',
          resourceId: userId,
          success: true,
          ipAddress: req.ip ?? null,
          userAgent: req.headers['user-agent'] ?? null,
          metadata: { targetUserId: userId },
        });
      }

      res.json({
        id: updatedUser.id,
        email: updatedUser.email,
        role: updatedUser.role,
        isDisabled: updatedUser.isDisabled,
        createdAt: updatedUser.createdAt.toISOString(),
        updatedAt: updatedUser.updatedAt.toISOString(),
      });
    } catch (error) {
      next(error);
    }
  }
);

adminRouter.get(
  '/audit',
  requireAuth,
  requireRole('ADMIN'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const cursor = req.query.cursor as string | undefined;
      const limit = Math.min(Math.max(parseInt(req.query.limit as string) || 20, 1), 100);

      const logs = await prisma.auditLog.findMany({
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
