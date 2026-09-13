import { Router, Request, Response, NextFunction } from 'express';
import { prisma } from '../config/database';
import { requireAuth } from '../middleware/auth.middleware';
import { NotFoundError, ValidationError } from '../types/errors';

export const userRouter = Router();

userRouter.get('/me', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.user!.id;
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundError('User not found');

    res.json({
      id: user.id,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt.toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

userRouter.get('/lookup', requireAuth, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const email = req.query['email'] as string | undefined;
    if (!email) {
      throw new ValidationError('Email query parameter required');
    }

    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase().trim() },
    });
    if (!user) {
      throw new NotFoundError('User not found');
    }

    res.json({
      id: user.id,
      email: user.email,
      publicKeyBase64: user.publicKey,
    });
  } catch (error) {
    next(error);
  }
});
