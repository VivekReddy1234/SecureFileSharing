import { Request, Response, NextFunction } from 'express';
import { UnauthorizedError, ForbiddenError } from '../types/errors';
import { UserRole } from '@ciphervault/shared';
import { verifyAccessToken } from '../services/auth.service';

export const requireAuth = async (req: Request, _res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      throw new UnauthorizedError('Missing or invalid token');
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      throw new UnauthorizedError('Missing token');
    }

    const payload = await verifyAccessToken(token);

    req.user = {
      id: payload.id,
      email: payload.email,
      role: payload.role as UserRole,
    };

    next();
  } catch (error) {
    next(new UnauthorizedError('Invalid token'));
  }
};

export const requireRole = (role: string) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new UnauthorizedError('Not authenticated'));
    }
    
    if (req.user.role !== role) {
      return next(new ForbiddenError('Insufficient permissions'));
    }
    
    next();
  };
};
