import { Request, Response, NextFunction } from 'express';
import { jwtVerify } from 'jose';
import { env } from '../config/env';
import { UnauthorizedError, ForbiddenError } from '../types/errors';
import { UserRole } from '@ciphervault/shared';

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

    const secret = new TextEncoder().encode(env.JWT_SECRET);
    
    const { payload, protectedHeader } = await jwtVerify(token, secret, {
      algorithms: ['HS256'],
    });

    if (protectedHeader.alg === 'none') {
      throw new UnauthorizedError('Invalid token algorithm');
    }

    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      throw new UnauthorizedError('Token expired');
    }

    req.user = {
      id: payload.id as string,
      email: payload.email as string,
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
