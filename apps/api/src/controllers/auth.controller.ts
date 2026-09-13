import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { prisma } from '../config/database';
import { logEvent } from '../services/audit.service';
import {
  hashAuthKey,
  verifyAuthKey,
  generateAccessToken,
  generateRefreshToken,
  hashToken,
} from '../services/auth.service';
import { env } from '../config/env';
import { requireAuth } from '../middleware/auth.middleware';
import { validateBody, validateQuery } from '../middleware/validation.middleware';
import { UnauthorizedError, ConflictError } from '../types/errors';
import {
  authRegisterSchema,
  authLoginSchema,
  authChangePasswordSchema,
  authSaltQuerySchema,
} from '@ciphervault/shared';

export const authRouter = Router();

/**
 * Helper to wrap async route handlers so rejected promises are forwarded to Express error handler.
 */
function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch(next);
  };
}

/**
 * GET /auth/salt?email=
 * Returns authSalt and kdfIterations for client-side key derivation.
 * MUST respond identically whether or not the email exists — prevents account enumeration.
 */
authRouter.get(
  '/salt',
  validateQuery(authSaltQuerySchema),
  asyncHandler(async (req: Request, res: Response) => {
    const email = req.query.email as string;

    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase().trim() },
      select: { authSalt: true, kdfIterations: true },
    });

    if (user) {
      res.json({
        authSaltBase64: user.authSalt,
        kdfIterations: user.kdfIterations,
      });
    } else {
      // Return a deterministic but unpredictable dummy salt for unknown emails.
      // Uses HMAC to derive a consistent salt from the email + a server secret,
      // so the same unknown email always gets the same dummy salt (preventing
      // timing-based detection of "new unknown" vs "known unknown" emails).
      const dummySalt = crypto
        .createHmac('sha256', env.JWT_SECRET)
        .update(email)
        .digest('base64');
      res.json({
        authSaltBase64: dummySalt,
        kdfIterations: 600000,
      });
    }
  })
);

/**
 * POST /auth/register
 */
authRouter.post(
  '/register',
  validateBody(authRegisterSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const {
      email,
      authKeyBase64,
      authSaltBase64,
      kdfIterations,
      publicKeyBase64,
      wrappedPrivateKeyBase64,
      wrappedPrivateKeyIvBase64,
      recoveryWrappedPrivateKeyBase64,
      recoveryWrappedKeyIvBase64,
    } = req.body;

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      throw new ConflictError('An account with this email already exists');
    }

    const authHash = await hashAuthKey(authKeyBase64);

    const user = await prisma.user.create({
      data: {
        email,
        authHash,
        authSalt: authSaltBase64,
        kdfIterations,
        publicKey: publicKeyBase64,
        wrappedPrivateKey: wrappedPrivateKeyBase64,
        wrappedPrivateKeyIv: wrappedPrivateKeyIvBase64,
        recoveryWrappedPrivateKey: recoveryWrappedPrivateKeyBase64 ?? null,
        recoveryWrappedKeyIv: recoveryWrappedKeyIvBase64 ?? null,
      },
    });

    await logEvent({
      userId: user.id,
      eventType: 'REGISTER',
      success: true,
      ipAddress: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
    });

    res.status(201).json({ id: user.id, email: user.email });
  })
);

/**
 * POST /auth/login
 * Identical error response for wrong email vs wrong password — prevents enumeration.
 */
authRouter.post(
  '/login',
  validateBody(authLoginSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const { email, authKeyBase64 } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user || user.isDisabled) {
      await logEvent({
        eventType: 'FAILED_LOGIN',
        success: false,
        ipAddress: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        // Log internally whether account exists — NEVER in the API response
        metadata: { accountExists: !!user, reason: user?.isDisabled ? 'disabled' : 'not_found' },
      });
      throw new UnauthorizedError('Invalid email or password');
    }

    const valid = await verifyAuthKey(authKeyBase64, user.authHash);
    if (!valid) {
      await logEvent({
        userId: user.id,
        eventType: 'FAILED_LOGIN',
        success: false,
        ipAddress: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
      });
      throw new UnauthorizedError('Invalid email or password');
    }

    const accessToken = await generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    const refreshToken = generateRefreshToken();
    const familyId = crypto.randomUUID();

    await prisma.refreshToken.create({
      data: {
        tokenHash: hashToken(refreshToken),
        userId: user.id,
        familyId,
        expiresAt: new Date(
          Date.now() + env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000
        ),
        ipAddress: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
      },
    });

    res.cookie('ciphervault_refresh', refreshToken, {
      httpOnly: true,
      secure: env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
      path: '/',
    });

    await logEvent({
      userId: user.id,
      eventType: 'LOGIN',
      success: true,
      ipAddress: req.ip ?? null,
      userAgent: req.headers['user-agent'] ?? null,
    });

    res.json({
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        publicKeyBase64: user.publicKey,
        wrappedPrivateKeyBase64: user.wrappedPrivateKey,
        wrappedPrivateKeyIvBase64: user.wrappedPrivateKeyIv,
      },
    });
  })
);

/**
 * POST /auth/refresh
 * Implements refresh token rotation with reuse detection.
 */
authRouter.post(
  '/refresh',
  asyncHandler(async (req: Request, res: Response) => {
    const token = req.cookies?.ciphervault_refresh;
    if (!token) {
      throw new UnauthorizedError('No refresh token provided');
    }

    const hashedToken = hashToken(token);
    const existingToken = await prisma.refreshToken.findUnique({
      where: { tokenHash: hashedToken },
      include: { user: true },
    });

    if (!existingToken || existingToken.expiresAt < new Date()) {
      throw new UnauthorizedError('Invalid or expired refresh token');
    }

    // REUSE DETECTION: if this token was already revoked, it means someone
    // is replaying a stolen token. Revoke the ENTIRE family.
    if (existingToken.revokedAt) {
      await prisma.refreshToken.updateMany({
        where: { familyId: existingToken.familyId },
        data: { revokedAt: new Date() },
      });

      await logEvent({
        userId: existingToken.userId,
        eventType: 'TOKEN_REUSE_DETECTED',
        success: false,
        ipAddress: req.ip ?? null,
        userAgent: req.headers['user-agent'] ?? null,
        metadata: { familyId: existingToken.familyId },
      });

      res.clearCookie('ciphervault_refresh');
      throw new UnauthorizedError('Token reuse detected — all sessions revoked');
    }

    const newRefreshToken = generateRefreshToken();
    const newTokenHash = hashToken(newRefreshToken);

    // Rotate: revoke old, create new — in a single transaction
    await prisma.$transaction([
      prisma.refreshToken.update({
        where: { id: existingToken.id },
        data: {
          revokedAt: new Date(),
          replacedByHash: newTokenHash,
        },
      }),
      prisma.refreshToken.create({
        data: {
          tokenHash: newTokenHash,
          userId: existingToken.userId,
          familyId: existingToken.familyId,
          expiresAt: new Date(
            Date.now() + env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000
          ),
          ipAddress: req.ip ?? null,
          userAgent: req.headers['user-agent'] ?? null,
        },
      }),
    ]);

    const accessToken = await generateAccessToken({
      id: existingToken.user.id,
      email: existingToken.user.email,
      role: existingToken.user.role,
    });

    res.cookie('ciphervault_refresh', newRefreshToken, {
      httpOnly: true,
      secure: env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
      path: '/',
    });

    await logEvent({
      userId: existingToken.userId,
      eventType: 'TOKEN_REFRESH',
      success: true,
      ipAddress: req.ip ?? null,
    });

    res.json({ accessToken });
  })
);

/**
 * POST /auth/logout
 */
authRouter.post(
  '/logout',
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const token = req.cookies?.ciphervault_refresh;
    if (token) {
      const hashedToken = hashToken(token);
      await prisma.refreshToken.updateMany({
        where: { tokenHash: hashedToken, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    }

    res.clearCookie('ciphervault_refresh', { path: '/' });

    await logEvent({
      userId: req.user!.id,
      eventType: 'LOGOUT',
      success: true,
      ipAddress: req.ip ?? null,
    });

    res.json({ success: true });
  })
);

/**
 * POST /auth/change-password
 * Re-wraps the private key under a new master key derived from the new password.
 * The DEKs don't change — only the user's key wrapping changes.
 */
authRouter.post(
  '/change-password',
  requireAuth,
  validateBody(authChangePasswordSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const {
      currentAuthKeyBase64,
      newAuthKeyBase64,
      newAuthSaltBase64,
      newKdfIterations,
      newWrappedPrivateKeyBase64,
      newWrappedPrivateKeyIvBase64,
    } = req.body;
    const userId = req.user!.id;

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedError('User not found');
    }

    const valid = await verifyAuthKey(currentAuthKeyBase64, user.authHash);
    if (!valid) {
      throw new UnauthorizedError('Current password verification failed');
    }

    const newAuthHash = await hashAuthKey(newAuthKeyBase64);

    // Update auth credentials and re-wrapped private key,
    // then revoke all refresh tokens — all in one transaction
    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: {
          authHash: newAuthHash,
          authSalt: newAuthSaltBase64,
          kdfIterations: newKdfIterations,
          wrappedPrivateKey: newWrappedPrivateKeyBase64,
          wrappedPrivateKeyIv: newWrappedPrivateKeyIvBase64,
        },
      }),
      prisma.refreshToken.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ]);

    res.clearCookie('ciphervault_refresh', { path: '/' });

    await logEvent({
      userId,
      eventType: 'PASSWORD_CHANGED',
      success: true,
      ipAddress: req.ip ?? null,
    });

    res.json({ success: true });
  })
);
