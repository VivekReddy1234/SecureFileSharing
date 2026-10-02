import cors from 'cors';
import cookieParser from 'cookie-parser';
import express, { ErrorRequestHandler, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import { v4 as uuidv4 } from 'uuid';
import { CSRF_HEADER_NAME, CSRF_HEADER_VALUE } from '@ciphervault/shared';

// Controllers
import { authRouter } from './controllers/auth.controller';
import { fileRouter } from './controllers/file.controller';
import { shareRouter } from './controllers/share.controller';
import { shareLinkRouter } from './controllers/share-link.controller';
import { auditRouter } from './controllers/audit.controller';
import { adminRouter } from './controllers/admin.controller';
import { userRouter } from './controllers/user.controller';

// Middleware
import { generalLimiter } from './middleware/rate-limit.middleware';
import { loginLimiter, registrationLimiter, refreshLimiter } from './middleware/rate-limit.middleware';

// Error types
import { AppError } from './types/errors';
import { env } from './config/env';

export const app = express();

const normalizeOrigin = (value: string): string => {
  try {
    return new URL(value).origin;
  } catch {
    return value.trim().replace(/\/+$/, '');
  }
};

const allowedOrigin = normalizeOrigin(env.CORS_ORIGIN);

// ──── Security Headers (Helmet) ────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // Tailwind needs inline styles
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'", allowedOrigin],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false, // Allow S3 presigned URL fetches
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'cross-origin' }, // Allow S3 direct uploads
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: {
      maxAge: 63072000,
      includeSubDomains: true,
      preload: true,
    },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  })
);

// ──── CORS ────
app.use(
  cors({
    origin: (origin, callback) => {
      const normalizedOrigin = origin ? normalizeOrigin(origin) : '';
      // Allow requests with no origin (curl, server-to-server) or matching origin
      if (!origin || normalizedOrigin === allowedOrigin) {
        callback(null, true);
      } else {
        callback(new Error('CORS policy violation: origin not permitted'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      CSRF_HEADER_NAME,
      'x-request-id',
    ],
    exposedHeaders: ['x-request-id'],
    maxAge: 86400,
  })
);

// ──── Cookie Parser (for refresh token in httpOnly cookie) ────
app.use(cookieParser());

// ──── Request ID ────
app.use((req: Request, res: Response, next: NextFunction) => {
  const incomingId = req.header('x-request-id');
  const requestId =
    incomingId && incomingId.trim().length > 0 ? incomingId : uuidv4();
  req.headers['x-request-id'] = requestId;
  res.setHeader('x-request-id', requestId);
  next();
});

// ──── Body Parsers ────
// Small limit — actual file bytes go directly to S3, not through this API
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ──── CSRF Header Guard ────
app.use((req: Request, _res: Response, next: NextFunction) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }

  const csrfHeader = req.header(CSRF_HEADER_NAME);
  if (csrfHeader !== CSRF_HEADER_VALUE) {
    return next(new AppError(403, 'Missing or invalid CSRF header', 'CSRF_MISSING_OR_INVALID'));
  }

  return next();
});

// ──── Rate Limiting ────
app.use(generalLimiter);

// ──── Health & Readiness Probes ────
app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
  });
});

app.get('/ready', async (_req: Request, res: Response) => {
  try {
    // Import lazily to avoid circular dependency issues at startup
    const { prisma } = await import('./config/database');
    const { redis } = await import('./config/redis');

    await prisma.$queryRawUnsafe('SELECT 1');
    await redis.ping();

    res.status(200).json({
      status: 'ready',
      timestamp: new Date().toISOString(),
      checks: { database: 'ok', redis: 'ok' },
    });
  } catch {
    res.status(503).json({
      status: 'not_ready',
      timestamp: new Date().toISOString(),
    });
  }
});

// ──── Routes ────
// Auth routes with specific rate limits
app.use('/auth/login', loginLimiter);
app.use('/auth/register', registrationLimiter);
app.use('/auth/refresh', refreshLimiter);
app.use('/auth', authRouter);

// Resource routes
app.use('/users', userRouter);
app.use('/files', fileRouter);
app.use('/files', shareRouter); // /files/:id/shares
app.use('/shares', shareRouter); // /shares/:id
app.use('/files', shareLinkRouter); // /files/:id/share-links
app.use('/share-links', shareLinkRouter); // /share-links/:id (public access + revoke)
app.use('/audit', auditRouter);
app.use('/admin', adminRouter);

// ──── 404 Handler ────
app.use((req: Request, res: Response) => {
  const requestId = (req.headers['x-request-id'] as string) ?? uuidv4();
  res.status(404).json({
    error: {
      code: 'NOT_FOUND',
      message: `Resource not found: ${req.method} ${req.path}`,
      requestId,
    },
  });
});

// ──── Centralized Error Handler ────
const errorHandler: ErrorRequestHandler = (
  err: unknown,
  req: Request,
  res: Response,
  _next: NextFunction
) => {
  const requestId = (req.headers['x-request-id'] as string) ?? uuidv4();
  const isProduction = process.env.NODE_ENV === 'production';

  let statusCode = 500;
  let code = 'INTERNAL_SERVER_ERROR';
  let message = 'An unexpected server error occurred';

  if (err instanceof AppError) {
    statusCode = err.statusCode;
    code = err.code;
    message = err.message;
  } else if (err instanceof Error) {
    if (err.message.includes('CORS')) {
      statusCode = 403;
      code = 'CORS_ERROR';
      message = 'Origin not permitted';
    } else {
      // In production, never expose internal error details
      message = isProduction
        ? 'An unexpected server error occurred'
        : err.message;
    }
  }

  // Log the full error server-side
  if (statusCode >= 500) {
    console.error(`[${requestId}] Unhandled error:`, err);
  }

  res.status(statusCode).json({
    error: {
      code,
      message,
      requestId,
    },
  });
};

app.use(errorHandler);
