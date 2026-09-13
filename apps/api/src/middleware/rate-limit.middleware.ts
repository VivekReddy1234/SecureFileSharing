import rateLimit, { Options } from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { redis } from '../config/redis';

function createLimiter(prefix: string, options: Partial<Options>) {
  // Use RedisStore only if Redis is explicitly enabled or connected
  const useRedisStore = process.env.NODE_ENV === 'production' && process.env.USE_REDIS_RATE_LIMIT === 'true';

  let store: RedisStore | undefined;
  if (useRedisStore) {
    try {
      store = new RedisStore({
        prefix: `ciphervault:rl:${prefix}:`,
        sendCommand: async (...args: string[]) => {
          return redis.call(args[0]!, ...args.slice(1)) as unknown as import('rate-limit-redis').RedisReply;
        },
      });
    } catch {
      store = undefined;
    }
  }

  return rateLimit({
    ...(store ? { store } : {}),
    standardHeaders: true,
    legacyHeaders: false,
    ...options,
  });
}

export const loginLimiter = createLimiter('login', {
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: 'Too many login attempts, please try again later' },
});

export const registrationLimiter = createLimiter('registration', {
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { message: 'Too many registration attempts, please try again later' },
});

export const refreshLimiter = createLimiter('refresh', {
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { message: 'Too many refresh attempts, please try again later' },
});

export const generalLimiter = createLimiter('general', {
  windowMs: 60 * 1000,
  max: 100,
  message: { message: 'Too many requests, please try again later' },
});

export const shareLinkPasswordLimiter = createLimiter('sharelink', {
  windowMs: 15 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => `${req.ip}-${req.params['linkId'] ?? ''}`,
  message: { message: 'Too many password attempts for this link, please try again later' },
});
