import Redis from 'ioredis';
import { env } from './env';
import { logger } from './logger';

export const redis = new Redis(env.REDIS_URL, {
  maxRetriesPerRequest: 1,
  enableOfflineQueue: false,
  retryStrategy(times) {
    if (times > 3 && env.NODE_ENV !== 'production') {
      return null; // Stop reconnection loop if Redis is absent in local dev
    }
    return Math.min(times * 500, 5000);
  },
});

redis.on('error', (err) => {
  // Log once gracefully without crashing process
  if (err.message.includes('ECONNREFUSED')) {
    logger.warn('Redis is not reachable; falling back to in-memory operations');
  } else {
    logger.error({ error: err.message }, 'Redis error');
  }
});

redis.on('connect', () => {
  logger.info('Connected to Redis');
});
