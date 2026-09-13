import pino from 'pino';
import { env } from './env';

const sensitiveKeys = ['authKey', 'jwt', 'password', 'privateKey', 'dek', 'refreshToken', 'accessToken', 'secret'];

export const logger = pino({
  level: env.NODE_ENV === 'test' ? 'silent' : 'info',
  formatters: {
    level: (label) => {
      return { level: label };
    },
  },
  redact: {
    paths: sensitiveKeys.map(key => `*.*${key}*`),
    censor: '[REDACTED]',
  },
});

export const createRequestLogger = (requestId: string) => {
  return logger.child({ requestId });
};
