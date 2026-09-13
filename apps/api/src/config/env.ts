import { z } from 'zod';

const envSchema = z.object({
  DATABASE_URL: z.string().startsWith('postgresql://'),
  REDIS_URL: z.string(),
  JWT_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  AWS_REGION: z.string(),
  AWS_ACCESS_KEY_ID: z.string(),
  AWS_SECRET_ACCESS_KEY: z.string(),
  AWS_S3_BUCKET: z.string(),
  CORS_ORIGIN: z.string().default('http://localhost:3000'),
  MAX_FILE_SIZE_BYTES: z.coerce.number().default(5368709120),
  ACCESS_TOKEN_TTL_MINUTES: z.coerce.number().default(15),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().default(30),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  API_PORT: z.coerce.number().default(4000),
}).refine(data => data.JWT_SECRET !== data.JWT_REFRESH_SECRET, {
  message: "JWT_SECRET and JWT_REFRESH_SECRET must be different",
  path: ["JWT_REFRESH_SECRET"]
});

export const env = envSchema.parse(process.env);
