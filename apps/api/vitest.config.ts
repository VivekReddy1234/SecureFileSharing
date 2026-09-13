import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    env: {
      DATABASE_URL: 'postgresql://postgres:postgres@localhost:5432/ciphervault_test?schema=public',
      REDIS_URL: 'redis://localhost:6379',
      JWT_SECRET: 'test-jwt-access-secret-minimum-32-characters-required!',
      JWT_REFRESH_SECRET: 'test-jwt-refresh-secret-different-and-min-32-chars!',
      AWS_REGION: 'us-east-1',
      AWS_ACCESS_KEY_ID: 'test-access-key-id',
      AWS_SECRET_ACCESS_KEY: 'test-secret-access-key',
      AWS_S3_BUCKET: 'test-bucket',
      NODE_ENV: 'test',
    },
  },
});
