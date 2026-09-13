import { describe, it, expect, beforeAll } from 'vitest';
import {
  hashAuthKey,
  verifyAuthKey,
  generateAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  hashToken,
} from '../../services/auth.service';

describe('Auth Service Unit Tests', () => {
  beforeAll(() => {
    process.env.JWT_SECRET = 'test-jwt-secret-with-minimum-32-chars-length!';
    process.env.JWT_REFRESH_SECRET = 'test-jwt-refresh-secret-with-minimum-32-chars-length!';
    process.env.ACCESS_TOKEN_TTL_MINUTES = '15';
    process.env.REFRESH_TOKEN_TTL_DAYS = '30';
  });

  describe('Argon2id Hashing', () => {
    it('hashes authKey and successfully verifies correct key', async () => {
      const authKey = 'ciphervault-client-derived-auth-key-base64';
      const hash = await hashAuthKey(authKey);

      expect(hash).toBeDefined();
      expect(hash).toContain('$argon2id$');

      const isValid = await verifyAuthKey(authKey, hash);
      expect(isValid).toBe(true);
    });

    it('rejects incorrect authKey', async () => {
      const authKey = 'correct-auth-key';
      const hash = await hashAuthKey(authKey);

      const isValid = await verifyAuthKey('wrong-auth-key', hash);
      expect(isValid).toBe(false);
    });
  });

  describe('JWT Access Token Lifecycle', () => {
    it('generates a signed JWT with role and user info', async () => {
      const user = {
        id: 'user-uuid-1234',
        email: 'alice@example.com',
        role: 'USER',
      };

      const token = await generateAccessToken(user);
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');

      const verified = await verifyAccessToken(token);
      expect(verified.id).toBe(user.id);
      expect(verified.email).toBe(user.email);
      expect(verified.role).toBe(user.role);
    });

    it('rejects tampered JWT signature', async () => {
      const user = {
        id: 'user-uuid-1234',
        email: 'alice@example.com',
        role: 'USER',
      };

      const token = await generateAccessToken(user);
      const parts = token.split('.');
      // Tamper with payload
      const tamperedToken = `${parts[0]}.${parts[1]}x.${parts[2]}`;

      await expect(verifyAccessToken(tamperedToken)).rejects.toThrow();
    });
  });

  describe('Refresh Token Rotation & Hashing', () => {
    it('generates random URL-safe refresh tokens', () => {
      const token1 = generateRefreshToken();
      const token2 = generateRefreshToken();

      expect(token1).toBeDefined();
      expect(token1).not.toBe(token2);
      expect(token1).not.toContain('+');
      expect(token1).not.toContain('/');
    });

    it('hashes refresh token deterministically with SHA-256 hex', () => {
      const token = 'sample-refresh-token';
      const hash1 = hashToken(token);
      const hash2 = hashToken(token);

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // SHA-256 hex length
    });
  });
});
