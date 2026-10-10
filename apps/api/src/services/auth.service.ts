import argon2 from 'argon2';
import { SignJWT, jwtVerify } from 'jose';
import crypto from 'crypto';
import { env } from '../config/env';

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
};

export const hashAuthKey = async (authKey: string): Promise<string> => {
  return argon2.hash(authKey, ARGON2_OPTIONS);
};

export const verifyAuthKey = async (authKey: string, hash: string): Promise<boolean> => {
  return argon2.verify(hash, authKey);
};

export const generateAccessToken = async (user: { id: string; email: string; role: string }): Promise<string> => {
  const secret = new TextEncoder().encode(env.JWT_SECRET);
  return new SignJWT({ id: user.id, email: user.email, role: user.role })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${env.ACCESS_TOKEN_TTL_MINUTES}m`)
    .sign(secret);
};

export const generateRefreshToken = (): string => {
  return crypto.randomBytes(32).toString('base64url');
};

export const verifyAccessToken = async (token: string): Promise<{ id: string; email: string; role: string }> => {
  const secret = new TextEncoder().encode(env.JWT_SECRET);
  const { payload } = await jwtVerify(token, secret, {
    algorithms: ['HS256'],
    requiredClaims: ['exp', 'iat'],
  });

  if (
    typeof payload.exp !== 'number' ||
    typeof payload.iat !== 'number' ||
    typeof payload.id !== 'string' ||
    payload.id.length === 0 ||
    typeof payload.email !== 'string' ||
    payload.email.length === 0 ||
    (payload.role !== 'USER' && payload.role !== 'ADMIN')
  ) {
    throw new Error('Invalid access token claims');
  }

  return {
    id: payload.id,
    email: payload.email,
    role: payload.role,
  };
};

export const hashToken = (token: string): string => {
  return crypto.createHash('sha256').update(token).digest('hex');
};
