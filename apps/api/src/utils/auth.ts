import crypto from 'node:crypto';
import { env } from '../config/index.js';

export interface TokenPayload {
  sub: string;
  email: string;
  role: 'user' | 'analyst' | 'admin';
  iat?: number;
  exp?: number;
}

/**
 * Hashes a plaintext password using standard scrypt key derivation with a random 16-byte salt.
 */
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return `${salt}:${derivedKey.toString('hex')}`;
}

/**
 * Verifies a password against the stored salt:hash string using constant-time comparison.
 */
export function verifyPassword(password: string, combinedHash: string): boolean {
  if (!combinedHash || !combinedHash.includes(':')) {
    return false;
  }
  const [salt, originalHash] = combinedHash.split(':');
  if (!salt || !originalHash) {
    return false;
  }

  const derivedKey = crypto.scryptSync(password, salt, 64);
  const derivedHashBuffer = Buffer.from(derivedKey.toString('hex'), 'utf8');
  const originalHashBuffer = Buffer.from(originalHash, 'utf8');

  if (derivedHashBuffer.length !== originalHashBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(derivedHashBuffer, originalHashBuffer);
}

/**
 * Generates a signed HMAC-SHA256 JWT token with an expiration timestamp.
 */
export function createToken(payload: Omit<TokenPayload, 'iat' | 'exp'>, expiresInSeconds: number = 86400 * 7): string {
  const header = {
    alg: 'HS256',
    typ: 'JWT',
  };

  const now = Math.floor(Date.now() / 1000);
  const fullPayload: TokenPayload = {
    ...payload,
    iat: now,
    exp: now + expiresInSeconds,
  };

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(fullPayload)).toString('base64url');
  const message = `${headerB64}.${payloadB64}`;

  const signature = crypto
    .createHmac('sha256', env.JWT_SECRET)
    .update(message)
    .digest('base64url');

  return `${message}.${signature}`;
}

/**
 * Verifies and decodes an HMAC-SHA256 JWT token. Throws if signature is invalid or expired.
 */
export function verifyToken(token: string): TokenPayload {
  if (!token || typeof token !== 'string') {
    throw new Error('Authentication token is required');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed token format');
  }

  const [headerB64, payloadB64, signature] = parts;
  const message = `${headerB64}.${payloadB64}`;

  const expectedSignature = crypto
    .createHmac('sha256', env.JWT_SECRET)
    .update(message)
    .digest('base64url');

  const sigBuf = Buffer.from(signature, 'utf8');
  const expBuf = Buffer.from(expectedSignature, 'utf8');

  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    throw new Error('Invalid token signature');
  }

  const payload: TokenPayload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

  if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
    throw new Error('Token has expired');
  }

  return payload;
}

