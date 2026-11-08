import crypto from 'node:crypto';
import { env } from '../config/index.js';

export interface TokenPayload {
  sub: string;
  email: string;
  role: 'user' | 'analyst' | 'admin';
  roleVersion: number;
  iss?: string;
  iat: number;
  exp: number;
}

const SCRYPT_OPTIONS: crypto.ScryptOptions = {
  N: 16384,
  r: 8,
  p: 1,
  maxmem: 32 * 1024 * 1024,
};

/**
 * Concurrency limiter to bound parallel scrypt key derivation operations.
 * Protects against thread pool exhaustion and caps memory footprint during load spikes.
 */
export class ScryptConcurrencyLimiter {
  private running = 0;
  private queue: Array<{ resolve: () => void; reject: (err: Error) => void }> = [];

  constructor(
    private readonly maxConcurrent: number = 10,
    private readonly maxQueueLength: number = 100
  ) {}

  async run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.running >= this.maxConcurrent) {
      if (this.queue.length >= this.maxQueueLength) {
        throw new Error('Authentication worker capacity exceeded. Please retry later.');
      }
      await new Promise<void>((resolve, reject) => {
        this.queue.push({ resolve, reject });
      });
    }

    this.running++;
    try {
      return await fn();
    } finally {
      this.running--;
      const next = this.queue.shift();
      if (next) {
        next.resolve();
      }
    }
  }

  get stats() {
    return {
      running: this.running,
      queued: this.queue.length,
      maxConcurrent: this.maxConcurrent,
      maxQueueLength: this.maxQueueLength,
    };
  }
}

export const scryptLimiter = new ScryptConcurrencyLimiter(10, 100);

const scryptAsync = (
  password: crypto.BinaryLike,
  salt: crypto.BinaryLike,
  keylen: number,
  options: crypto.ScryptOptions
): Promise<Buffer> => {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, options, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(derivedKey);
    });
  });
};

interface ParsedScryptParams {
  options: crypto.ScryptOptions;
  salt: string;
  originalHashHex: string;
}

/**
 * Safely parses and validates parameters from versioned or legacy password hashes.
 * Rejects unsupported versions, malformed formats, and parameter values outside safe bounds.
 */
export function parseHashParameters(combinedHash: string): ParsedScryptParams | null {
  if (typeof combinedHash !== 'string' || !combinedHash) {
    return null;
  }

  if (combinedHash.startsWith('scrypt$v=')) {
    const parts = combinedHash.split('$');
    // Format: scrypt$v=1$n=16384,r=8,p=1$<saltHex>$<derivedKeyHex>
    if (parts.length !== 5 || parts[0] !== 'scrypt') {
      return null;
    }

    // Version validation: strictly reject unsupported versions
    if (parts[1] !== 'v=1') {
      return null;
    }

    // Parameter extraction and strict boundary validation
    const paramMatch = parts[2].match(/^n=(\d+),r=(\d+),p=(\d+)$/);
    if (!paramMatch) {
      return null;
    }

    const N = parseInt(paramMatch[1], 10);
    const r = parseInt(paramMatch[2], 10);
    const p = parseInt(paramMatch[3], 10);

    // Validate boundaries to prevent memory exhaustion / CPU DoS from corrupted hashes
    if (
      !Number.isInteger(N) ||
      N < 1024 ||
      N > 32768 ||
      (N & (N - 1)) !== 0 || // Must be power of 2
      !Number.isInteger(r) ||
      r < 1 ||
      r > 16 ||
      !Number.isInteger(p) ||
      p < 1 ||
      p > 4
    ) {
      return null;
    }

    const salt = parts[3];
    const originalHashHex = parts[4];

    if (!salt || !originalHashHex || salt.length < 16) {
      return null;
    }

    return {
      options: {
        N,
        r,
        p,
        maxmem: 32 * 1024 * 1024,
      },
      salt,
      originalHashHex,
    };
  } else if (combinedHash.includes(':')) {
    // Legacy backward-compatibility format: <saltHex>:<derivedKeyHex>
    const parts = combinedHash.split(':');
    if (parts.length !== 2) {
      return null;
    }

    const salt = parts[0];
    const originalHashHex = parts[1];

    if (!salt || !originalHashHex || salt.length < 16) {
      return null;
    }

    return {
      options: SCRYPT_OPTIONS,
      salt,
      originalHashHex,
    };
  }

  return null;
}

// Static dummy hash used to neutralize timing side-channel attacks during login
const DUMMY_HASH =
  'scrypt$v=1$n=16384,r=8,p=1$0123456789abcdef0123456789abcdef$00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

/**
 * Non-blocking password hashing using standard scrypt key derivation with random 16-byte salt.
 * Formats hash with explicit scrypt parameters and versioning:
 * scrypt$v=1$n=16384,r=8,p=1$<saltHex>$<derivedKeyHex>
 */
export async function hashPassword(password: string): Promise<string> {
  if (!password || typeof password !== 'string') {
    throw new Error('Password must be a valid non-empty string.');
  }
  if (password.length > 128) {
    throw new Error('Password must not exceed 128 characters.');
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = (await scryptLimiter.run(() => scryptAsync(password, salt, 64, SCRYPT_OPTIONS))) as Buffer;
  return `scrypt$v=1$n=16384,r=8,p=1$${salt}$${derivedKey.toString('hex')}`;
}

/**
 * Synchronous password hashing helper for synchronous contexts and tests.
 */
export function hashPasswordSync(password: string): string {
  if (!password || typeof password !== 'string') {
    throw new Error('Password must be a valid non-empty string.');
  }
  if (password.length > 128) {
    throw new Error('Password must not exceed 128 characters.');
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64, SCRYPT_OPTIONS);
  return `scrypt$v=1$n=16384,r=8,p=1$${salt}$${derivedKey.toString('hex')}`;
}

/**
 * Non-blocking, constant-time password verification.
 * Supports both versioned scrypt$v=1$... format and legacy <saltHex>:<hashHex> format.
 */
export async function verifyPassword(password: string, combinedHash: string): Promise<boolean> {
  if (!password || typeof password !== 'string' || password.length > 128) {
    return false;
  }
  if (!combinedHash || typeof combinedHash !== 'string') {
    return false;
  }

  try {
    const parsed = parseHashParameters(combinedHash);
    if (!parsed) {
      return false;
    }

    const derivedKey = (await scryptLimiter.run(() =>
      scryptAsync(password, parsed.salt, 64, parsed.options)
    )) as Buffer;

    const derivedHashBuf = Buffer.from(derivedKey.toString('hex'), 'utf8');
    const originalHashBuf = Buffer.from(parsed.originalHashHex, 'utf8');

    if (derivedHashBuf.length !== originalHashBuf.length) {
      return false;
    }

    return crypto.timingSafeEqual(derivedHashBuf, originalHashBuf);
  } catch {
    return false;
  }
}

/**
 * Synchronous password verification helper for synchronous contexts and tests.
 */
export function verifyPasswordSync(password: string, combinedHash: string): boolean {
  if (!password || typeof password !== 'string' || password.length > 128) {
    return false;
  }
  if (!combinedHash || typeof combinedHash !== 'string') {
    return false;
  }

  try {
    const parsed = parseHashParameters(combinedHash);
    if (!parsed) {
      return false;
    }

    const derivedKey = crypto.scryptSync(password, parsed.salt, 64, parsed.options);
    const derivedHashBuf = Buffer.from(derivedKey.toString('hex'), 'utf8');
    const originalHashBuf = Buffer.from(parsed.originalHashHex, 'utf8');

    if (derivedHashBuf.length !== originalHashBuf.length) return false;

    return crypto.timingSafeEqual(derivedHashBuf, originalHashBuf);
  } catch {
    return false;
  }
}

/**
 * Executes a constant-time dummy password check to prevent timing-based user enumeration.
 */
export async function dummyVerifyPassword(password: string): Promise<void> {
  await verifyPassword(password, DUMMY_HASH);
}

/**
 * Generates a signed HMAC-SHA256 JWT token with an expiration timestamp, roleVersion, and issuer.
 */
export function createToken(
  payload: Omit<TokenPayload, 'iat' | 'exp' | 'iss'>,
  expiresInSeconds: number = 86400 * 7
): string {
  if (!payload.sub || typeof payload.sub !== 'string') {
    throw new Error('User subject ID is required for token issuance.');
  }
  if (!['user', 'analyst', 'admin'].includes(payload.role)) {
    throw new Error('Invalid user role for token issuance.');
  }

  const header = {
    alg: 'HS256',
    typ: 'JWT',
  };

  const now = Math.floor(Date.now() / 1000);
  const fullPayload: TokenPayload = {
    ...payload,
    roleVersion: typeof payload.roleVersion === 'number' ? payload.roleVersion : 1,
    iss: 'sentrix-api',
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
 * Verifies and decodes an HMAC-SHA256 JWT token.
 * Validates algorithm, signature, expiration, required payload structure, and role enum.
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
  if (!headerB64 || !payloadB64 || !signature) {
    throw new Error('Malformed token format: empty segment');
  }

  // 1. Validate Header
  let header: any;
  try {
    header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
  } catch {
    throw new Error('Malformed token header');
  }

  if (header.alg !== 'HS256') {
    throw new Error(`Unsupported token algorithm '${header.alg}'. Only HS256 is permitted.`);
  }

  if (header.typ !== 'JWT') {
    throw new Error(`Unsupported token type '${header.typ}'. Expected JWT.`);
  }

  // 2. Cryptographic Signature Verification
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

  // 3. Validate Payload Structure & Claims
  let payload: any;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    throw new Error('Malformed token payload');
  }

  if (!payload || typeof payload !== 'object') {
    throw new Error('Invalid token payload structure');
  }

  if (!payload.sub || typeof payload.sub !== 'string') {
    throw new Error('Invalid token: missing or non-string subject claim (sub)');
  }

  if (!payload.email || typeof payload.email !== 'string') {
    throw new Error('Invalid token: missing or non-string email claim');
  }

  if (!payload.role || !['user', 'analyst', 'admin'].includes(payload.role)) {
    throw new Error(`Invalid token: unauthorized or unrecognized role claim '${payload.role}'`);
  }

  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) {
    throw new Error('Invalid token: required expiration claim (exp) is missing or invalid');
  }

  const now = Math.floor(Date.now() / 1000);
  if (now > payload.exp) {
    throw new Error('Token has expired');
  }

  if (payload.iss && payload.iss !== 'sentrix-api') {
    throw new Error(`Invalid token issuer: expected 'sentrix-api', got '${payload.iss}'`);
  }

  return {
    sub: payload.sub,
    email: payload.email,
    role: payload.role,
    roleVersion: typeof payload.roleVersion === 'number' ? payload.roleVersion : 1,
    iss: payload.iss,
    iat: payload.iat,
    exp: payload.exp,
  };
}
