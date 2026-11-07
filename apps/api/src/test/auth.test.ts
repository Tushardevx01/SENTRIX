import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { hashPassword, verifyPassword, createToken, verifyToken } from '../utils/auth.js';
import { buildServer } from '../server.js';
import { UserModel } from '../models/User.js';
import { authenticate, requireRole } from '../modules/auth/middleware.js';

describe('SENTRIX User Authentication & RBAC Tests', () => {
  // --------------------------------------------------------------------------
  // Password Hashing & Constant-Time Verification
  // --------------------------------------------------------------------------
  it('hashPassword generates distinct salts and verifyPassword verifies correctly', () => {
    const raw = 'SuperSecret123!';
    const hash1 = hashPassword(raw);
    const hash2 = hashPassword(raw);

    // Ensure distinct salts
    assert.notEqual(hash1, hash2);
    assert.equal(hash1.includes(':'), true);

    // Verify correct password
    assert.equal(verifyPassword(raw, hash1), true);
    assert.equal(verifyPassword(raw, hash2), true);

    // Verify incorrect password
    assert.equal(verifyPassword('WrongPassword!', hash1), false);
    assert.equal(verifyPassword('', hash1), false);
    assert.equal(verifyPassword(raw, 'malformed'), false);
    assert.equal(verifyPassword(raw, ''), false);
  });

  // --------------------------------------------------------------------------
  // HMAC-SHA256 JWT Token Lifecycle
  // --------------------------------------------------------------------------
  it('createToken and verifyToken enforce cryptographic integrity and expiration', () => {
    const payload = {
      sub: 'user123',
      email: 'analyst@sentrix.local',
      role: 'analyst' as const,
    };

    const token = createToken(payload, 3600);
    const verified = verifyToken(token);

    assert.equal(verified.sub, 'user123');
    assert.equal(verified.email, 'analyst@sentrix.local');
    assert.equal(verified.role, 'analyst');
    assert.ok(verified.exp && verified.exp > verified.iat!);

    // Tampered payload
    const parts = token.split('.');
    const tamperedPayloadB64 = Buffer.from(
      JSON.stringify({ ...verified, role: 'admin' })
    ).toString('base64url');
    const tamperedToken = `${parts[0]}.${tamperedPayloadB64}.${parts[2]}`;

    assert.throws(() => verifyToken(tamperedToken), /Invalid token signature/);

    // Expired token
    const expiredToken = createToken(payload, -10); // Expired 10 seconds ago
    assert.throws(() => verifyToken(expiredToken), /Token has expired/);
  });

  // --------------------------------------------------------------------------
  // Auth API Endpoints (Register, Login, Me)
  // --------------------------------------------------------------------------
  it('POST /api/v1/auth/register and /login flow', async () => {
    const app = buildServer();

    // Mock in-memory user storage for isolated execution
    const mockUsers = new Map<string, any>();

    const origFindOne = UserModel.findOne;
    const origCreate = UserModel.create;
    const origFindById = UserModel.findById;

    (UserModel as any).findOne = (query: any) => {
      const exec = async () => {
        if (query.email) {
          const u = mockUsers.get(query.email);
          return u ? { ...u } : null;
        }
        return null;
      };
      return {
        lean: exec,
        select: (sel: string) => ({
          then: (resolve: any) => exec().then(resolve),
        }),
        then: (resolve: any) => exec().then(resolve),
      };
    };

    (UserModel as any).create = async (doc: any) => {
      const id = new mongoose.Types.ObjectId();
      const user = {
        _id: id,
        email: doc.email,
        passwordHash: doc.passwordHash,
        role: doc.role || 'user',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockUsers.set(doc.email, user);
      return user;
    };

    (UserModel as any).findById = (id: any) => {
      const exec = async () => {
        for (const u of mockUsers.values()) {
          if (u._id.toString() === id.toString()) {
            return { ...u };
          }
        }
        return null;
      };
      return {
        lean: exec,
        then: (resolve: any) => exec().then(resolve),
      };
    };

    try {
      // 1. Register valid user
      const regRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'analyst@sentrix.io',
          password: 'Password123!',
          role: 'analyst',
        },
      });

      assert.equal(regRes.statusCode, 201);
      const regBody = JSON.parse(regRes.body);
      assert.ok(regBody.token);
      assert.equal(regBody.user.email, 'analyst@sentrix.io');
      assert.equal(regBody.user.role, 'analyst');

      const userToken = regBody.token;

      // 2. Reject duplicate email
      const dupRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'analyst@sentrix.io',
          password: 'Password123!',
        },
      });
      assert.equal(dupRes.statusCode, 409);

      // 3. Login with correct credentials
      const loginRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: {
          email: 'analyst@sentrix.io',
          password: 'Password123!',
        },
      });
      assert.equal(loginRes.statusCode, 200);
      const loginBody = JSON.parse(loginRes.body);
      assert.ok(loginBody.token);

      // 4. Login with incorrect password
      const badLoginRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: {
          email: 'analyst@sentrix.io',
          password: 'WrongPassword!',
        },
      });
      assert.equal(badLoginRes.statusCode, 401);

      // 5. GET /me with valid Bearer token
      const meRes = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: {
          authorization: `Bearer ${userToken}`,
        },
      });
      assert.equal(meRes.statusCode, 200);
      const meBody = JSON.parse(meRes.body);
      assert.equal(meBody.user.email, 'analyst@sentrix.io');

      // 6. GET /me without token returns 401
      const noAuthRes = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
      });
      assert.equal(noAuthRes.statusCode, 401);
    } finally {
      (UserModel as any).findOne = origFindOne;
      (UserModel as any).create = origCreate;
      (UserModel as any).findById = origFindById;
      await app.close();
    }
  });

  // --------------------------------------------------------------------------
  // Role-Based Access Control (RBAC) Guard Enforcement
  // --------------------------------------------------------------------------
  it('requireRole guard strictly enforces role authorizations', async () => {
    const app = buildServer();

    // Register protected test routes
    app.get(
      '/admin-only',
      { preHandler: [authenticate, requireRole(['admin'])] },
      async () => ({ status: 'admin-granted' })
    );

    app.get(
      '/analyst-or-admin',
      { preHandler: [authenticate, requireRole(['analyst', 'admin'])] },
      async () => ({ status: 'staff-granted' })
    );

    try {
      const userToken = createToken({ sub: 'u1', email: 'user@test.io', role: 'user' });
      const analystToken = createToken({ sub: 'u2', email: 'analyst@test.io', role: 'analyst' });
      const adminToken = createToken({ sub: 'u3', email: 'admin@test.io', role: 'admin' });

      // User trying admin-only route -> 403 Forbidden
      const resUserOnAdmin = await app.inject({
        method: 'GET',
        url: '/admin-only',
        headers: { authorization: `Bearer ${userToken}` },
      });
      assert.equal(resUserOnAdmin.statusCode, 403);
      assert.equal(JSON.parse(resUserOnAdmin.body).error, 'FORBIDDEN');

      // Analyst trying admin-only route -> 403 Forbidden
      const resAnalystOnAdmin = await app.inject({
        method: 'GET',
        url: '/admin-only',
        headers: { authorization: `Bearer ${analystToken}` },
      });
      assert.equal(resAnalystOnAdmin.statusCode, 403);

      // Admin trying admin-only route -> 200 OK
      const resAdminOnAdmin = await app.inject({
        method: 'GET',
        url: '/admin-only',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      assert.equal(resAdminOnAdmin.statusCode, 200);

      // Analyst on analyst-or-admin -> 200 OK
      const resAnalystOnBoth = await app.inject({
        method: 'GET',
        url: '/analyst-or-admin',
        headers: { authorization: `Bearer ${analystToken}` },
      });
      assert.equal(resAnalystOnBoth.statusCode, 200);
    } finally {
      await app.close();
    }
  });
});

