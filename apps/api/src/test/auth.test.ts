import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import {
  hashPassword,
  hashPasswordSync,
  verifyPassword,
  verifyPasswordSync,
  createToken,
  verifyToken,
} from '../utils/auth.js';
import { buildServer } from '../server.js';
import { UserModel } from '../models/User.js';
import { authenticate, requireRole } from '../modules/auth/middleware.js';
import { provisionAdminAccount } from '../scripts/createAdmin.js';

describe('SENTRIX User Authentication & RBAC Security Remediation Tests', () => {
  // --------------------------------------------------------------------------
  // 1. Password Hashing, Versioning, and Backward Compatibility
  // --------------------------------------------------------------------------
  it('hashPassword generates versioned scrypt hashes and verifyPassword verifies both modern and legacy formats', async () => {
    const raw = 'SuperSecret123!';
    const modernHash1 = await hashPassword(raw);
    const modernHash2 = await hashPassword(raw);

    // Ensure distinct salts
    assert.notEqual(modernHash1, modernHash2);
    // Versioned format verification
    assert.ok(modernHash1.startsWith('scrypt$v=1$n=16384,r=8,p=1$'));

    // Verify correct password on modern versioned hash
    assert.equal(await verifyPassword(raw, modernHash1), true);
    assert.equal(await verifyPassword(raw, modernHash2), true);
    assert.equal(verifyPasswordSync(raw, modernHash1), true);

    // Verify incorrect password on modern hash
    assert.equal(await verifyPassword('WrongPassword!', modernHash1), false);
    assert.equal(await verifyPassword('', modernHash1), false);
    assert.equal(await verifyPassword(raw, 'malformed'), false);
    assert.equal(await verifyPassword(raw, ''), false);

    // Backward compatibility: verify legacy <saltHex>:<hashHex> format
    const legacySalt = '0123456789abcdef0123456789abcdef';
    const legacyHash = hashPasswordSync('LegacyPassword123!');
    assert.equal(await verifyPassword('LegacyPassword123!', legacyHash), true);

    // Password length bounds: reject passwords exceeding 128 chars to prevent scrypt DoS
    const longPassword = 'A'.repeat(129);
    await assert.rejects(async () => hashPassword(longPassword), /exceed 128 characters/);
    assert.equal(await verifyPassword(longPassword, modernHash1), false);
  });

  // --------------------------------------------------------------------------
  // 2. JWT Cryptographic Lifecycle, Algorithm & Claims Validation
  // --------------------------------------------------------------------------
  it('createToken and verifyToken enforce algorithm, signature, role, and expiration validity', () => {
    const payload = {
      sub: 'user123',
      email: 'analyst@sentrix.local',
      role: 'analyst' as const,
      roleVersion: 1,
    };

    const token = createToken(payload, 3600);
    const verified = verifyToken(token);

    assert.equal(verified.sub, 'user123');
    assert.equal(verified.email, 'analyst@sentrix.local');
    assert.equal(verified.role, 'analyst');
    assert.equal(verified.roleVersion, 1);
    assert.equal(verified.iss, 'sentrix-api');
    assert.ok(verified.exp && verified.exp > verified.iat!);

    // Scenario: Expired JWT is rejected
    const expiredToken = createToken(payload, -10);
    assert.throws(() => verifyToken(expiredToken), /Token has expired/);

    // Scenario: Invalid signature is rejected
    const parts = token.split('.');
    const tamperedPayloadB64 = Buffer.from(
      JSON.stringify({ ...verified, role: 'admin' })
    ).toString('base64url');
    const tamperedToken = `${parts[0]}.${tamperedPayloadB64}.${parts[2]}`;
    assert.throws(() => verifyToken(tamperedToken), /Invalid token signature/);

    // Scenario: Malformed token payload is rejected
    assert.throws(() => verifyToken('not.a.valid.jwt'), /Malformed token format/);
    assert.throws(() => verifyToken('invalid-single-string'), /Malformed token format/);

    // Scenario: Algorithm confusion / non-HS256 rejected
    const noneHeaderB64 = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const noneToken = `${noneHeaderB64}.${parts[1]}.${parts[2]}`;
    assert.throws(() => verifyToken(noneToken), /Unsupported token algorithm 'none'/);

    // Scenario: Invalid role claims rejected
    const invalidRolePayload = { ...verified, role: 'superadmin' as any };
    const invalidRoleToken = `${parts[0]}.${Buffer.from(JSON.stringify(invalidRolePayload)).toString('base64url')}`;
    const invalidSig = createToken(payload).split('.')[2];
    assert.throws(() => verifyToken(`${invalidRoleToken}.${invalidSig}`), /Invalid token signature/);
  });

  // --------------------------------------------------------------------------
  // 3. Public Registration Privilege Escalation Immunity
  // --------------------------------------------------------------------------
  it('Public registration strictly creates role user and ignores client-supplied roles or mass assignment', async () => {
    const app = buildServer();
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
        select: () => ({ then: (resolve: any) => exec().then(resolve) }),
        then: (resolve: any) => exec().then(resolve),
      };
    };

    (UserModel as any).create = async (doc: any) => {
      const id = new mongoose.Types.ObjectId();
      const user = {
        _id: id,
        email: doc.email,
        passwordHash: doc.passwordHash,
        role: doc.role,
        roleVersion: doc.roleVersion || 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockUsers.set(doc.email, user);
      return user;
    };

    (UserModel as any).findById = (id: any) => {
      const exec = async () => {
        for (const u of mockUsers.values()) {
          if (u._id.toString() === id.toString()) return { ...u };
        }
        return null;
      };
      return {
        select: () => ({
          lean: exec,
          then: (resolve: any) => exec().then(resolve),
        }),
        lean: exec,
        then: (resolve: any) => exec().then(resolve),
      };
    };

    try {
      // 1. Registration without role creates regular user
      const res1 = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'standard@sentrix.io',
          password: 'Password123!',
        },
      });
      assert.equal(res1.statusCode, 201);
      const body1 = JSON.parse(res1.body);
      assert.equal(body1.user.role, 'user');
      const tokenPayload1 = verifyToken(body1.token);
      assert.equal(tokenPayload1.role, 'user');

      // 2. Registration with role: admin CANNOT create an administrator
      const resAdminAttempt = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'attacker1@sentrix.io',
          password: 'Password123!',
          role: 'admin',
        },
      });
      assert.equal(resAdminAttempt.statusCode, 201);
      const bodyAdmin = JSON.parse(resAdminAttempt.body);
      // Invariant: Stored user and issued token must be 'user', NEVER 'admin'
      assert.equal(bodyAdmin.user.role, 'user');
      const tokenPayloadAdmin = verifyToken(bodyAdmin.token);
      assert.equal(tokenPayloadAdmin.role, 'user');
      assert.equal(mockUsers.get('attacker1@sentrix.io').role, 'user');

      // 3. Registration with role: analyst CANNOT create an analyst
      const resAnalystAttempt = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'attacker2@sentrix.io',
          password: 'Password123!',
          role: 'analyst',
        },
      });
      assert.equal(resAnalystAttempt.statusCode, 201);
      const bodyAnalyst = JSON.parse(resAnalystAttempt.body);
      assert.equal(bodyAnalyst.user.role, 'user');
      assert.equal(mockUsers.get('attacker2@sentrix.io').role, 'user');

      // 4. Unknown privilege-related properties cannot modify stored user (mass-assignment immunity)
      const resMassAssign = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'attacker3@sentrix.io',
          password: 'Password123!',
          role: 'admin',
          isAdmin: true,
          isSuperuser: true,
          permissions: ['ALL'],
          roleVersion: 999,
        },
      });
      assert.equal(resMassAssign.statusCode, 201);
      const storedAttacker3 = mockUsers.get('attacker3@sentrix.io');
      assert.equal(storedAttacker3.role, 'user');
      assert.equal(storedAttacker3.roleVersion, 1);
      assert.equal((storedAttacker3 as any).isAdmin, undefined);
      assert.equal((storedAttacker3 as any).isSuperuser, undefined);
    } finally {
      (UserModel as any).findOne = origFindOne;
      (UserModel as any).create = origCreate;
      (UserModel as any).findById = origFindById;
      await app.close();
    }
  });

  // --------------------------------------------------------------------------
  // 4. Privileged Account Provisioning (CLI & Authorized Admin API)
  // --------------------------------------------------------------------------
  it('Privileged account provisioning works idempotently and prevents accidental last admin demotion', async () => {
    const app = buildServer();
    const mockUsers = new Map<string, any>();

    const origFindOne = UserModel.findOne;
    const origCreate = UserModel.create;
    const origFindById = UserModel.findById;
    const origCountDocuments = UserModel.countDocuments;
    const origFindOneAndUpdate = UserModel.findOneAndUpdate;

    (UserModel as any).findOneAndUpdate = async (filter: any, update: any) => {
      let target: any = null;
      for (const u of mockUsers.values()) {
        const idMatches = filter._id ? u._id.toString() === filter._id.toString() : true;
        const roleMatches = filter.role ? u.role === filter.role : true;
        if (idMatches && roleMatches) {
          target = u;
          break;
        }
      }
      if (!target) return null;
      if (update.$set) {
        Object.assign(target, update.$set);
      }
      if (update.$inc) {
        for (const [k, v] of Object.entries(update.$inc)) {
          target[k] = (target[k] || 0) + (v as number);
        }
      }
      mockUsers.set(target.email, target);
      return target;
    };

    (UserModel as any).findOne = (query: any) => {
      const exec = async () => {
        if (query.email) {
          const u = mockUsers.get(query.email);
          return u ? { ...u, save: async function() { mockUsers.set(this.email, this); } } : null;
        }
        return null;
      };
      return {
        lean: exec,
        select: () => ({ then: (resolve: any) => exec().then(resolve) }),
        then: (resolve: any) => exec().then(resolve),
      };
    };

    (UserModel as any).create = async (doc: any) => {
      const id = new mongoose.Types.ObjectId();
      const user = {
        _id: id,
        email: doc.email,
        passwordHash: doc.passwordHash,
        role: doc.role,
        roleVersion: doc.roleVersion || 1,
        createdAt: new Date(),
        updatedAt: new Date(),
        save: async function() { mockUsers.set(this.email, this); },
      };
      mockUsers.set(doc.email, user);
      return user;
    };

    (UserModel as any).findById = (id: any) => {
      const exec = async () => {
        for (const u of mockUsers.values()) {
          if (u._id.toString() === id.toString()) {
            return {
              ...u,
              save: async function() { mockUsers.set(this.email, this); },
            };
          }
        }
        return null;
      };
      return {
        select: () => ({
          lean: exec,
          then: (resolve: any) => exec().then(resolve),
        }),
        lean: exec,
        then: (resolve: any) => exec().then(resolve),
      };
    };

    (UserModel as any).countDocuments = async (query: any) => {
      let count = 0;
      for (const u of mockUsers.values()) {
        if (!query.role || u.role === query.role) count++;
      }
      return count;
    };

    try {
      // 1. Initial admin provisioning via operator script
      const provResult = await provisionAdminAccount({
        email: 'admin@sentrix.io',
        password: 'ValidSecureAdminPassword123!',
      });
      assert.equal(provResult.success, true);
      const adminUser = mockUsers.get('admin@sentrix.io');
      assert.equal(adminUser.role, 'admin');

      // 2. Idempotent check: provisioning again without force reports existing account intact
      const idempotentResult = await provisionAdminAccount({
        email: 'admin@sentrix.io',
        password: 'ValidSecureAdminPassword123!',
      });
      assert.equal(idempotentResult.success, true);
      assert.ok(idempotentResult.message.includes('already exists'));

      // 3. Regular user attempting to access PATCH /users/:id/role is rejected (403 Forbidden)
      const userDoc = await (UserModel as any).create({
        email: 'regular@sentrix.io',
        passwordHash: 'hash',
        role: 'user',
        roleVersion: 1,
      });

      const userToken = createToken({ sub: userDoc._id.toString(), email: userDoc.email, role: 'user', roleVersion: 1 });
      const adminToken = createToken({ sub: adminUser._id.toString(), email: adminUser.email, role: 'admin', roleVersion: 1 });

      const unauthPatch = await app.inject({
        method: 'PATCH',
        url: `/api/v1/auth/users/${userDoc._id.toString()}/role`,
        headers: { authorization: `Bearer ${userToken}` },
        payload: { role: 'analyst' },
      });
      assert.equal(unauthPatch.statusCode, 403);

      // 4. Authorized admin promoting regular user to analyst
      const authPatch = await app.inject({
        method: 'PATCH',
        url: `/api/v1/auth/users/${userDoc._id.toString()}/role`,
        headers: { authorization: `Bearer ${adminToken}` },
        payload: { role: 'analyst' },
      });
      assert.equal(authPatch.statusCode, 200);
      const promotedUser = mockUsers.get('regular@sentrix.io');
      assert.equal(promotedUser.role, 'analyst');
      assert.equal(promotedUser.roleVersion, 2); // roleVersion incremented

      // 5. Demoting sole remaining administrator is blocked (Safety invariant)
      const demoteAdminRes = await app.inject({
        method: 'PATCH',
        url: `/api/v1/auth/users/${adminUser._id.toString()}/role`,
        headers: { authorization: `Bearer ${adminToken}` },
        payload: { role: 'user' },
      });
      assert.equal(demoteAdminRes.statusCode, 400);
      assert.ok(JSON.parse(demoteAdminRes.body).message.includes('last remaining administrator'));
    } finally {
      (UserModel as any).findOne = origFindOne;
      (UserModel as any).create = origCreate;
      (UserModel as any).findById = origFindById;
      (UserModel as any).countDocuments = origCountDocuments;
      (UserModel as any).findOneAndUpdate = origFindOneAndUpdate;
      await app.close();
    }
  });

  // --------------------------------------------------------------------------
  // 5. Role Revocation Enforcement via roleVersion
  // --------------------------------------------------------------------------
  it('Role revocation is instantaneously enforced when roleVersion or role in DB changes', async () => {
    const app = buildServer();
    const mockUsers = new Map<string, any>();

    const origFindById = UserModel.findById;

    (UserModel as any).findById = (id: any) => {
      const exec = async () => {
        const u = mockUsers.get(id.toString());
        return u ? { ...u } : null;
      };
      return {
        select: () => ({
          lean: exec,
          then: (resolve: any) => exec().then(resolve),
        }),
        lean: exec,
        then: (resolve: any) => exec().then(resolve),
      };
    };

    // Protected route requiring admin role
    app.get(
      '/admin-dashboard',
      { preHandler: [authenticate, requireRole(['admin'])] },
      async () => ({ status: 'privileged-data-accessed' })
    );

    try {
      const adminId = new mongoose.Types.ObjectId().toString();

      // Active admin in DB with roleVersion 1
      mockUsers.set(adminId, {
        _id: adminId,
        email: 'revokeme@sentrix.io',
        role: 'admin',
        roleVersion: 1,
      });

      // Token issued under roleVersion 1
      const activeAdminToken = createToken({
        sub: adminId,
        email: 'revokeme@sentrix.io',
        role: 'admin',
        roleVersion: 1,
      });

      // 1. Initial request succeeds
      const resSuccess = await app.inject({
        method: 'GET',
        url: '/admin-dashboard',
        headers: { authorization: `Bearer ${activeAdminToken}` },
      });
      assert.equal(resSuccess.statusCode, 200);

      // 2. User is demoted to 'user' and roleVersion is bumped to 2
      mockUsers.set(adminId, {
        _id: adminId,
        email: 'revokeme@sentrix.io',
        role: 'user',
        roleVersion: 2,
      });

      // 3. Stale token with roleVersion 1 is immediately rejected (401 Unauthorized)
      const resRevoked = await app.inject({
        method: 'GET',
        url: '/admin-dashboard',
        headers: { authorization: `Bearer ${activeAdminToken}` },
      });
      assert.equal(resRevoked.statusCode, 401);
      assert.ok(JSON.parse(resRevoked.body).message.includes('revoked'));
    } finally {
      (UserModel as any).findById = origFindById;
      await app.close();
    }
  });

  // --------------------------------------------------------------------------
  // 6. Login Protection & Rate Limiting
  // --------------------------------------------------------------------------
  it('Login provides generic error messages and enforces rate limiting', async () => {
    const app = buildServer();
    const mockUsers = new Map<string, any>();

    const origFindOne = UserModel.findOne;

    (UserModel as any).findOne = (query: any) => {
      const exec = async () => {
        if (query.email) {
          const u = mockUsers.get(query.email);
          return u ? { ...u } : null;
        }
        return null;
      };
      return {
        select: () => ({
          then: (resolve: any) => exec().then(resolve),
        }),
        then: (resolve: any) => exec().then(resolve),
      };
    };

    try {
      const testEmail = 'victim@sentrix.io';
      const realPassword = 'CorrectPassword123!';
      const hash = await hashPassword(realPassword);

      mockUsers.set(testEmail, {
        _id: new mongoose.Types.ObjectId(),
        email: testEmail,
        passwordHash: hash,
        role: 'user',
        roleVersion: 1,
      });

      // 1. Non-existent user gets generic 401 error
      const notFoundRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: 'nonexistent@sentrix.io', password: 'SomePassword123!' },
      });
      assert.equal(notFoundRes.statusCode, 401);
      assert.equal(JSON.parse(notFoundRes.body).message, 'Invalid email address or password.');

      // 2. Existing user with bad password gets identical generic 401 error
      const badPasswordRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: testEmail, password: 'WrongPassword123!' },
      });
      assert.equal(badPasswordRes.statusCode, 401);
      assert.equal(JSON.parse(badPasswordRes.body).message, 'Invalid email address or password.');

      // 3. Login with correct password succeeds
      const goodLoginRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: testEmail, password: realPassword },
      });
      assert.equal(goodLoginRes.statusCode, 200);
      assert.ok(JSON.parse(goodLoginRes.body).token);

      // 4. Login rate limiting: rapid attempts exceeding threshold trigger 429
      const clientIp = '198.51.100.42';
      let hit429 = false;

      for (let i = 0; i < 15; i++) {
        const rateRes = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/login',
          headers: { 'x-forwarded-for': clientIp },
          payload: { email: testEmail, password: 'WrongPassword!' },
        });

        if (rateRes.statusCode === 429) {
          hit429 = true;
          break;
        }
      }
      assert.equal(hit429, true, 'Login route must enforce rate limiting (HTTP 429)');
    } finally {
      (UserModel as any).findOne = origFindOne;
      await app.close();
    }
  });
});
