import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { buildServer } from '../server.js';
import { UserModel } from '../models/User.js';
import { createToken, hashPassword, verifyPassword, scryptLimiter } from '../utils/auth.js';
import { provisionAdminAccount } from '../scripts/createAdmin.js';
import { FastifyInstance } from 'fastify';

const TEST_DB_URI = process.env.TEST_MONGODB_URI || 'mongodb://127.0.0.1:27017/sentrix_test_auth_integration';

describe('SENTRIX Phase 5.2 Real MongoDB 7.0 Authentication & RBAC Integration Tests', () => {
  let app: FastifyInstance;
  let isDbConnected = false;

  before(async () => {
    mongoose.set('strictQuery', true);
    try {
      await mongoose.connect(TEST_DB_URI, {
        serverSelectionTimeoutMS: 2000,
      });
      isDbConnected = true;

      // Clean test database collections
      await UserModel.deleteMany({});
      const db = mongoose.connection.db;
      if (db) {
        try {
          await db.collection('_auth_locks').deleteMany({});
        } catch {
          // collection may not exist yet
        }
      }
    } catch (err: any) {
      console.warn(`Real MongoDB not available at ${TEST_DB_URI}, skipping live integration tests:`, err.message);
    }

    app = buildServer();
    await app.ready();
  });

  after(async () => {
    if (app) {
      await app.close();
    }
    if (isDbConnected) {
      await UserModel.deleteMany({});
      const db = mongoose.connection.db;
      if (db) {
        try {
          await db.collection('_auth_locks').deleteMany({});
        } catch {
          // cleanup
        }
      }
      await mongoose.disconnect();
    }
  });

  // --------------------------------------------------------------------------
  // 1. Concurrent Administrator Demotion Invariant
  // --------------------------------------------------------------------------
  it('Concurrent administrator demotions: guarantees at least one admin remains and failed update preserves roleVersion', async () => {
    if (!isDbConnected) return;
    // Clean and seed exactly two administrator accounts
    await UserModel.deleteMany({});
    const passHash = await hashPassword('AdminPass123!@#');

    const admin1 = await UserModel.create({
      email: 'admin1_concurrency@sentrix.io',
      passwordHash: passHash,
      role: 'admin',
      roleVersion: 1,
    });

    const admin2 = await UserModel.create({
      email: 'admin2_concurrency@sentrix.io',
      passwordHash: passHash,
      role: 'admin',
      roleVersion: 1,
    });

    const tokenAdmin1 = createToken({
      sub: admin1._id.toString(),
      email: admin1.email,
      role: 'admin',
      roleVersion: 1,
    });

    const tokenAdmin2 = createToken({
      sub: admin2._id.toString(),
      email: admin2.email,
      role: 'admin',
      roleVersion: 1,
    });

    // Concurrent demotion requests racing against the last two admins
    const [res1, res2] = await Promise.all([
      app.inject({
        method: 'PATCH',
        url: `/api/v1/auth/users/${admin1._id.toString()}/role`,
        headers: {
          authorization: `Bearer ${tokenAdmin2}`,
        },
        payload: { role: 'user' },
      }),
      app.inject({
        method: 'PATCH',
        url: `/api/v1/auth/users/${admin2._id.toString()}/role`,
        headers: {
          authorization: `Bearer ${tokenAdmin1}`,
        },
        payload: { role: 'user' },
      }),
    ]);

    const statuses = [res1.statusCode, res2.statusCode].sort();
    // Exactly one must succeed (200) and exactly one must fail (400)
    assert.deepEqual(statuses, [200, 400], `Expected exactly one 200 and one 400, got: [${res1.statusCode}, ${res2.statusCode}]`);

    // Verify error message on the failing request
    const failedRes = res1.statusCode === 400 ? res1 : res2;
    const failedJson = JSON.parse(failedRes.body);
    assert.equal(failedJson.error, 'INVALID_OPERATION');
    assert.match(failedJson.message, /Cannot demote the last remaining administrator/);

    // Verify persistent state in MongoDB
    const remainingAdmins = await UserModel.find({ role: 'admin' });
    assert.equal(remainingAdmins.length, 1, 'Invariant violation: System must have exactly 1 active administrator remaining.');

    // Verify that the surviving administrator did NOT have roleVersion incremented
    const survivingAdmin = remainingAdmins[0];
    assert.equal(survivingAdmin.role, 'admin');
    assert.equal(survivingAdmin.roleVersion, 1, 'Failed demotion must not increment roleVersion.');
  });

  // --------------------------------------------------------------------------
  // 2. Concurrent Administrator Provisioning
  // --------------------------------------------------------------------------
  it('Concurrent administrator provisioning handles race conditions idempotently without duplicate key errors', async () => {
    if (!isDbConnected) return;
    const email = 'concurrent_provision@sentrix.io';
    const password = 'StrongPassword123!@#';

    // Run two provisioning operations concurrently for the same email
    const [resA, resB] = await Promise.all([
      provisionAdminAccount({ email, password }),
      provisionAdminAccount({ email, password }),
    ]);

    assert.equal(resA.success, true);
    assert.equal(resB.success, true);

    const admins = await UserModel.find({ email });
    assert.equal(admins.length, 1);
    assert.equal(admins[0].role, 'admin');
  });

  // --------------------------------------------------------------------------
  // 3. Real MongoDB Role Revocation & Immediate Invalidation
  // --------------------------------------------------------------------------
  it('Role revocation: modifying user role in MongoDB immediately revokes active JWT on protected endpoints', async () => {
    if (!isDbConnected) return;
    const passHash = await hashPassword('AnalystPass123!');
    const analyst = await UserModel.create({
      email: 'analyst_revocation@sentrix.io',
      passwordHash: passHash,
      role: 'analyst',
      roleVersion: 1,
    });

    const rootAdmin = await UserModel.findOne({ role: 'admin' });
    assert.ok(rootAdmin, 'Expected at least one admin to exist');

    const adminToken = createToken({
      sub: rootAdmin._id.toString(),
      email: rootAdmin.email,
      role: 'admin',
      roleVersion: rootAdmin.roleVersion,
    });

    const analystToken = createToken({
      sub: analyst._id.toString(),
      email: analyst.email,
      role: 'analyst',
      roleVersion: 1,
    });

    // Demote analyst to regular user via admin API
    const patchRes = await app.inject({
      method: 'PATCH',
      url: `/api/v1/auth/users/${analyst._id.toString()}/role`,
      headers: { authorization: `Bearer ${adminToken}` },
      payload: { role: 'user' },
    });
    assert.equal(patchRes.statusCode, 200);

    // Verify user in MongoDB has role 'user' and roleVersion 2
    const updatedAnalyst = await UserModel.findById(analyst._id);
    assert.equal(updatedAnalyst?.role, 'user');
    assert.equal(updatedAnalyst?.roleVersion, 2);

    // Now attempt to access an analyst-required route with the old token
    // The role update endpoint requires 'admin', so let's test attempting to patch with old token
    const oldTokenRes = await app.inject({
      method: 'PATCH',
      url: `/api/v1/auth/users/${rootAdmin._id.toString()}/role`,
      headers: { authorization: `Bearer ${analystToken}` },
      payload: { role: 'user' },
    });

    // Old token must be rejected with 401 unauthorized because role and roleVersion changed in DB
    assert.equal(oldTokenRes.statusCode, 401);
    const body = JSON.parse(oldTokenRes.body);
    assert.equal(body.error, 'UNAUTHORIZED');
    assert.match(body.message, /revoked/i);
  });

  // --------------------------------------------------------------------------
  // 4. User Deletion and Token Invalidation
  // --------------------------------------------------------------------------
  it('User deletion: deleting a user from MongoDB immediately invalidates their active token', async () => {
    if (!isDbConnected) return;
    const passHash = await hashPassword('DeleteMe123!@#');
    const user = await UserModel.create({
      email: 'deleted_user@sentrix.io',
      passwordHash: passHash,
      role: 'admin',
      roleVersion: 1,
    });

    const userToken = createToken({
      sub: user._id.toString(),
      email: user.email,
      role: 'admin',
      roleVersion: 1,
    });

    // Delete user directly from database
    await UserModel.deleteOne({ _id: user._id });

    // Attempt protected request with valid signature and unexpired token
    const res = await app.inject({
      method: 'PATCH',
      url: `/api/v1/auth/users/${user._id.toString()}/role`,
      headers: { authorization: `Bearer ${userToken}` },
      payload: { role: 'user' },
    });

    assert.equal(res.statusCode, 401);
    const body = JSON.parse(res.body);
    assert.equal(body.error, 'UNAUTHORIZED');
    assert.match(body.message, /no longer exists/i);
  });

  // --------------------------------------------------------------------------
  // 5. Public Registration Mass-Assignment & Privilege Escalation Immunity
  // --------------------------------------------------------------------------
  it('Public registration payload attempting role elevation is strictly stored as role user in MongoDB', async () => {
    if (!isDbConnected) return;
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: {
        email: 'malicious_admin_attempt@sentrix.io',
        password: 'Password123!',
        role: 'admin',
        admin: true,
        superuser: true,
      },
    });

    assert.equal(res.statusCode, 201);
    const body = JSON.parse(res.body);
    assert.equal(body.user.role, 'user');

    // Query MongoDB directly to verify persisted document
    const persisted = await UserModel.findOne({ email: 'malicious_admin_attempt@sentrix.io' });
    assert.ok(persisted);
    assert.equal(persisted.role, 'user', 'Persisted document in MongoDB MUST have role user.');
    assert.equal(persisted.roleVersion, 1);
  });

  // --------------------------------------------------------------------------
  // 6. Authentication Concurrency Limits
  // --------------------------------------------------------------------------
  it('Scrypt concurrency limiter bounds parallel execution and handles bursts safely', async () => {
    const initialStats = scryptLimiter.stats;
    assert.equal(initialStats.maxConcurrent, 10);

    // Launch 15 concurrent password verification operations
    const raw = 'ConcurrencyTestPassword123!';
    const hash = await hashPassword(raw);

    const operations = Array.from({ length: 15 }, () => verifyPassword(raw, hash));
    const results = await Promise.all(operations);

    assert.equal(results.length, 15);
    for (const r of results) {
      assert.equal(r, true);
    }

    // After all operations drain, running count must return to 0
    assert.equal(scryptLimiter.stats.running, 0);
    assert.equal(scryptLimiter.stats.queued, 0);
  });

  // --------------------------------------------------------------------------
  // 7. Password Hash Bounds & Malformed Hash Protection
  // --------------------------------------------------------------------------
  it('Password hashing rejects malformed parameters, oversized inputs, and unsupported versions', async () => {
    const validPass = 'ValidPassword123!';
    const validHash = await hashPassword(validPass);

    // 1. Password input length upper bound (> 128 characters)
    const longPassword = 'P'.repeat(129);
    assert.equal(await verifyPassword(longPassword, validHash), false);
    await assert.rejects(async () => hashPassword(longPassword), /exceed 128 characters/);

    // 2. Unsupported version
    const v2Hash = validHash.replace('scrypt$v=1$', 'scrypt$v=2$');
    assert.equal(await verifyPassword(validPass, v2Hash), false);

    // 3. Giant N parameter (memory exhaustion attempt)
    const giantNHash = 'scrypt$v=1$n=1048576,r=8,p=1$0123456789abcdef0123456789abcdef$0000000000000000';
    assert.equal(await verifyPassword(validPass, giantNHash), false);

    // 4. Non-power of 2 N parameter
    const nonPower2Hash = 'scrypt$v=1$n=15000,r=8,p=1$0123456789abcdef0123456789abcdef$0000000000000000';
    assert.equal(await verifyPassword(validPass, nonPower2Hash), false);

    // 5. Corrupted delimiters
    assert.equal(await verifyPassword(validPass, 'scrypt$v=1$n=16384,r=8,p=1'), false);
    assert.equal(await verifyPassword(validPass, 'random_string_not_a_hash'), false);
    assert.equal(await verifyPassword(validPass, ''), false);
  });
});
