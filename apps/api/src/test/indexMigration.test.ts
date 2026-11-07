import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import {
  IndexMigrationManager,
  REQUIRED_INDEXES,
  MIGRATION_ID_PHASE4,
} from '../migrations/indexMigration.js';

function getTestDbUri(dbName: string): string {
  if (process.env.TEST_MONGODB_URI) {
    try {
      const parsed = new URL(process.env.TEST_MONGODB_URI);
      parsed.pathname = `/${dbName}`;
      return parsed.toString();
    } catch {
      return process.env.TEST_MONGODB_URI;
    }
  }
  return `mongodb://127.0.0.1:27017/${dbName}`;
}

const TEST_MONGO_URI = getTestDbUri('sentrix_test_migration');

describe('SENTRIX Controlled Index Migration Tests', () => {
  let isConnected = false;
  let connection: mongoose.Connection;
  let manager: IndexMigrationManager;

  before(async () => {
    try {
      mongoose.set('strictQuery', true);
      connection = mongoose.createConnection(TEST_MONGO_URI, {
        serverSelectionTimeoutMS: 3000,
        autoIndex: false,
      });
      await connection.asPromise();
      isConnected = true;
      manager = new IndexMigrationManager(connection);
    } catch (err: any) {
      console.warn('Real MongoDB not available, skipping index migration tests:', err.message);
    }
  });

  after(async () => {
    if (isConnected && connection) {
      const db = connection.db;
      if (db) {
        try {
          await db.dropDatabase();
        } catch {
          // ignore cleanup error
        }
      }
      await connection.close();
    }
  });

  // --------------------------------------------------------------------------
  // Test 1: Fresh database migration creates all required indexes
  // --------------------------------------------------------------------------
  it('Test 1: Fresh database migration creates all required indexes', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const db = connection.db!;
    await db.dropDatabase();

    const result = await manager.applyMigrations({ force: true });
    assert.equal(result.success, true);
    assert.equal(result.errors.length, 0);
    assert.ok(result.createdIndexes.length >= REQUIRED_INDEXES.length);

    // Verify scans indexes
    const scanIndexes = await db.collection('scans').indexes();
    const scanNames = scanIndexes.map((i) => i.name);
    assert.ok(scanNames.includes('status_1_createdAt_1'));
    assert.ok(scanNames.includes('status_1_claimedAt_1'));
    assert.ok(scanNames.includes('urlHash_1_partial_active'));
    assert.ok(scanNames.includes('publishedLeaseToken_1'));

    // Verify findings indexes
    const findingIndexes = await db.collection('findings').indexes();
    const findingNames = findingIndexes.map((i) => i.name);
    assert.ok(findingNames.includes('scanId_1_leaseToken_1'));
    assert.ok(findingNames.includes('scanId_1_severity_1'));

    // Verify certificates indexes
    const certIndexes = await db.collection('certificates').indexes();
    const certNames = certIndexes.map((i) => i.name);
    assert.ok(certNames.includes('scanId_1_leaseToken_1'));
    assert.ok(certNames.includes('fingerprint_1'));

    // Verify users unique email index
    const userIndexes = await db.collection('users').indexes();
    const userNames = userIndexes.map((i) => i.name);
    assert.ok(userNames.includes('email_1'));
  });

  // --------------------------------------------------------------------------
  // Test 2: Existing correct indexes remain unchanged
  // --------------------------------------------------------------------------
  it('Test 2: Existing correct indexes remain unchanged', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    // Planning on an already-migrated database should detect existing indexes
    const plan = await manager.planMigrations();
    assert.equal(plan.plannedCreations.length, 0);
    assert.equal(plan.plannedDrops.length, 0);
    assert.equal(plan.existingValid.length, REQUIRED_INDEXES.length);

    // Applying again without force should return cleanly as already completed
    const secondResult = await manager.applyMigrations();
    assert.equal(secondResult.success, true);
    assert.equal(secondResult.createdIndexes.length, 0);
    assert.equal(secondResult.droppedIndexes.length, 0);
    assert.ok(secondResult.preservedIndexes.length > 0);
  });

  // --------------------------------------------------------------------------
  // Test 3: Obsolete indexes are identified in migration plan
  // --------------------------------------------------------------------------
  it('Test 3: Obsolete indexes are identified in migration plan', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const db = connection.db!;
    // Drop existing non-unique index if present, then create obsolete unique index on certificates { scanId: 1 }
    await db.collection('certificates').dropIndex('scanId_1').catch(() => {});
    await db.collection('certificates').createIndex({ scanId: 1 }, { name: 'scanId_1', unique: true });

    const plan = await manager.planMigrations();
    const obsoleteDrop = plan.plannedDrops.find(
      (d) => d.collection === 'certificates' && d.name === 'scanId_1'
    );

    assert.ok(obsoleteDrop !== undefined);
    assert.ok(obsoleteDrop.reason.includes('Legacy unique index'));
  });

  // --------------------------------------------------------------------------
  // Test 4: Dry-run performs no destructive operations
  // --------------------------------------------------------------------------
  it('Test 4: Dry-run performs no destructive operations', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const db = connection.db!;
    const migrationsColl = db.collection<{ _id: string; [key: string]: any }>('_schema_migrations');
    await migrationsColl.deleteMany({});

    // Run dry-run migration
    const dryRunResult = await manager.applyMigrations({ dryRun: true });

    assert.equal(dryRunResult.dryRun, true);
    assert.equal(dryRunResult.success, true);
    assert.ok(dryRunResult.droppedIndexes.includes('certificates.scanId_1'));

    // Verify the obsolete index was NOT dropped in reality
    const certIndexes = await db.collection('certificates').indexes();
    const obsoleteStillExists = certIndexes.some((i) => i.name === 'scanId_1');
    assert.equal(obsoleteStillExists, true, 'Obsolete index must still exist after dry-run');

    // Verify migration history is not updated during dry-run
    const history = await migrationsColl.findOne({ _id: MIGRATION_ID_PHASE4 });
    assert.equal(history, null, 'Dry run must not create migration history entries');
  });

  // --------------------------------------------------------------------------
  // Test 5: Explicit migration removes an obsolete index safely
  // --------------------------------------------------------------------------
  it('Test 5: Explicit migration removes an obsolete index safely (certificates.scanId_1 unique dropped)', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const db = connection.db!;
    // Run migration with force to apply drops
    const result = await manager.applyMigrations({ force: true });

    assert.equal(result.success, true);
    assert.ok(result.droppedIndexes.includes('certificates.scanId_1'));

    // Verify the obsolete index was dropped
    const certIndexes = await db.collection('certificates').indexes();
    const obsoleteExists = certIndexes.some((i) => i.name === 'scanId_1' && i.unique);
    assert.equal(obsoleteExists, false, 'Obsolete unique scanId_1 index must be dropped');

    // Immutable safeguard check: _id_ was NEVER dropped
    const hasIdIndex = certIndexes.some((i) => i.name === '_id_');
    assert.equal(hasIdIndex, true, 'Immutable _id_ index must never be dropped');
  });

  // --------------------------------------------------------------------------
  // Test 6: Unique-index creation handles duplicate existing records safely
  // --------------------------------------------------------------------------
  it('Test 6: Unique-index creation handles duplicate existing records safely', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const db = connection.db!;
    // Drop the partial unique index to simulate legacy state
    try {
      await db.collection('scans').dropIndex('urlHash_1_partial_active');
    } catch {
      // ignore
    }

    // Insert duplicate active scans with the same urlHash
    const duplicateHash = 'duplicate-active-hash-1234';
    const oldScanId = new mongoose.Types.ObjectId();
    const newScanId = new mongoose.Types.ObjectId();

    await db.collection('scans').insertMany([
      {
        _id: oldScanId,
        submittedUrl: 'https://dup1.test.com',
        urlHash: duplicateHash,
        status: 'QUEUED',
        createdAt: new Date(Date.now() - 60_000),
      },
      {
        _id: newScanId,
        submittedUrl: 'https://dup1.test.com',
        urlHash: duplicateHash,
        status: 'QUEUED',
        createdAt: new Date(),
      },
    ]);

    // Apply migration: pre-flight resolver should handle duplicate scans and build index
    const result = await manager.applyMigrations({ force: true });
    assert.equal(result.success, true);

    // Verify the partial unique index exists
    const scanIndexes = await db.collection('scans').indexes();
    const hasPartialActive = scanIndexes.some((i) => i.name === 'urlHash_1_partial_active');
    assert.equal(hasPartialActive, true, 'urlHash_1_partial_active index must be created');

    // Verify the older duplicate was marked FAILED, and the newer scan kept
    const oldScan = await db.collection('scans').findOne({ _id: oldScanId });
    const newScan = await db.collection('scans').findOne({ _id: newScanId });
    assert.equal(oldScan?.status, 'FAILED');
    assert.equal(newScan?.status, 'QUEUED');
  });

  // --------------------------------------------------------------------------
  // Test 7: Concurrent migration execution is prevented (lock rejection)
  // --------------------------------------------------------------------------
  it('Test 7: Concurrent migration execution is prevented (lock rejection)', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const db = connection.db!;
    const migrationsColl = db.collection<{ _id: string; [key: string]: any }>('_schema_migrations');
    // Manually acquire lock simulating another running migration process
    await migrationsColl.updateOne(
      { _id: MIGRATION_ID_PHASE4 },
      {
        $set: {
          status: 'IN_PROGRESS',
          lockedAt: new Date(),
          lockHolder: 'another_process_instance_9999',
          updatedAt: new Date(),
        },
      },
      { upsert: true }
    );

    // A second instance attempting to run migration must be rejected
    const secondManager = new IndexMigrationManager(connection);
    await assert.rejects(
      async () => {
        await secondManager.applyMigrations({ force: true });
      },
      (err: any) => {
        return (
          err.message.includes('Concurrent migration execution detected') ||
          err.message.includes('lock already held')
        );
      }
    );
  });

  // --------------------------------------------------------------------------
  // Test 8: Migration failure does not silently mark the migration complete
  // --------------------------------------------------------------------------
  it('Test 8: Migration failure does not silently mark the migration complete', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const db = connection.db!;
    const migrationsColl = db.collection<{ _id: string; [key: string]: any }>('_schema_migrations');
    // Clear lock to allow run
    await migrationsColl.updateOne(
      { _id: MIGRATION_ID_PHASE4 },
      { $set: { status: 'PENDING', lockedAt: null } }
    );

    // Mock createIndex on db.collection('scans') to throw a fatal error
    const originalCollection = db.collection.bind(db);
    (db as any).collection = (name: string) => {
      const coll = originalCollection(name);
      if (name === 'users') {
        return {
          ...coll,
          indexes: coll.indexes.bind(coll),
          createIndex: async () => {
            throw new Error('Fatal Disk I/O or Quota Error during index build');
          },
        };
      }
      return coll;
    };

    const failingManager = new IndexMigrationManager(connection);
    const result = await failingManager.applyMigrations({ force: true });

    // Restore original collection
    (db as any).collection = originalCollection;

    assert.equal(result.success, false);
    assert.ok(result.errors.length > 0);
    assert.ok(result.errors[0].includes('Fatal Disk I/O or Quota Error'));

    // Verify _schema_migrations recorded status FAILED, not COMPLETED
    const history = await migrationsColl.findOne({ _id: MIGRATION_ID_PHASE4 });
    assert.equal(history?.status, 'FAILED');
    assert.ok(history?.lastError.includes('Fatal Disk I/O or Quota Error'));
  });
});
