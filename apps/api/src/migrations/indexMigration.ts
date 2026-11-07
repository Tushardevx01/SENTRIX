import mongoose, { Connection } from 'mongoose';
import crypto from 'node:crypto';

export interface IIndexSpec {
  collection: string;
  keys: Record<string, 1 | -1 | string>;
  options: {
    name: string;
    unique?: boolean;
    partialFilterExpression?: Record<string, any>;
    sparse?: boolean;
    background?: boolean;
  };
  description: string;
}

export interface IObsoleteIndexSpec {
  collection: string;
  name: string;
  reason: string;
  isObsoleteIf?: (indexDef: any) => boolean;
}

export interface IMigrationPlan {
  migrationId: string;
  dryRun: boolean;
  plannedCreations: Array<{ collection: string; name: string; keys: any; options: any; description: string }>;
  plannedDrops: Array<{ collection: string; name: string; reason: string }>;
  existingValid: Array<{ collection: string; name: string }>;
  duplicatesDetected: Array<{ collection: string; conflict: string; count: number }>;
}

export interface IMigrationResult {
  migrationId: string;
  dryRun: boolean;
  success: boolean;
  createdIndexes: string[];
  droppedIndexes: string[];
  preservedIndexes: string[];
  errors: string[];
}

export const MIGRATION_ID_PHASE4 = '001_phase4_production_indexes';

/**
 * Complete specification of production indexes required for SENTRIX.
 */
export const REQUIRED_INDEXES: IIndexSpec[] = [
  // ---------------- Scans Collection ----------------
  {
    collection: 'scans',
    keys: { status: 1, createdAt: 1 },
    options: { name: 'status_1_createdAt_1', background: true },
    description: 'FIFO queue status and creation time index for atomic job claiming',
  },
  {
    collection: 'scans',
    keys: { status: 1, claimedAt: 1 },
    options: { name: 'status_1_claimedAt_1', background: true },
    description: 'Processing status and claimed time index for abandoned job recovery reaper',
  },
  {
    collection: 'scans',
    keys: { urlHash: 1, status: 1 },
    options: { name: 'urlHash_1_status_1', background: true },
    description: 'URL hash and status lookup for in-flight active scan queries',
  },
  {
    collection: 'scans',
    keys: { urlHash: 1 },
    options: {
      name: 'urlHash_1_partial_active',
      unique: true,
      partialFilterExpression: { status: { $in: ['QUEUED', 'PROCESSING'] } },
      background: true,
    },
    description: 'Partial unique active URL hash index preventing concurrent duplicate submissions',
  },
  {
    collection: 'scans',
    keys: { publishedLeaseToken: 1 },
    options: { name: 'publishedLeaseToken_1', background: true },
    description: 'Published lease token lookup for result ownership validation',
  },
  {
    collection: 'scans',
    keys: { leaseToken: 1 },
    options: { name: 'leaseToken_1', background: true },
    description: 'Active lease token lookup for worker ownership verification',
  },
  {
    collection: 'scans',
    keys: { normalizedDomain: 1, createdAt: -1 },
    options: { name: 'normalizedDomain_1_createdAt_-1', background: true },
    description: 'Domain search and scan history lookup index',
  },
  {
    collection: 'scans',
    keys: { createdAt: -1 },
    options: { name: 'createdAt_-1', background: true },
    description: 'Global scan chronology index',
  },
  {
    collection: 'scans',
    keys: { verdict: 1 },
    options: { name: 'verdict_1', background: true },
    description: 'Verdict filtering index for threat analytics',
  },

  // ---------------- Findings Collection ----------------
  {
    collection: 'findings',
    keys: { scanId: 1, severity: 1 },
    options: { name: 'scanId_1_severity_1', background: true },
    description: 'Scan ID and severity index for categorized finding queries',
  },
  {
    collection: 'findings',
    keys: { scanId: 1, leaseToken: 1 },
    options: { name: 'scanId_1_leaseToken_1', background: true },
    description: 'Compound scan ID and lease token index for attempt-scoped queries and rollback',
  },
  {
    collection: 'findings',
    keys: { leaseToken: 1 },
    options: { name: 'leaseToken_1', background: true },
    description: 'Lease token index for orphan-artifact identification',
  },
  {
    collection: 'findings',
    keys: { category: 1 },
    options: { name: 'category_1', background: true },
    description: 'Finding category index for MITRE and taxonomy aggregation',
  },

  // ---------------- Certificates Collection ----------------
  {
    collection: 'certificates',
    keys: { scanId: 1 },
    options: { name: 'scanId_1', background: true },
    description: 'Scan ID lookup index for TLS certificate queries (non-unique)',
  },
  {
    collection: 'certificates',
    keys: { scanId: 1, leaseToken: 1 },
    options: { name: 'scanId_1_leaseToken_1', unique: true, sparse: true, background: true },
    description: 'Compound unique scan ID and lease token index isolating separate worker attempts',
  },
  {
    collection: 'certificates',
    keys: { fingerprint: 1 },
    options: { name: 'fingerprint_1', background: true },
    description: 'Certificate SHA-256 fingerprint index',
  },
  {
    collection: 'certificates',
    keys: { leaseToken: 1 },
    options: { name: 'leaseToken_1', background: true },
    description: 'Lease token index for certificate attempt scoping',
  },

  // ---------------- Threat Reports & Votes ----------------
  {
    collection: 'threatreports',
    keys: { urlHash: 1 },
    options: { name: 'urlHash_1', background: true },
    description: 'Threat report URL hash deduplication index',
  },
  {
    collection: 'threatreports',
    keys: { status: 1 },
    options: { name: 'status_1', background: true },
    description: 'Threat report status index',
  },
  {
    collection: 'threatvotes',
    keys: { reportId: 1, userId: 1 },
    options: { name: 'reportId_1_userId_1', unique: true, background: true },
    description: 'Compound unique index enforcing single vote per report per voter',
  },
  {
    collection: 'users',
    keys: { email: 1 },
    options: { name: 'email_1', unique: true, background: true },
    description: 'Unique email index for user accounts',
  },
];

/**
 * Obsolete indexes that must be safely dropped during explicit migration.
 */
export const OBSOLETE_INDEXES: IObsoleteIndexSpec[] = [
  {
    collection: 'certificates',
    name: 'scanId_1',
    reason: 'Legacy unique index on scanId alone; conflicts with multi-attempt result isolation',
    isObsoleteIf: (indexDef: any) => Boolean(indexDef.unique),
  },
];

export class IndexMigrationManager {
  private connection: Connection;
  private instanceId: string;

  constructor(connection?: Connection) {
    this.connection = connection || mongoose.connection;
    this.instanceId = `migrator_${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
  }

  /**
   * Plans or inspects index migrations (dry-run mode).
   */
  public async planMigrations(): Promise<IMigrationPlan> {
    const db = this.connection.db;
    if (!db) throw new Error('Database connection is not open');

    const plan: IMigrationPlan = {
      migrationId: MIGRATION_ID_PHASE4,
      dryRun: true,
      plannedCreations: [],
      plannedDrops: [],
      existingValid: [],
      duplicatesDetected: [],
    };

    // 1. Inspect required indexes
    for (const spec of REQUIRED_INDEXES) {
      const coll = db.collection(spec.collection);
      let existingIndexes: any[] = [];
      try {
        existingIndexes = await coll.indexes();
      } catch (err: any) {
        // Collection might not exist yet in fresh database
        existingIndexes = [];
      }

      const match = existingIndexes.find(
        (idx) =>
          idx.name === spec.options.name ||
          JSON.stringify(idx.key) === JSON.stringify(spec.keys)
      );

      if (match) {
        plan.existingValid.push({ collection: spec.collection, name: match.name });
      } else {
        plan.plannedCreations.push({
          collection: spec.collection,
          name: spec.options.name,
          keys: spec.keys,
          options: spec.options,
          description: spec.description,
        });
      }
    }

    // 2. Check for obsolete indexes
    for (const obs of OBSOLETE_INDEXES) {
      const coll = db.collection(obs.collection);
      let existingIndexes: any[] = [];
      try {
        existingIndexes = await coll.indexes();
      } catch {
        existingIndexes = [];
      }

      for (const idx of existingIndexes) {
        if (idx.name === '_id_') continue; // NEVER drop _id_
        if (idx.name === obs.name) {
          if (!obs.isObsoleteIf || obs.isObsoleteIf(idx)) {
            plan.plannedDrops.push({
              collection: obs.collection,
              name: idx.name,
              reason: obs.reason,
            });
          }
        }
      }
    }

    // 3. Pre-flight check: duplicate data for unique indexes
    try {
      const activeScanDuplicates = await db
        .collection('scans')
        .aggregate([
          { $match: { status: { $in: ['QUEUED', 'PROCESSING'] }, urlHash: { $exists: true } } },
          { $group: { _id: '$urlHash', count: { $sum: 1 } } },
          { $match: { count: { $gt: 1 } } },
        ])
        .toArray();

      for (const dup of activeScanDuplicates) {
        plan.duplicatesDetected.push({
          collection: 'scans',
          conflict: `Active scan urlHash duplicate: ${dup._id}`,
          count: dup.count,
        });
      }
    } catch {
      // Non-fatal during dry-run
    }

    return plan;
  }

  /**
   * Executes controlled index migration with distributed locking and audit recording.
   */
  public async applyMigrations(options: { dryRun?: boolean; force?: boolean } = {}): Promise<IMigrationResult> {
    const db = this.connection.db;
    if (!db) throw new Error('Database connection is not open');

    const dryRun = Boolean(options.dryRun);
    const result: IMigrationResult = {
      migrationId: MIGRATION_ID_PHASE4,
      dryRun,
      success: false,
      createdIndexes: [],
      droppedIndexes: [],
      preservedIndexes: [],
      errors: [],
    };

    if (dryRun) {
      const plan = await this.planMigrations();
      result.success = true;
      result.createdIndexes = plan.plannedCreations.map((c) => `${c.collection}.${c.name}`);
      result.droppedIndexes = plan.plannedDrops.map((d) => `${d.collection}.${d.name}`);
      result.preservedIndexes = plan.existingValid.map((v) => `${v.collection}.${v.name}`);
      return result;
    }

    // 1. Acquire distributed migration lock in _schema_migrations
    const migrationsColl = db.collection<{ _id: string; [key: string]: any }>('_schema_migrations');

    const existingMigration = await migrationsColl.findOne({ _id: MIGRATION_ID_PHASE4 });
    if (existingMigration && existingMigration.status === 'COMPLETED' && !options.force) {
      result.success = true;
      result.preservedIndexes.push('Migration already completed previously');
      return result;
    }

    // Atomic lock acquisition preventing concurrent executions across instances
    const lockCutoff = new Date(Date.now() - 5 * 60_000); // 5 min lock timeout
    try {
      const lockAcquired = await migrationsColl.findOneAndUpdate(
        {
          _id: MIGRATION_ID_PHASE4,
          $or: [
            { status: { $ne: 'IN_PROGRESS' } },
            { lockedAt: { $lt: lockCutoff } },
            { lockedAt: { $exists: false } },
          ],
        },
        {
          $set: {
            status: 'IN_PROGRESS',
            lockedAt: new Date(),
            lockHolder: this.instanceId,
            updatedAt: new Date(),
          },
        },
        { upsert: true, returnDocument: 'after' }
      );

      if (!lockAcquired) {
        throw new Error('Concurrent migration execution detected; another instance holds the lock');
      }
    } catch (lockErr: any) {
      if (lockErr.code === 11000) {
        throw new Error('Concurrent migration execution detected; lock already held by another instance');
      }
      throw lockErr;
    }

    try {
      // 2. Pre-flight data deduplication for unique indexes
      await this.resolveActiveScanDuplicates(db);

      // 3. Drop obsolete indexes safely first (NEVER drop _id_)
      // Dropping conflicting obsolete indexes first allows required replacement indexes to be created cleanly
      for (const obs of OBSOLETE_INDEXES) {
        const coll = db.collection(obs.collection);
        let existingIndexes: any[] = [];
        try {
          existingIndexes = await coll.indexes();
        } catch {
          existingIndexes = [];
        }

        for (const idx of existingIndexes) {
          if (idx.name === '_id_') continue; // Immutable safeguard
          if (idx.name === obs.name && (!obs.isObsoleteIf || obs.isObsoleteIf(idx))) {
            try {
              await coll.dropIndex(idx.name);
              result.droppedIndexes.push(`${obs.collection}.${idx.name}`);
            } catch (dropErr: any) {
              result.errors.push(`Failed to drop obsolete index ${obs.collection}.${idx.name}: ${dropErr.message}`);
            }
          }
        }
      }

      // 4. Create all missing required indexes
      for (const spec of REQUIRED_INDEXES) {
        const coll = db.collection(spec.collection);
        try {
          const indexName = await coll.createIndex(spec.keys as any, spec.options as any);
          result.createdIndexes.push(`${spec.collection}.${indexName}`);
        } catch (idxErr: any) {
          if (idxErr.code === 85 || idxErr.codeName === 'IndexOptionsConflict') {
            // Index already exists with slightly different name/options; record as preserved
            result.preservedIndexes.push(`${spec.collection}.${spec.options.name} (existing options match)`);
          } else {
            const msg = `Failed to create index ${spec.collection}.${spec.options.name}: ${idxErr.message}`;
            result.errors.push(msg);
          }
        }
      }

      if (result.errors.length > 0) {
        // Mark migration as FAILED in history
        await migrationsColl.updateOne(
          { _id: MIGRATION_ID_PHASE4 },
          {
            $set: {
              status: 'FAILED',
              lastError: result.errors.join('; '),
              updatedAt: new Date(),
              lockedAt: null,
            },
          }
        );
        result.success = false;
      } else {
        // Mark migration as COMPLETED in history
        await migrationsColl.updateOne(
          { _id: MIGRATION_ID_PHASE4 },
          {
            $set: {
              status: 'COMPLETED',
              appliedAt: new Date(),
              lockHolder: null,
              lockedAt: null,
              updatedAt: new Date(),
              details: {
                createdCount: result.createdIndexes.length,
                droppedCount: result.droppedIndexes.length,
              },
            },
          }
        );
        result.success = true;
      }
    } catch (migrationErr: any) {
      await migrationsColl.updateOne(
        { _id: MIGRATION_ID_PHASE4 },
        {
          $set: {
            status: 'FAILED',
            lastError: migrationErr.message,
            updatedAt: new Date(),
            lockedAt: null,
          },
        }
      );
      result.errors.push(migrationErr.message);
      result.success = false;
      throw migrationErr;
    }

    return result;
  }

  /**
   * Pre-flight resolver: handles duplicate active scans before creating the partial unique index.
   */
  private async resolveActiveScanDuplicates(db: any): Promise<void> {
    try {
      const duplicates = await db
        .collection('scans')
        .aggregate([
          { $match: { status: { $in: ['QUEUED', 'PROCESSING'] }, urlHash: { $exists: true } } },
          { $group: { _id: '$urlHash', count: { $sum: 1 }, ids: { $push: '$_id' } } },
          { $match: { count: { $gt: 1 } } },
        ])
        .toArray();

      for (const group of duplicates) {
        // Keep the newest active scan, mark older active duplicates as FAILED
        const [keepId, ...olderIds] = group.ids.reverse();
        if (olderIds.length > 0) {
          await db.collection('scans').updateMany(
            { _id: { $in: olderIds } },
            {
              $set: {
                status: 'FAILED',
                errorMessage: 'Superseded by concurrent duplicate submission during index migration',
                completedAt: new Date(),
              },
            }
          );
        }
      }
    } catch {
      // Non-fatal if scans collection is empty or fresh
    }
  }
}
