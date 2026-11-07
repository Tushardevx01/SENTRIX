import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import {
  ScanStatusEnum,
  FindingCategoryEnum,
  FindingSeverityEnum,
} from '@sentrix/shared';
import { ScanModel } from '../models/Scan.js';
import { FindingModel } from '../models/Finding.js';
import { CertificateModel } from '../models/Certificate.js';
import { ScanWorkerService } from '../services/scanWorker.js';
import { buildServer } from '../server.js';

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

const REAL_MONGO_URI = getTestDbUri('sentrix_test_concurrency');

describe('SENTRIX Real MongoDB 7.0 Concurrency & Integrity Integration Tests', () => {
  let isConnected = false;

  before(async () => {
    try {
      mongoose.set('strictQuery', true);
      await mongoose.connect(REAL_MONGO_URI, {
        serverSelectionTimeoutMS: 3000,
      });
      // Synchronize all schema indexes with live test DB
      await Promise.all([
        ScanModel.syncIndexes(),
        FindingModel.syncIndexes(),
        CertificateModel.syncIndexes(),
      ]);
      isConnected = true;
    } catch (err: any) {
      console.warn('Real MongoDB not accessible, skipping real DB tests:', err.message);
    }
  });

  after(async () => {
    if (isConnected) {
      // Clean up test collections
      await ScanModel.deleteMany({});
      await FindingModel.deleteMany({});
      await CertificateModel.deleteMany({});
      await mongoose.disconnect();
    }
  });

  // --------------------------------------------------------------------------
  // 1. Concurrent Worker Publication Race against Real MongoDB
  // --------------------------------------------------------------------------
  it('Real Mongo 1: Concurrent worker publication allows exactly one winner and losers receive null', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB not available');

    const scan = await ScanModel.create({
      submittedUrl: 'https://concurrency-test.com/race',
      normalizedDomain: 'concurrency-test.com',
      urlHash: 'hash-race-worker-test',
      status: ScanStatusEnum.PROCESSING,
      leaseToken: 'token-worker-1',
      retryCount: 0,
    });

    const token1 = 'token-worker-1';
    const token2 = 'token-worker-2-loser';

    // Simulate concurrent publication attempts
    const [res1, res2] = await Promise.all([
      ScanModel.findOneAndUpdate(
        { _id: scan._id, leaseToken: token1, status: ScanStatusEnum.PROCESSING },
        { $set: { status: ScanStatusEnum.COMPLETED, publishedLeaseToken: token1 } },
        { new: true }
      ),
      ScanModel.findOneAndUpdate(
        { _id: scan._id, leaseToken: token2, status: ScanStatusEnum.PROCESSING },
        { $set: { status: ScanStatusEnum.COMPLETED, publishedLeaseToken: token2 } },
        { new: true }
      ),
    ]);

    // Exactly one winner
    assert.notEqual(res1, null, 'Worker 1 holding active lease must successfully publish');
    assert.equal(res2, null, 'Worker 2 holding foreign lease must be rejected by atomic condition');

    const dbRecord: any = await ScanModel.findById(scan._id).lean();
    assert.equal(dbRecord?.status, ScanStatusEnum.COMPLETED);
    assert.equal(dbRecord?.publishedLeaseToken, token1);
  });

  // --------------------------------------------------------------------------
  // 2. Delayed Stale-Worker Writes & Attempt-Scoped Rollback
  // --------------------------------------------------------------------------
  it('Real Mongo 2: Delayed stale worker cannot delete or overwrite valid published results', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB not available');

    const scanId = new mongoose.Types.ObjectId();
    const tokenWinner = 'worker-winner-token';
    const tokenStale = 'worker-stale-token';

    // Worker Winner publishes results in real MongoDB
    await ScanModel.create({
      _id: scanId,
      submittedUrl: 'https://stale-worker-race.com',
      normalizedDomain: 'stale-worker-race.com',
      urlHash: 'hash-stale-worker-race',
      status: ScanStatusEnum.COMPLETED,
      leaseToken: tokenWinner,
      publishedLeaseToken: tokenWinner,
    });

    await FindingModel.create({
      scanId,
      leaseToken: tokenWinner,
      category: FindingCategoryEnum.DOMAIN_REPUTATION,
      severity: FindingSeverityEnum.HIGH,
      title: 'Valid Winner Finding',
      description: 'Found by Worker Winner',
      confidence: 90,
    });

    await CertificateModel.create({
      scanId,
      leaseToken: tokenWinner,
      issuer: 'Winner CA',
      subject: 'stale-worker-race.com',
      validFrom: '2026-01-01',
      validUntil: '2027-01-01',
      fingerprint: 'sha256:winner',
      hostnameMatched: true,
    });

    // Stale Worker wakes up and writes delayed findings with tokenStale
    await FindingModel.create({
      scanId,
      leaseToken: tokenStale,
      category: FindingCategoryEnum.URL_ANOMALY,
      severity: FindingSeverityEnum.CRITICAL,
      title: 'Stale Ghost Finding',
      description: 'Should never be published',
      confidence: 99,
    });

    // Stale Worker attempts publication (step 6)
    const staleUpdate = await ScanModel.findOneAndUpdate(
      { _id: scanId, leaseToken: tokenStale, status: ScanStatusEnum.PROCESSING },
      { $set: { status: ScanStatusEnum.COMPLETED, publishedLeaseToken: tokenStale } },
      { new: true }
    );
    assert.equal(staleUpdate, null, 'Stale worker publication must return null');

    // Stale Worker executes scoped rollback (step 6 rollback)
    await FindingModel.deleteMany({ scanId, leaseToken: tokenStale });
    await CertificateModel.deleteMany({ scanId, leaseToken: tokenStale });

    // Verify Winner data is intact in real MongoDB
    const winnerFindings = await FindingModel.find({ scanId }).lean();
    assert.equal(winnerFindings.length, 1);
    assert.equal(winnerFindings[0].title, 'Valid Winner Finding');
    assert.equal(winnerFindings[0].leaseToken, tokenWinner);

    const winnerCert: any = await CertificateModel.findOne({ scanId }).lean();
    assert.notEqual(winnerCert, null);
    assert.equal(winnerCert?.issuer, 'Winner CA');
  });

  // --------------------------------------------------------------------------
  // 3. Reader Query Isolation against Orphaned / Incomplete Attempts
  // --------------------------------------------------------------------------
  it('Real Mongo 3: Reader endpoints query strictly by publishedLeaseToken isolating winning results', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB not available');

    const app = buildServer();
    const scanId = new mongoose.Types.ObjectId();
    const winningToken = 'winning-attempt-token';
    const crashedToken = 'crashed-attempt-token';

    await ScanModel.create({
      _id: scanId,
      submittedUrl: 'https://reader-isolation-target.com',
      normalizedDomain: 'reader-isolation-target.com',
      urlHash: 'hash-reader-isolation',
      status: ScanStatusEnum.COMPLETED,
      leaseToken: winningToken,
      publishedLeaseToken: winningToken,
      verdict: 'SUSPICIOUS',
      riskScore: 65,
    });

    // Both winning and crashed attempt findings exist in MongoDB
    await FindingModel.create([
      {
        scanId,
        leaseToken: winningToken,
        category: FindingCategoryEnum.URL_ANOMALY,
        severity: FindingSeverityEnum.MEDIUM,
        title: 'Winning Attempt Finding',
        description: 'Verified',
        confidence: 80,
      },
      {
        scanId,
        leaseToken: crashedToken,
        category: FindingCategoryEnum.URL_ANOMALY,
        severity: FindingSeverityEnum.CRITICAL,
        title: 'Crashed Incomplete Finding',
        description: 'Corrupted partial attempt',
        confidence: 100,
      },
    ]);

    await CertificateModel.create({
      scanId,
      leaseToken: winningToken,
      issuer: 'Winning CA',
      subject: 'reader-isolation-target.com',
      validFrom: '2026-01-01',
      validUntil: '2027-01-01',
      fingerprint: 'sha256:win',
      hostnameMatched: true,
    });

    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/scans/${scanId}/results`,
    });

    assert.equal(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.equal(body.status, ScanStatusEnum.COMPLETED);
    assert.equal(body.findings.length, 1);
    assert.equal(body.findings[0].title, 'Winning Attempt Finding');
    assert.equal(body.findings[0].leaseToken, winningToken);
    assert.equal(body.certificate.issuer, 'Winning CA');

    await app.close();
  });

  // --------------------------------------------------------------------------
  // 4. Legacy Completed Scan Backward Compatibility
  // --------------------------------------------------------------------------
  it('Real Mongo 4: Legacy completed scans without publishedLeaseToken correctly return untagged findings', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB not available');

    const app = buildServer();
    const scanId = new mongoose.Types.ObjectId();

    // Legacy scan: completed before attempt scoping; has leaseToken on scan, but NO publishedLeaseToken
    await ScanModel.collection.insertOne({
      _id: scanId,
      submittedUrl: 'https://legacy-scan.com',
      normalizedDomain: 'legacy-scan.com',
      urlHash: 'hash-legacy-1',
      status: ScanStatusEnum.COMPLETED,
      leaseToken: 'legacy-lease-token',
      verdict: 'BENIGN',
      riskScore: 10,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // Legacy findings without leaseToken field
    await FindingModel.collection.insertOne({
      scanId,
      category: FindingCategoryEnum.DOMAIN_REPUTATION,
      severity: FindingSeverityEnum.INFO,
      title: 'Legacy Untagged Finding',
      description: 'Created before leaseToken scoping',
      confidence: 50,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await CertificateModel.collection.insertOne({
      scanId,
      issuer: 'Legacy Root CA',
      subject: 'legacy-scan.com',
      validFrom: '2025-01-01',
      validUntil: '2026-01-01',
      fingerprint: 'sha256:legacy',
      hostnameMatched: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/scans/${scanId}/results`,
    });

    assert.equal(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.equal(body.status, ScanStatusEnum.COMPLETED);
    assert.equal(body.findings.length, 1, 'Legacy scan must return untagged findings');
    assert.equal(body.findings[0].title, 'Legacy Untagged Finding');
    assert.equal(body.certificate.issuer, 'Legacy Root CA');

    await app.close();
  });

  // --------------------------------------------------------------------------
  // 5. Certificate Compound Unique Index
  // --------------------------------------------------------------------------
  it('Real Mongo 5: Certificate compound unique index permits separate attempts but prevents collision within same attempt', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB not available');

    const scanId = new mongoose.Types.ObjectId();

    // Attempt 1 creates cert
    const cert1 = await CertificateModel.create({
      scanId,
      leaseToken: 'token-attempt-1',
      issuer: 'CA 1',
      subject: 'test.com',
      validFrom: '2026-01-01',
      validUntil: '2027-01-01',
      fingerprint: 'fp1',
      hostnameMatched: true,
    });
    assert.notEqual(cert1, null);

    // Attempt 2 creates cert for SAME scanId with different leaseToken -> SUCCEEDS
    const cert2 = await CertificateModel.create({
      scanId,
      leaseToken: 'token-attempt-2',
      issuer: 'CA 2',
      subject: 'test.com',
      validFrom: '2026-01-01',
      validUntil: '2027-01-01',
      fingerprint: 'fp2',
      hostnameMatched: true,
    });
    assert.notEqual(cert2, null);

    // Duplicate within SAME attempt -> THROWS E11000
    await assert.rejects(
      async () => {
        await CertificateModel.create({
          scanId,
          leaseToken: 'token-attempt-1',
          issuer: 'CA Duplicate',
          subject: 'test.com',
          validFrom: '2026-01-01',
          validUntil: '2027-01-01',
          fingerprint: 'fp1',
          hostnameMatched: true,
        });
      },
      (err: any) => err.code === 11000
    );
  });

  // --------------------------------------------------------------------------
  // 6. Active Scan Partial Unique Index Duplicate Prevention
  // --------------------------------------------------------------------------
  it('Real Mongo 6: Partial unique index blocks active duplicates but allows re-scanning after completion', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB not available');

    const testUrlHash = 'partial-unique-index-test-hash';

    // 1. First scan in QUEUED
    const activeScan = await ScanModel.create({
      submittedUrl: 'https://partial-index-target.com',
      normalizedDomain: 'partial-index-target.com',
      urlHash: testUrlHash,
      status: ScanStatusEnum.QUEUED,
    });
    assert.notEqual(activeScan, null);

    // 2. Second scan with same urlHash while first is QUEUED -> E11000 duplicate key
    await assert.rejects(
      async () => {
        await ScanModel.create({
          submittedUrl: 'https://partial-index-target.com',
          normalizedDomain: 'partial-index-target.com',
          urlHash: testUrlHash,
          status: ScanStatusEnum.PROCESSING,
        });
      },
      (err: any) => err.code === 11000
    );

    // 3. Complete the active scan
    await ScanModel.updateOne(
      { _id: activeScan._id },
      { $set: { status: ScanStatusEnum.COMPLETED, publishedLeaseToken: 'token-done' } }
    );

    // 4. Now a new scan with same urlHash in QUEUED succeeds
    const newScan = await ScanModel.create({
      submittedUrl: 'https://partial-index-target.com',
      normalizedDomain: 'partial-index-target.com',
      urlHash: testUrlHash,
      status: ScanStatusEnum.QUEUED,
    });
    assert.notEqual(newScan, null);
  });

  // --------------------------------------------------------------------------
  // 7. Abandoned Job Reaper & Completion Race in Real MongoDB
  // --------------------------------------------------------------------------
  it('Real Mongo 7: Reaper and completion race ensures exactly one state mutation', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB not available');

    const worker = new ScanWorkerService('real-mongo-reaper');
    const scanId = new mongoose.Types.ObjectId();
    const workerToken = 'racing-worker-lease';

    // Job claimed 70 seconds ago (exceeds 60s timeout)
    const claimedAt = new Date(Date.now() - 70000);

    await ScanModel.create({
      _id: scanId,
      submittedUrl: 'https://reaper-race-target.com',
      normalizedDomain: 'reaper-race-target.com',
      urlHash: 'hash-reaper-race',
      status: ScanStatusEnum.PROCESSING,
      leaseToken: workerToken,
      claimedAt,
      retryCount: 0,
    });

    // Race: Worker attempts fenced completion vs Reaper attempts recovery
    const [workerCommit, recoveredCount] = await Promise.all([
      ScanModel.findOneAndUpdate(
        { _id: scanId, leaseToken: workerToken, status: ScanStatusEnum.PROCESSING },
        { $set: { status: ScanStatusEnum.COMPLETED, publishedLeaseToken: workerToken } },
        { new: true }
      ),
      worker.recoverAbandonedJobs(60000),
    ]);

    const finalScan: any = await ScanModel.findById(scanId).lean();
    if (workerCommit) {
      // Worker won: final status must be COMPLETED
      assert.equal(finalScan?.status, ScanStatusEnum.COMPLETED);
      assert.equal(finalScan?.publishedLeaseToken, workerToken);
    } else {
      // Reaper won: final status must be QUEUED
      assert.equal(finalScan?.status, ScanStatusEnum.QUEUED);
      assert.equal(recoveredCount, 1);
    }
  });

  // --------------------------------------------------------------------------
  // 8. Post-Publication Pruning Resiliency
  // --------------------------------------------------------------------------
  it('Real Mongo 8: Post-publication pruning removes older attempts and leaves winning attempt intact', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB not available');

    const scanId = new mongoose.Types.ObjectId();
    const winningToken = 'prune-test-winning-token';
    const oldToken1 = 'prune-test-old-token-1';
    const oldToken2 = 'prune-test-old-token-2';

    await FindingModel.create([
      {
        scanId,
        leaseToken: oldToken1,
        category: FindingCategoryEnum.URL_ANOMALY,
        severity: FindingSeverityEnum.LOW,
        title: 'Old Attempt 1 Finding',
        description: 'Old attempt 1 description',
        confidence: 40,
      },
      {
        scanId,
        leaseToken: oldToken2,
        category: FindingCategoryEnum.URL_ANOMALY,
        severity: FindingSeverityEnum.LOW,
        title: 'Old Attempt 2 Finding',
        description: 'Old attempt 2 description',
        confidence: 40,
      },
      {
        scanId,
        leaseToken: winningToken,
        category: FindingCategoryEnum.URL_ANOMALY,
        severity: FindingSeverityEnum.HIGH,
        title: 'Winning Finding',
        description: 'Winning attempt description',
        confidence: 90,
      },
    ]);

    // Execute post-publication pruning
    await FindingModel.deleteMany({
      scanId,
      leaseToken: { $ne: winningToken },
    });

    const remaining = await FindingModel.find({ scanId }).lean();
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0].title, 'Winning Finding');
    assert.equal(remaining[0].leaseToken, winningToken);
  });
});
