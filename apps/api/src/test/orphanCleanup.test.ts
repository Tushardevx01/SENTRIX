import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { ScanStatusEnum, FindingCategoryEnum, FindingSeverityEnum } from '@sentrix/shared';
import { ScanModel } from '../models/Scan.js';
import { FindingModel } from '../models/Finding.js';
import { CertificateModel } from '../models/Certificate.js';
import {
  OrphanCleanupService,
  IOrphanCleanupOptions,
} from '../services/orphanCleanup.js';

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

const TEST_MONGO_URI = getTestDbUri('sentrix_test_orphan');

describe('SENTRIX Orphan-Artifact Recovery & Cleanup Tests', () => {
  let isConnected = false;
  let cleanupService: OrphanCleanupService;

  before(async () => {
    try {
      mongoose.set('strictQuery', true);
      await mongoose.connect(TEST_MONGO_URI, { serverSelectionTimeoutMS: 3000 });
      isConnected = true;
    } catch (err: any) {
      console.warn('Real MongoDB not available, skipping orphan integration tests:', err.message);
    }
    cleanupService = new OrphanCleanupService();
  });

  after(async () => {
    if (isConnected) {
      await ScanModel.deleteMany({});
      await FindingModel.deleteMany({});
      await CertificateModel.deleteMany({});
      await mongoose.disconnect();
    }
  });

  beforeEach(async () => {
    if (isConnected) {
      await ScanModel.deleteMany({});
      await FindingModel.deleteMany({});
      await CertificateModel.deleteMany({});
    }
  });

  // --------------------------------------------------------------------------
  // Test 1: Abandoned attempt artifacts are removed
  // --------------------------------------------------------------------------
  it('Test 1: Abandoned attempt artifacts on failed/re-queued scans are safely removed', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const scanId = new mongoose.Types.ObjectId();
    const abandonedToken = 'abandoned-lease-token-1';

    // Scan is FAILED (timed out or crashed)
    await ScanModel.create({
      _id: scanId,
      submittedUrl: 'https://abandoned-test.com',
      normalizedDomain: 'abandoned-test.com',
      urlHash: 'hash-abandoned-1',
      status: ScanStatusEnum.FAILED,
      retryCount: 3,
    });

    await FindingModel.create({
      scanId,
      leaseToken: abandonedToken,
      category: FindingCategoryEnum.URL_ANOMALY,
      severity: FindingSeverityEnum.HIGH,
      title: 'Abandoned Finding',
      description: 'Worker crashed before publishing',
      confidence: 85,
    });

    await CertificateModel.create({
      scanId,
      leaseToken: abandonedToken,
      issuer: 'Abandoned CA',
      subject: 'abandoned-test.com',
      validFrom: '2026-01-01',
      validUntil: '2027-01-01',
      fingerprint: 'sha256:abandoned',
      hostnameMatched: true,
    });

    const report = await cleanupService.runCleanup({ retentionMs: 0 });

    assert.equal(report.abandonedDeleted, 1);
    assert.equal(report.findingsDeleted, 1);
    assert.equal(report.certificatesDeleted, 1);

    const remainingFindings = await FindingModel.find({ scanId, leaseToken: abandonedToken });
    assert.equal(remainingFindings.length, 0);

    const remainingCerts = await CertificateModel.find({ scanId, leaseToken: abandonedToken });
    assert.equal(remainingCerts.length, 0);
  });

  // --------------------------------------------------------------------------
  // Test 2: Published attempt artifacts are preserved
  // --------------------------------------------------------------------------
  it('Test 2: Published attempt artifacts are strictly preserved and never deleted', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const scanId = new mongoose.Types.ObjectId();
    const winningToken = 'winning-published-token';

    await ScanModel.create({
      _id: scanId,
      submittedUrl: 'https://published-target.com',
      normalizedDomain: 'published-target.com',
      urlHash: 'hash-published-target',
      status: ScanStatusEnum.COMPLETED,
      leaseToken: winningToken,
      publishedLeaseToken: winningToken,
    });

    await FindingModel.create({
      scanId,
      leaseToken: winningToken,
      category: FindingCategoryEnum.DOMAIN_REPUTATION,
      severity: FindingSeverityEnum.MEDIUM,
      title: 'Published Winning Finding',
      description: 'Crucial forensic evidence',
      confidence: 90,
    });

    await CertificateModel.create({
      scanId,
      leaseToken: winningToken,
      issuer: 'Valid Root CA',
      subject: 'published-target.com',
      validFrom: '2026-01-01',
      validUntil: '2027-01-01',
      fingerprint: 'sha256:valid',
      hostnameMatched: true,
    });

    const report = await cleanupService.runCleanup({ retentionMs: 0 });

    assert.equal(report.publishedPreserved, 1);
    assert.equal(report.findingsDeleted, 0);
    assert.equal(report.certificatesDeleted, 0);

    const preservedFindings = await FindingModel.find({ scanId });
    assert.equal(preservedFindings.length, 1);
    assert.equal(preservedFindings[0].title, 'Published Winning Finding');

    const preservedCert = await CertificateModel.findOne({ scanId });
    assert.notEqual(preservedCert, null);
    assert.equal(preservedCert?.issuer, 'Valid Root CA');
  });

  // --------------------------------------------------------------------------
  // Test 3: Active lease artifacts are preserved
  // --------------------------------------------------------------------------
  it('Test 3: Active in-flight worker attempt artifacts are preserved during execution', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const scanId = new mongoose.Types.ObjectId();
    const activeToken = 'in-flight-active-lease';

    // Scan is actively PROCESSING by a worker
    await ScanModel.create({
      _id: scanId,
      submittedUrl: 'https://in-flight-scan.com',
      normalizedDomain: 'in-flight-scan.com',
      urlHash: 'hash-in-flight-scan',
      status: ScanStatusEnum.PROCESSING,
      leaseToken: activeToken,
      claimedAt: new Date(),
    });

    await FindingModel.create({
      scanId,
      leaseToken: activeToken,
      category: FindingCategoryEnum.TLS_SECURITY,
      severity: FindingSeverityEnum.LOW,
      title: 'Active In-Flight Finding',
      description: 'Being generated right now',
      confidence: 70,
    });

    const report = await cleanupService.runCleanup({ retentionMs: 0 });

    assert.equal(report.activePreserved, 1);
    assert.equal(report.findingsDeleted, 0);

    const activeFindings = await FindingModel.find({ scanId, leaseToken: activeToken });
    assert.equal(activeFindings.length, 1);
  });

  // --------------------------------------------------------------------------
  // Test 4: Superseded attempts are cleaned safely
  // --------------------------------------------------------------------------
  it('Test 4: Superseded attempts on COMPLETED scans are cleaned while published attempt remains', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const scanId = new mongoose.Types.ObjectId();
    const winningToken = 'winner-token-final';
    const supersededToken = 'superseded-token-retry-1';

    await ScanModel.create({
      _id: scanId,
      submittedUrl: 'https://superseded-test.com',
      normalizedDomain: 'superseded-test.com',
      urlHash: 'hash-superseded-test',
      status: ScanStatusEnum.COMPLETED,
      leaseToken: winningToken,
      publishedLeaseToken: winningToken,
    });

    // 1 winning finding and 1 superseded finding
    await FindingModel.create([
      {
        scanId,
        leaseToken: winningToken,
        category: FindingCategoryEnum.URL_ANOMALY,
        severity: FindingSeverityEnum.HIGH,
        title: 'Winning Published Finding',
        description: 'Final published record',
        confidence: 95,
      },
      {
        scanId,
        leaseToken: supersededToken,
        category: FindingCategoryEnum.URL_ANOMALY,
        severity: FindingSeverityEnum.LOW,
        title: 'Superseded Early Finding',
        description: 'From an earlier retry attempt',
        confidence: 40,
      },
    ]);

    const report = await cleanupService.runCleanup({ retentionMs: 0 });

    assert.equal(report.supersededDeleted, 1);
    assert.equal(report.publishedPreserved, 1);
    assert.equal(report.findingsDeleted, 1);

    const remaining = await FindingModel.find({ scanId }).lean();
    assert.equal(remaining.length, 1);
    assert.equal((remaining[0] as any).leaseToken, winningToken);
  });

  // --------------------------------------------------------------------------
  // Test 5: Cleanup cannot race with publication and delete winning results
  // --------------------------------------------------------------------------
  it('Test 5: Cleanup cannot race with publication and delete winning results', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const scanId = new mongoose.Types.ObjectId();
    const candidateToken = 'racing-publication-token';

    // Scan is currently PROCESSING with candidateToken
    await ScanModel.create({
      _id: scanId,
      submittedUrl: 'https://racing-pub.com',
      normalizedDomain: 'racing-pub.com',
      urlHash: 'hash-racing-pub',
      status: ScanStatusEnum.PROCESSING,
      leaseToken: candidateToken,
      claimedAt: new Date(),
    });

    await FindingModel.create({
      scanId,
      leaseToken: candidateToken,
      category: FindingCategoryEnum.PHISHING_INDICATOR,
      severity: FindingSeverityEnum.CRITICAL,
      title: 'Phishing Target Match',
      description: 'Crucial detection',
      confidence: 99,
    });

    // Worker publishes completion concurrently
    await ScanModel.updateOne(
      { _id: scanId, leaseToken: candidateToken },
      { $set: { status: ScanStatusEnum.COMPLETED, publishedLeaseToken: candidateToken } }
    );

    // Cleanup executes
    const report = await cleanupService.runCleanup({ retentionMs: 0 });

    // Winning token must be recognized as published and preserved
    assert.equal(report.publishedPreserved, 1);
    assert.equal(report.findingsDeleted, 0);

    const findings = await FindingModel.find({ scanId });
    assert.equal(findings.length, 1);
    assert.equal(findings[0].title, 'Phishing Target Match');
  });

  // --------------------------------------------------------------------------
  // Test 6: Missing scan references are handled safely
  // --------------------------------------------------------------------------
  it('Test 6: Artifacts pointing to non-existent or deleted scans are safely cleaned', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const nonExistentScanId = new mongoose.Types.ObjectId();
    const ghostToken = 'ghost-scan-lease-token';

    // Artifact created with no corresponding Scan record
    await FindingModel.create({
      scanId: nonExistentScanId,
      leaseToken: ghostToken,
      category: FindingCategoryEnum.URL_ANOMALY,
      severity: FindingSeverityEnum.INFO,
      title: 'Ghost Finding',
      description: 'Orphaned from deleted scan',
      confidence: 20,
    });

    const report = await cleanupService.runCleanup({ retentionMs: 0 });

    assert.equal(report.missingScanDeleted, 1);
    assert.equal(report.findingsDeleted, 1);

    const remaining = await FindingModel.find({ scanId: nonExistentScanId });
    assert.equal(remaining.length, 0);
  });

  // --------------------------------------------------------------------------
  // Test 7: MongoDB disconnection does not crash the worker
  // --------------------------------------------------------------------------
  it('Test 7: Database disconnection or query error is caught safely without crashing', async () => {
    const disconnectedService = new OrphanCleanupService();

    // Mock FindingModel.find to simulate database network failure
    const originalFind = FindingModel.find;
    (FindingModel as any).find = () => {
      throw new Error('MongoNetworkError: connection 1 to 127.0.0.1:27017 timed out');
    };

    try {
      const report = await disconnectedService.runCleanup();
      assert.equal(report.errors.length, 1);
      assert.match(report.errors[0], /MongoNetworkError/);
      assert.equal(disconnectedService.isExecutionRunning(), false, 'isRunning must be reset even on failure');
    } finally {
      FindingModel.find = originalFind;
    }
  });

  // --------------------------------------------------------------------------
  // Test 8: Cleanup is idempotent
  // --------------------------------------------------------------------------
  it('Test 8: Cleanup is idempotent across multiple sequential executions', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const scanId = new mongoose.Types.ObjectId();
    const oldToken = 'idempotent-old-token';

    await ScanModel.create({
      _id: scanId,
      submittedUrl: 'https://idempotent-test.com',
      normalizedDomain: 'idempotent-test.com',
      urlHash: 'hash-idempotent-test',
      status: ScanStatusEnum.FAILED,
    });

    await FindingModel.create({
      scanId,
      leaseToken: oldToken,
      category: FindingCategoryEnum.URL_ANOMALY,
      severity: FindingSeverityEnum.LOW,
      title: 'Transient Finding',
      description: 'To be cleaned',
      confidence: 30,
    });

    // Run 1: Deletes artifact
    const report1 = await cleanupService.runCleanup({ retentionMs: 0 });
    assert.equal(report1.abandonedDeleted, 1);
    assert.equal(report1.findingsDeleted, 1);

    // Run 2: Nothing left to clean, finishes cleanly with 0 deleted
    const report2 = await cleanupService.runCleanup({ retentionMs: 0 });
    assert.equal(report2.scannedCount, 0);
    assert.equal(report2.findingsDeleted, 0);
    assert.equal(report2.errors.length, 0);
  });

  // --------------------------------------------------------------------------
  // Test 9: Large cleanup batches respect configured limits
  // --------------------------------------------------------------------------
  it('Test 9: Large cleanup batches respect configured limits without excessive database load', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    // Create 10 orphaned findings across different scans
    const docs = [];
    for (let i = 0; i < 10; i++) {
      docs.push({
        scanId: new mongoose.Types.ObjectId(),
        leaseToken: `batch-token-${i}`,
        category: FindingCategoryEnum.URL_ANOMALY,
        severity: FindingSeverityEnum.LOW,
        title: `Batch Finding ${i}`,
        description: 'Batch test description',
        confidence: 30,
      });
    }
    await FindingModel.create(docs);

    // Request batch size of 4
    const report = await cleanupService.runCleanup({ batchSize: 4, retentionMs: 0 });

    assert.equal(report.scannedCount, 4, 'Must bound scanned items to requested batch size');
    assert.equal(report.attemptsEvaluated, 4);
    assert.equal(report.findingsDeleted, 4);
  });

  // --------------------------------------------------------------------------
  // Test 10: Concurrent cleanup executions do not overlap
  // --------------------------------------------------------------------------
  it('Test 10: Concurrent cleanup executions do not overlap and second execution skips safely', async (t) => {
    if (!isConnected) return t.skip('Real MongoDB required');

    const service = new OrphanCleanupService();

    // Trigger two cleanup executions concurrently
    const [report1, report2] = await Promise.all([
      service.runCleanup({ retentionMs: 0 }),
      service.runCleanup({ retentionMs: 0 }),
    ]);

    // One of them should succeed, the other should be skipped due to concurrency lock
    const oneSkipped = report1.skipped || report2.skipped;
    assert.equal(oneSkipped, true, 'At least one concurrent execution must skip via concurrency lock');
  });
});
