import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { ScanStatusEnum } from '@sentrix/shared';
import { buildServer } from '../server.js';
import { ScanModel } from '../models/Scan.js';
import { FindingModel } from '../models/Finding.js';
import { CertificateModel } from '../models/Certificate.js';
import {
  ScanWorkerService,
  scanWorker,
  MAX_RETRIES,
  MAX_CONCURRENT_JOBS,
} from '../services/scanWorker.js';
import { ScannerClientError } from '../services/scannerClient.js';

describe('SENTRIX Asynchronous Background Scanning Reliability & Fencing Tests', () => {
  // --------------------------------------------------------------------------
  // Scenario 1: Concurrent worker claiming
  // --------------------------------------------------------------------------
  it('Scenario 1: Concurrent worker claiming ensures atomic single-worker acquisition', async () => {
    const workerA = new ScanWorkerService('worker-node-1');
    const workerB = new ScanWorkerService('worker-node-2');
    const targetScanId = new mongoose.Types.ObjectId();

    // Simulated shared MongoDB state for atomic queue
    let queueState = {
      _id: targetScanId,
      status: ScanStatusEnum.QUEUED,
      retryCount: 0,
      workerId: undefined as string | undefined,
      leaseToken: undefined as string | undefined,
    };

    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;
    (ScanModel as any).findOneAndUpdate = async (query: any, update: any, opts: any) => {
      // Atomic query condition simulation: matches if status is QUEUED
      if (query.status === queueState.status && query.retryCount.$lt > queueState.retryCount) {
        queueState = {
          ...queueState,
          status: update.$set.status,
          workerId: update.$set.workerId,
          leaseToken: update.$set.leaseToken,
        };
        return { ...queueState };
      }
      return null;
    };

    try {
      // Both workers attempt to claim simultaneously
      const [claimA, claimB] = await Promise.all([
        workerA.claimNextJob(),
        workerB.claimNextJob(),
      ]);

      // Exactly one worker must acquire the lease; the other must receive null
      const acquiredCount = (claimA ? 1 : 0) + (claimB ? 1 : 0);
      assert.equal(acquiredCount, 1, 'Exactly one worker must acquire the lease');

      const winningClaim = claimA || claimB;
      assert.notEqual(winningClaim, null);
      assert.equal(winningClaim?.status, ScanStatusEnum.PROCESSING);
      assert.ok(winningClaim?.leaseToken, 'Winning claim must have a unique leaseToken');
    } finally {
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
    }
  });

  // --------------------------------------------------------------------------
  // Scenario 2: Expired lease result rejection (Fencing Token Protection)
  // --------------------------------------------------------------------------
  it('Scenario 2: Worker with expired leaseToken has results rejected and rolled back', async () => {
    const worker = new ScanWorkerService('zombie-worker');
    const scanId = new mongoose.Types.ObjectId();
    const staleLeaseToken = 'lease-token-expired-epoch-1';

    const mockScanDoc: any = {
      _id: scanId,
      submittedUrl: 'https://slow-analysis.com',
      normalizedDomain: 'slow-analysis.com',
      leaseToken: staleLeaseToken,
      retryCount: 0,
    };

    const originalFetch = globalThis.fetch;
    const originalFindOne = ScanModel.findOne;
    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;
    const originalDeleteMany = FindingModel.deleteMany;
    const originalInsertMany = FindingModel.insertMany;

    let deleteCalls: any[] = [];
    (FindingModel as any).deleteMany = async (q: any) => {
      deleteCalls.push(q);
      return { acknowledged: true };
    };

    (FindingModel as any).insertMany = async (docs: any[]) => docs;

    // Simulate pre-write check failure: lease was revoked in MongoDB by reaper or another worker
    (ScanModel as any).findOne = () => ({
      lean: async () => null, // Lease is no longer active in DB
    });

    let fencedUpdateCalled = false;
    (ScanModel as any).findOneAndUpdate = async () => {
      fencedUpdateCalled = true;
      return null;
    };

    globalThis.fetch = async () =>
      ({
        ok: true,
        status: 200,
        json: async () => ({
          scanId: scanId.toString(),
          riskScore: 90,
          verdict: 'MALICIOUS',
          confidence: 95,
          analyzerStatuses: {},
          findings: [{ title: 'Ghost Finding', severity: 'CRITICAL', category: 'HEURISTIC' }],
        }),
      } as any);

    try {
      await worker.executeJob(mockScanDoc);

      // Verify that the zombie worker did NOT perform the status update
      assert.equal(fencedUpdateCalled, false, 'Should abort before updating scan if lease expired');
    } finally {
      globalThis.fetch = originalFetch;
      ScanModel.findOne = originalFindOne;
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
      FindingModel.deleteMany = originalDeleteMany;
      FindingModel.insertMany = originalInsertMany;
    }
  });

  // --------------------------------------------------------------------------
  // Scenario 3: Reaper versus completion race
  // --------------------------------------------------------------------------
  it('Scenario 3: Reaper does not overwrite a scan that completed right as reaper ran', async () => {
    const worker = new ScanWorkerService('reaper-worker');
    const scanId = new mongoose.Types.ObjectId();
    const originalLeaseToken = 'lease-token-racing-123';

    // The scan in the reaper query list
    const staleScanJob = {
      _id: scanId,
      status: ScanStatusEnum.PROCESSING,
      leaseToken: originalLeaseToken,
      claimedAt: new Date(Date.now() - 120_000),
      retryCount: 0,
    };

    const originalFind = ScanModel.find;
    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;

    (ScanModel as any).find = () => ({
      limit: async () => [staleScanJob],
    });

    // Simulate that the active worker completed and committed status = COMPLETED
    // right before reaper's conditional findOneAndUpdate runs:
    (ScanModel as any).findOneAndUpdate = async (condition: any) => {
      // Condition requires status === PROCESSING. If job is now COMPLETED, match fails.
      if (condition.status === ScanStatusEnum.PROCESSING && condition.leaseToken === originalLeaseToken) {
        // Active worker already modified status to COMPLETED, so return null
        return null;
      }
      return null;
    };

    try {
      const recoveredCount = await worker.recoverAbandonedJobs(60_000);

      // Reaper must recover 0 jobs because the condition failed
      assert.equal(recoveredCount, 0, 'Reaper must not overwrite completed scan');
    } finally {
      ScanModel.find = originalFind;
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
    }
  });

  // --------------------------------------------------------------------------
  // Scenario 4: Worker crash during scanner execution
  // --------------------------------------------------------------------------
  it('Scenario 4: Worker crash during scanner call is safely recovered by reaper', async () => {
    const worker = new ScanWorkerService('reaper-test');
    const scanId = new mongoose.Types.ObjectId();
    const staleScan = {
      _id: scanId,
      status: ScanStatusEnum.PROCESSING,
      workerId: 'crashed-worker-pid-999',
      leaseToken: 'crashed-lease-token',
      claimedAt: new Date(Date.now() - 90_000), // 90s ago (> 60s timeout)
      retryCount: 0,
    };

    const originalFind = ScanModel.find;
    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;

    (ScanModel as any).find = () => ({
      limit: async () => [staleScan],
    });

    let recordedUpdate: any = null;
    (ScanModel as any).findOneAndUpdate = async (condition: any, update: any) => {
      recordedUpdate = update;
      return { _id: scanId, ...update.$set };
    };

    try {
      const recoveredCount = await worker.recoverAbandonedJobs(60_000);

      assert.equal(recoveredCount, 1);
      assert.notEqual(recordedUpdate, null);
      assert.equal(recordedUpdate.$set.status, ScanStatusEnum.QUEUED);
      assert.equal(recordedUpdate.$set.workerId, undefined);
      assert.equal(recordedUpdate.$set.leaseToken, undefined);
      assert.equal(recordedUpdate.$set.claimedAt, undefined);
      assert.equal(recordedUpdate.$inc.retryCount, 1);
    } finally {
      ScanModel.find = originalFind;
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
    }
  });

  // --------------------------------------------------------------------------
  // Scenario 5: Worker crash during result persistence & retry cleanup
  // --------------------------------------------------------------------------
  it('Scenario 5: Subsequent retry deletes orphan findings from earlier crashed attempt', async () => {
    const worker = new ScanWorkerService('retry-worker');
    const scanId = new mongoose.Types.ObjectId();
    const leaseToken = 'valid-active-lease';

    const mockScan: any = {
      _id: scanId,
      submittedUrl: 'https://partial-crash.com',
      normalizedDomain: 'partial-crash.com',
      leaseToken,
      retryCount: 1,
    };

    const originalFetch = globalThis.fetch;
    const originalFindOne = ScanModel.findOne;
    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;
    const originalDeleteMany = FindingModel.deleteMany;
    const originalCertificateDeleteMany = CertificateModel.deleteMany;
    const originalInsertMany = FindingModel.insertMany;

    const findingDeleteQueries: any[] = [];
    const certDeleteQueries: any[] = [];

    (ScanModel as any).findOne = () => ({
      lean: async () => ({ _id: scanId, leaseToken, status: ScanStatusEnum.PROCESSING }),
    });

    (FindingModel as any).deleteMany = async (q: any) => {
      findingDeleteQueries.push(q);
      return { acknowledged: true };
    };

    (CertificateModel as any).deleteMany = async (q: any) => {
      certDeleteQueries.push(q);
      return { acknowledged: true };
    };

    (FindingModel as any).insertMany = async (docs: any[]) => docs;
    (ScanModel as any).findOneAndUpdate = async () => ({ _id: scanId });

    globalThis.fetch = async () =>
      ({
        ok: true,
        status: 200,
        json: async () => ({
          scanId: scanId.toString(),
          riskScore: 20,
          verdict: 'BENIGN',
          confidence: 90,
          analyzerStatuses: {},
          findings: [],
        }),
      } as any);

    try {
      await worker.executeJob(mockScan);

      // Verify that deleteMany was called first with leaseToken scope, then post-publication with $ne
      assert.equal(findingDeleteQueries.length, 2);
      assert.equal(findingDeleteQueries[0].scanId.toString(), scanId.toString());
      assert.equal(findingDeleteQueries[0].leaseToken, leaseToken);
      assert.deepEqual(findingDeleteQueries[1].leaseToken, { $ne: leaseToken });

      assert.equal(certDeleteQueries.length, 2);
      assert.equal(certDeleteQueries[0].scanId.toString(), scanId.toString());
      assert.equal(certDeleteQueries[0].leaseToken, leaseToken);
      assert.deepEqual(certDeleteQueries[1].leaseToken, { $ne: leaseToken });
    } finally {
      globalThis.fetch = originalFetch;
      ScanModel.findOne = originalFindOne;
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
      FindingModel.deleteMany = originalDeleteMany;
      CertificateModel.deleteMany = originalCertificateDeleteMany;
      FindingModel.insertMany = originalInsertMany;
    }
  });

  // --------------------------------------------------------------------------
  // Scenario 6: Retry counter and maximum retry enforcement
  // --------------------------------------------------------------------------
  it('Scenario 6: Transient errors re-queue when retryCount < 3 and mark FAILED when retryCount reaches 3', async () => {
    const worker = new ScanWorkerService('retry-enforcer');
    const scanId = new mongoose.Types.ObjectId();
    const leaseToken = 'lease-retry-test';

    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;
    let lastUpdate: any = null;

    (ScanModel as any).findOneAndUpdate = async (q: any, update: any) => {
      lastUpdate = update;
      return { _id: scanId, ...update.$set };
    };

    try {
      // 1. Transient error with retryCount = 1 -> should re-queue
      const transientScanDoc: any = {
        _id: scanId,
        submittedUrl: 'https://flaky-server.com',
        leaseToken,
        retryCount: 1,
      };
      await worker.handleJobError(transientScanDoc, new Error('Gateway Timeout 504'));
      assert.equal(lastUpdate.$set.status, ScanStatusEnum.QUEUED);
      assert.equal(lastUpdate.$inc.retryCount, 1);

      // 2. Transient error with retryCount = 2 (2 + 1 = 3 >= MAX_RETRIES) -> should fail
      const terminalScanDoc: any = {
        _id: scanId,
        submittedUrl: 'https://flaky-server.com',
        leaseToken,
        retryCount: 2,
      };
      await worker.handleJobError(terminalScanDoc, new Error('Gateway Timeout 504'));
      assert.equal(lastUpdate.$set.status, ScanStatusEnum.FAILED);
      assert.match(lastUpdate.$set.errorMessage, /Gateway Timeout 504/);
    } finally {
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
    }
  });

  // --------------------------------------------------------------------------
  // Scenario 7: Concurrent duplicate submissions (Database partial unique index E11000)
  // --------------------------------------------------------------------------
  it('Scenario 7: Concurrent duplicate submissions catching E11000 gracefully return existing active scan', async () => {
    const app = buildServer();
    const existingActiveId = new mongoose.Types.ObjectId();
    const testUrl = 'https://race-condition-target.com/login';

    const originalFindOne = ScanModel.findOne;
    const originalCreate = ScanModel.create;

    // Simulate findOne returning null on check
    let findOneCallCount = 0;
    (ScanModel as any).findOne = () => ({
      lean: async () => {
        findOneCallCount++;
        if (findOneCallCount === 1) {
          // Pre-flight check sees no duplicate initially
          return null;
        }
        // Second lookup after catching E11000 returns the winning active scan
        return {
          _id: existingActiveId,
          submittedUrl: testUrl,
          normalizedDomain: 'race-condition-target.com',
          status: ScanStatusEnum.QUEUED,
          createdAt: new Date(),
        };
      },
    });

    // Simulate MongoDB unique index duplicate key error (E11000)
    (ScanModel as any).create = async () => {
      const duplicateError: any = new Error('E11000 duplicate key error collection: sentrix.scans index: urlHash_1');
      duplicateError.code = 11000;
      throw duplicateError;
    };

    try {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/scans',
        payload: { url: testUrl },
      });

      assert.equal(res.statusCode, 200);
      const body = JSON.parse(res.body);
      assert.equal(body.isDuplicate, true);
      assert.equal(body.scanId, existingActiveId.toString());
      assert.equal(body.status, ScanStatusEnum.QUEUED);
    } finally {
      ScanModel.findOne = originalFindOne;
      ScanModel.create = originalCreate;
      await app.close();
    }
  });

  // --------------------------------------------------------------------------
  // Scenario 8: Temporary MongoDB disconnection without process crash
  // --------------------------------------------------------------------------
  it('Scenario 8: Database disconnection during error handling is caught without unhandled rejection', async () => {
    const worker = new ScanWorkerService('db-outage-worker');
    const scanId = new mongoose.Types.ObjectId();

    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;
    // Simulate MongoDB throwing connection error during error handler write
    (ScanModel as any).findOneAndUpdate = async () => {
      throw new Error('MongoServerSelectionError: connection refused to 127.0.0.1:27017');
    };

    try {
      const mockScanDoc: any = {
        _id: scanId,
        submittedUrl: 'https://target.com',
        leaseToken: 'lease-123',
        retryCount: 0,
      };

      // Must not throw or produce an unhandled rejection
      await assert.doesNotReject(async () => {
        await worker.handleJobError(mockScanDoc, new Error('Scanner service timeout'));
      });
    } finally {
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
    }
  });

  // --------------------------------------------------------------------------
  // Scenario 9: Graceful shutdown with active jobs
  // --------------------------------------------------------------------------
  it('Scenario 9: Graceful shutdown stops new claims and drains active in-flight jobs', async () => {
    const worker = new ScanWorkerService('shutdown-tester');
    worker.start();
    assert.equal(worker.isWorkerRunning(), true);

    // Simulate 1 active in-flight job
    (worker as any).activeJobs = 1;

    // Simulate in-flight job completing after 150ms
    setTimeout(() => {
      (worker as any).activeJobs = 0;
    }, 150);

    const startTime = Date.now();
    await worker.stop();
    const duration = Date.now() - startTime;

    assert.equal(worker.isWorkerRunning(), false, 'Worker must not be running after stop()');
    assert.equal(worker.getActiveJobsCount(), 0, 'Active jobs must drain to 0');
    assert.ok(duration >= 100, 'Shutdown must have waited for active jobs to drain');
  });

  // --------------------------------------------------------------------------
  // Scenario 10: Maximum timeout recovery and FAILED transition
  // --------------------------------------------------------------------------
  it('Scenario 10: Stale job exceeding 60s with retryCount >= 2 transitions to FAILED', async () => {
    const worker = new ScanWorkerService('terminal-reaper');
    const scanId = new mongoose.Types.ObjectId();
    const staleScan = {
      _id: scanId,
      status: ScanStatusEnum.PROCESSING,
      leaseToken: 'token-timeout-exceeded',
      claimedAt: new Date(Date.now() - 100_000), // > 60s
      retryCount: 2, // 2 + 1 = 3 -> terminal failure
    };

    const originalFind = ScanModel.find;
    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;

    (ScanModel as any).find = () => ({
      limit: async () => [staleScan],
    });

    let terminalUpdate: any = null;
    (ScanModel as any).findOneAndUpdate = async (condition: any, update: any) => {
      terminalUpdate = update;
      return { _id: scanId, ...update.$set };
    };

    try {
      const recoveredCount = await worker.recoverAbandonedJobs(60_000);

      assert.equal(recoveredCount, 1);
      assert.notEqual(terminalUpdate, null);
      assert.equal(terminalUpdate.$set.status, ScanStatusEnum.FAILED);
      assert.match(terminalUpdate.$set.errorMessage, /timeout ceiling/);
      assert.ok(terminalUpdate.$set.completedAt instanceof Date);
    } finally {
      ScanModel.find = originalFind;
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
    }
  });

  // --------------------------------------------------------------------------
  // Additional API Endpoint & Contract Tests
  // --------------------------------------------------------------------------
  it('POST /api/v1/scans immediately returns HTTP 201 with QUEUED status', async () => {
    const app = buildServer();
    const fakeScanId = new mongoose.Types.ObjectId();
    const testUrl = 'https://phishing-portal.malicious-domain.test/login';

    const originalFindOne = ScanModel.findOne;
    const originalCreate = ScanModel.create;
    const originalTrigger = scanWorker.trigger;

    let triggerCalled = false;
    scanWorker.trigger = () => {
      triggerCalled = true;
    };

    (ScanModel as any).findOne = () => ({
      lean: async () => null,
    });

    (ScanModel as any).create = async (doc: any) => ({
      _id: fakeScanId,
      ...doc,
      createdAt: new Date(),
    });

    try {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/scans',
        payload: { url: testUrl },
      });

      assert.equal(res.statusCode, 201);
      const body = JSON.parse(res.body);
      assert.equal(body.scanId, fakeScanId.toString());
      assert.equal(body.status, ScanStatusEnum.QUEUED);
      assert.equal(body.normalizedDomain, 'phishing-portal.malicious-domain.test');
      assert.equal(triggerCalled, true);
    } finally {
      ScanModel.findOne = originalFindOne;
      ScanModel.create = originalCreate;
      scanWorker.trigger = originalTrigger;
      await app.close();
    }
  });

  it('GET /api/v1/scans/:id/results returns status and in-flight information while PROCESSING', async () => {
    const app = buildServer();
    const scanId = new mongoose.Types.ObjectId();

    const originalFindById = ScanModel.findById;
    (ScanModel as any).findById = () => ({
      lean: async () => ({
        _id: scanId,
        status: ScanStatusEnum.PROCESSING,
        submittedUrl: 'https://in-flight.com',
        normalizedDomain: 'in-flight.com',
        createdAt: new Date(),
        analyzerStatuses: {
          dns: 'COMPLETED',
          tls: 'IN_PROGRESS',
        },
      }),
    });

    try {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/scans/${scanId}/results`,
      });

      assert.equal(res.statusCode, 200);
      const body = JSON.parse(res.body);
      assert.equal(body.scanId, scanId.toString());
      assert.equal(body.status, ScanStatusEnum.PROCESSING);
      assert.equal(body.message, 'Scan is currently in progress');
    } finally {
      ScanModel.findById = originalFindById;
      await app.close();
    }
  });

  it('GET /api/v1/scans/:id/results returns full findings and certificate when COMPLETED', async () => {
    const app = buildServer();
    const scanId = new mongoose.Types.ObjectId();

    const originalScanFindById = ScanModel.findById;
    const originalFindingFind = FindingModel.find;
    const originalCertFindOne = CertificateModel.findOne;

    (ScanModel as any).findById = () => ({
      lean: async () => ({
        _id: scanId,
        status: ScanStatusEnum.COMPLETED,
        submittedUrl: 'https://completed-target.com',
        normalizedDomain: 'completed-target.com',
        verdict: 'MALICIOUS',
        riskScore: 92,
        confidence: 96,
        analysisStatus: 'COMPLETE',
        completedAt: new Date(),
        summary: { threatTypes: ['MALWARE'] },
      }),
    });

    (FindingModel as any).find = () => ({
      sort: () => ({
        lean: async () => [
          {
            _id: new mongoose.Types.ObjectId(),
            category: 'HEURISTIC',
            severity: 'CRITICAL',
            title: 'Malware dropper script detected',
          },
        ],
      }),
    });

    (CertificateModel as any).findOne = () => ({
      lean: async () => ({
        _id: new mongoose.Types.ObjectId(),
        issuer: 'Fake Issuer CA',
        fingerprint: 'sha256:112233',
      }),
    });

    try {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/scans/${scanId}/results`,
      });

      assert.equal(res.statusCode, 200);
      const body = JSON.parse(res.body);
      assert.equal(body.status, ScanStatusEnum.COMPLETED);
      assert.equal(body.verdict, 'MALICIOUS');
      assert.equal(body.riskScore, 92);
      assert.equal(body.findings.length, 1);
    } finally {
      ScanModel.findById = originalScanFindById;
      FindingModel.find = originalFindingFind;
      CertificateModel.findOne = originalCertFindOne;
      await app.close();
    }
  });

  it('GET /api/v1/reports/:id rejects invalid ObjectId format with HTTP 400 VALIDATION_ERROR', async () => {
    const app = buildServer();

    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/reports/malformed-not-an-id',
    });

    assert.equal(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert.equal(body.error, 'VALIDATION_ERROR');
    assert.match(body.message, /Invalid report ID format/);

    await app.close();
  });

  it('Permanent SSRF errors immediately transition to FAILED with 0 retries', async () => {
    const worker = new ScanWorkerService('ssrf-guard-tester');
    const scanId = new mongoose.Types.ObjectId();
    const leaseToken = 'lease-ssrf-1';

    const ssrfError = new ScannerClientError(
      'Target URL rejected due to security policy (SSRF / restricted network)',
      400
    );

    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;
    let updatedScan: any = null;

    (ScanModel as any).findOneAndUpdate = async (q: any, update: any) => {
      updatedScan = update;
      return { _id: scanId, ...update.$set };
    };

    try {
      const mockScanDoc: any = {
        _id: scanId,
        submittedUrl: 'http://169.254.169.254/metadata',
        leaseToken,
        retryCount: 0,
      };

      await worker.handleJobError(mockScanDoc, ssrfError);

      assert.notEqual(updatedScan, null);
      assert.equal(updatedScan.$set.status, ScanStatusEnum.FAILED);
      assert.match(updatedScan.$set.errorMessage, /SSRF/);
      assert.equal(updatedScan.$inc.retryCount, 0, 'Permanent errors must not increment retryCount');
    } finally {
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
    }
  });

  // ==========================================================================
  // Phase 4 Final Reliability: Attempt-Scoped Result Persistence & Zombie Worker Safety
  // ==========================================================================

  // Regression Test 1: Stale worker cannot delete new results
  it('Regression 1: Stale worker cannot delete newer worker results (attempt-scoped cleanup)', async () => {
    const scanId = new mongoose.Types.ObjectId();
    const tokenA = 'stale-token-A';
    const tokenB = 'new-valid-token-B';

    // Mock in-memory findings and certificates
    let findingDocs = [
      { scanId, leaseToken: tokenB, title: 'Valid Worker B finding' },
    ];
    let certDocs = [
      { scanId, leaseToken: tokenB, issuer: 'Worker B CA' },
    ];

    const originalFindingDeleteMany = FindingModel.deleteMany;
    const originalCertDeleteMany = CertificateModel.deleteMany;

    (FindingModel as any).deleteMany = async (filter: any) => {
      findingDocs = findingDocs.filter((d) => {
        if (filter.scanId && d.scanId.toString() !== filter.scanId.toString()) return true;
        if (filter.leaseToken && d.leaseToken !== filter.leaseToken) return true;
        return false;
      });
      return { acknowledged: true };
    };

    (CertificateModel as any).deleteMany = async (filter: any) => {
      certDocs = certDocs.filter((d) => {
        if (filter.scanId && d.scanId.toString() !== filter.scanId.toString()) return true;
        if (filter.leaseToken && d.leaseToken !== filter.leaseToken) return true;
        return false;
      });
      return { acknowledged: true };
    };

    try {
      // Stale Worker A attempts cleanup with tokenA
      await FindingModel.deleteMany({ scanId, leaseToken: tokenA });
      await CertificateModel.deleteMany({ scanId, leaseToken: tokenA });

      // Worker B's artifacts must remain intact
      assert.equal(findingDocs.length, 1);
      assert.equal(findingDocs[0].leaseToken, tokenB);
      assert.equal(certDocs.length, 1);
      assert.equal(certDocs[0].leaseToken, tokenB);
    } finally {
      FindingModel.deleteMany = originalFindingDeleteMany;
      CertificateModel.deleteMany = originalCertDeleteMany;
    }
  });

  // Regression Test 2: Stale worker cannot publish results
  it('Regression 2: Stale worker cannot publish results (fenced atomic update returns null)', async () => {
    const scanId = new mongoose.Types.ObjectId();
    const activeLeaseToken = 'active-token-B';
    const staleLeaseToken = 'stale-token-A';

    // DB state has activeLeaseToken
    const dbScan = {
      _id: scanId,
      leaseToken: activeLeaseToken,
      status: ScanStatusEnum.PROCESSING,
    };

    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;
    let rollbackCalled = false;
    const originalFindingDeleteMany = FindingModel.deleteMany;
    const originalCertDeleteMany = CertificateModel.deleteMany;

    (ScanModel as any).findOneAndUpdate = async (filter: any, update: any) => {
      if (
        filter._id.toString() === dbScan._id.toString() &&
        filter.leaseToken === dbScan.leaseToken &&
        filter.status === dbScan.status
      ) {
        return { ...dbScan, ...update.$set };
      }
      return null;
    };

    (FindingModel as any).deleteMany = async (filter: any) => {
      if (filter.leaseToken === staleLeaseToken) {
        rollbackCalled = true;
      }
      return { acknowledged: true };
    };
    (CertificateModel as any).deleteMany = async () => ({ acknowledged: true });

    const worker = new ScanWorkerService('stale-worker-a');
    const originalFetch = globalThis.fetch;
    const originalFindOne = ScanModel.findOne;

    (ScanModel as any).findOne = () => ({
      lean: async () => ({ _id: scanId, leaseToken: staleLeaseToken, status: ScanStatusEnum.PROCESSING }),
    });

    globalThis.fetch = async () =>
      ({
        ok: true,
        status: 200,
        json: async () => ({
          scanId: scanId.toString(),
          riskScore: 50,
          verdict: 'SUSPICIOUS',
          findings: [{ title: 'Stale Finding', category: 'HEURISTIC', severity: 'MEDIUM', confidence: 70 }],
        }),
      } as any);

    try {
      const staleScanDoc: any = {
        _id: scanId,
        submittedUrl: 'https://stale-worker.com',
        normalizedDomain: 'stale-worker.com',
        leaseToken: staleLeaseToken,
      };

      await worker.executeJob(staleScanDoc);

      // Verify that rollback was called for stale worker's own attempt and publication was rejected
      assert.equal(rollbackCalled, true);
    } finally {
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
      ScanModel.findOne = originalFindOne;
      FindingModel.deleteMany = originalFindingDeleteMany;
      CertificateModel.deleteMany = originalCertDeleteMany;
      globalThis.fetch = originalFetch;
    }
  });

  // Regression Test 3: Stale worker cannot replace current results
  it('Regression 3: Stale worker cannot replace current results or overwrite publishedLeaseToken', async () => {
    const scanId = new mongoose.Types.ObjectId();
    const winningToken = 'winning-token-B';
    const staleToken = 'stale-token-A';

    let dbState: any = {
      _id: scanId,
      status: ScanStatusEnum.COMPLETED,
      publishedLeaseToken: winningToken,
      riskScore: 90,
      verdict: 'MALICIOUS',
    };

    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;
    const originalFindOne = ScanModel.findOne;

    (ScanModel as any).findOne = () => ({
      lean: async () => (dbState.status === ScanStatusEnum.PROCESSING ? dbState : null),
    });

    (ScanModel as any).findOneAndUpdate = async (filter: any, update: any) => {
      if (
        filter._id.toString() === dbState._id.toString() &&
        filter.leaseToken === winningToken &&
        filter.status === ScanStatusEnum.PROCESSING
      ) {
        dbState = { ...dbState, ...update.$set };
        return dbState;
      }
      return null;
    };

    const worker = new ScanWorkerService('stale-zombie');
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      ({
        ok: true,
        status: 200,
        json: async () => ({
          scanId: scanId.toString(),
          riskScore: 10,
          verdict: 'BENIGN',
          findings: [],
        }),
      } as any);

    try {
      await worker.executeJob({
        _id: scanId,
        submittedUrl: 'https://target.com',
        normalizedDomain: 'target.com',
        leaseToken: staleToken,
      } as any);

      // Verify state was never replaced
      assert.equal(dbState.status, ScanStatusEnum.COMPLETED);
      assert.equal(dbState.publishedLeaseToken, winningToken);
      assert.equal(dbState.riskScore, 90);
      assert.equal(dbState.verdict, 'MALICIOUS');
    } finally {
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
      ScanModel.findOne = originalFindOne;
      globalThis.fetch = originalFetch;
    }
  });

  // Regression Test 4: Crash during persistence
  it('Regression 4: Crash during persistence leaves incomplete attempt results unpublished', async () => {
    const app = buildServer();
    const scanId = new mongoose.Types.ObjectId();
    const crashingToken = 'crashing-token-123';

    // Scan remains in PROCESSING state in DB
    const originalScanFindById = ScanModel.findById;
    (ScanModel as any).findById = () => ({
      lean: async () => ({
        _id: scanId,
        status: ScanStatusEnum.PROCESSING,
        submittedUrl: 'https://crashed-persistence.com',
        normalizedDomain: 'crashed-persistence.com',
        leaseToken: crashingToken,
        createdAt: new Date(),
      }),
    });

    try {
      // Reader calls results endpoint while persistence crashed / scan never reached COMPLETED
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/scans/${scanId}/results`,
      });

      assert.equal(res.statusCode, 200);
      const body = JSON.parse(res.body);
      assert.equal(body.status, ScanStatusEnum.PROCESSING);
      assert.equal(body.message, 'Scan is currently in progress');
      assert.equal(body.findings, undefined); // Incomplete findings are not exposed
    } finally {
      ScanModel.findById = originalScanFindById;
      await app.close();
    }
  });

  // Regression Test 5: Retry result isolation
  it('Regression 5: Retry result isolation ensures readers query only winning publishedLeaseToken', async () => {
    const app = buildServer();
    const scanId = new mongoose.Types.ObjectId();
    const attempt1Token = 'attempt-1-failed-token';
    const winningToken = 'attempt-2-winning-token';

    const originalScanFindById = ScanModel.findById;
    const originalFindingFind = FindingModel.find;
    const originalCertFindOne = CertificateModel.findOne;

    let queriedFindingFilter: any = null;
    let queriedCertFilter: any = null;

    (ScanModel as any).findById = () => ({
      lean: async () => ({
        _id: scanId,
        status: ScanStatusEnum.COMPLETED,
        submittedUrl: 'https://retry-isolation.com',
        normalizedDomain: 'retry-isolation.com',
        publishedLeaseToken: winningToken,
        verdict: 'CLEAN',
        riskScore: 5,
        confidence: 95,
        completedAt: new Date(),
      }),
    });

    (FindingModel as any).find = (filter: any) => {
      queriedFindingFilter = filter;
      return {
        sort: () => ({
          lean: async () => [
            {
              scanId,
              leaseToken: winningToken,
              title: 'Attempt 2 Clean Finding',
              category: 'DOMAIN_REPUTATION',
              severity: 'INFORMATIONAL',
            },
          ],
        }),
      };
    };

    (CertificateModel as any).findOne = (filter: any) => {
      queriedCertFilter = filter;
      return {
        lean: async () => ({ scanId, leaseToken: winningToken, issuer: 'Valid CA' }),
      };
    };

    try {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/scans/${scanId}/results`,
      });

      assert.equal(res.statusCode, 200);
      const body = JSON.parse(res.body);
      assert.equal(body.status, ScanStatusEnum.COMPLETED);
      assert.equal(queriedFindingFilter.scanId, scanId.toString());
      assert.equal(queriedFindingFilter.leaseToken, winningToken);
      assert.notEqual(queriedFindingFilter.leaseToken, attempt1Token);
      assert.equal(queriedCertFilter.leaseToken, winningToken);
    } finally {
      ScanModel.findById = originalScanFindById;
      FindingModel.find = originalFindingFind;
      CertificateModel.findOne = originalCertFindOne;
      await app.close();
    }
  });

  // Regression Test 6: Concurrent publication race
  it('Regression 6: Concurrent publication race allows exactly one worker to publish and loser rolls back', async () => {
    const scanId = new mongoose.Types.ObjectId();
    const token1 = 'racing-worker-1';
    const token2 = 'racing-worker-2';

    let currentScanInDb = {
      _id: scanId,
      leaseToken: token1,
      status: ScanStatusEnum.PROCESSING,
      publishedLeaseToken: undefined as string | undefined,
    };

    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;
    let winnerPublished = 0;
    let loserRollbacks = 0;

    (ScanModel as any).findOneAndUpdate = async (filter: any, update: any) => {
      if (
        filter._id.toString() === currentScanInDb._id.toString() &&
        filter.leaseToken === currentScanInDb.leaseToken &&
        filter.status === ScanStatusEnum.PROCESSING
      ) {
        currentScanInDb = { ...currentScanInDb, ...update.$set, status: ScanStatusEnum.COMPLETED };
        winnerPublished++;
        return currentScanInDb;
      }
      return null;
    };

    const originalFindingDeleteMany = FindingModel.deleteMany;
    const originalCertDeleteMany = CertificateModel.deleteMany;

    (FindingModel as any).deleteMany = async (filter: any) => {
      if (filter.leaseToken === token2) {
        loserRollbacks++;
      }
      return { acknowledged: true };
    };
    (CertificateModel as any).deleteMany = async () => ({ acknowledged: true });

    // Worker 1 tries to commit
    const result1 = await ScanModel.findOneAndUpdate(
      { _id: scanId, leaseToken: token1, status: ScanStatusEnum.PROCESSING },
      { $set: { status: ScanStatusEnum.COMPLETED, publishedLeaseToken: token1 } },
      { new: true }
    );

    // Worker 2 tries to commit concurrently
    const result2 = await ScanModel.findOneAndUpdate(
      { _id: scanId, leaseToken: token2, status: ScanStatusEnum.PROCESSING },
      { $set: { status: ScanStatusEnum.COMPLETED, publishedLeaseToken: token2 } },
      { new: true }
    );

    if (!result2) {
      // Worker 2 rollback
      await FindingModel.deleteMany({ scanId, leaseToken: token2 });
    }

    try {
      assert.notEqual(result1, null);
      assert.equal(result2, null);
      assert.equal(winnerPublished, 1);
      assert.equal(loserRollbacks, 1);
      assert.equal(currentScanInDb.publishedLeaseToken, token1);
      assert.equal(currentScanInDb.status, ScanStatusEnum.COMPLETED);
    } finally {
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
      FindingModel.deleteMany = originalFindingDeleteMany;
      CertificateModel.deleteMany = originalCertDeleteMany;
    }
  });

  // Regression Test 7: Attempt-scoped cleanup
  it('Regression 7: Attempt-scoped cleanup deletes only token-A artifacts and preserves token-B', async () => {
    const scanId = new mongoose.Types.ObjectId();
    const tokenA = 'attempt-A';
    const tokenB = 'attempt-B';

    let findings = [
      { id: 1, scanId, leaseToken: tokenA },
      { id: 2, scanId, leaseToken: tokenA },
      { id: 3, scanId, leaseToken: tokenB },
    ];
    let certificates = [
      { id: 101, scanId, leaseToken: tokenA },
      { id: 102, scanId, leaseToken: tokenB },
    ];

    const originalFindingDeleteMany = FindingModel.deleteMany;
    const originalCertDeleteMany = CertificateModel.deleteMany;

    (FindingModel as any).deleteMany = async (filter: any) => {
      findings = findings.filter(
        (f) => !(f.scanId.toString() === filter.scanId.toString() && f.leaseToken === filter.leaseToken)
      );
      return { acknowledged: true };
    };

    (CertificateModel as any).deleteMany = async (filter: any) => {
      certificates = certificates.filter(
        (c) => !(c.scanId.toString() === filter.scanId.toString() && c.leaseToken === filter.leaseToken)
      );
      return { acknowledged: true };
    };

    try {
      // Attempt A cleans up its own artifacts
      await FindingModel.deleteMany({ scanId, leaseToken: tokenA });
      await CertificateModel.deleteMany({ scanId, leaseToken: tokenA });

      // Findings & certs for Attempt B must still exist
      assert.equal(findings.length, 1);
      assert.equal(findings[0].leaseToken, tokenB);
      assert.equal(certificates.length, 1);
      assert.equal(certificates[0].leaseToken, tokenB);
    } finally {
      FindingModel.deleteMany = originalFindingDeleteMany;
      CertificateModel.deleteMany = originalCertDeleteMany;
    }
  });

  // Regression Test 8: Completed scan integrity
  it('Regression 8: Completed scan integrity cannot be modified by subsequent stale worker activity', async () => {
    const scanId = new mongoose.Types.ObjectId();
    const publishedToken = 'published-token-winner';
    const staleWorkerToken = 'stale-worker-late';

    const completedScan = {
      _id: scanId,
      status: ScanStatusEnum.COMPLETED,
      publishedLeaseToken: publishedToken,
      verdict: 'MALICIOUS',
      riskScore: 88,
    };

    const originalFindOne = ScanModel.findOne;
    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;
    const originalFindingDeleteMany = FindingModel.deleteMany;

    let deleteCalled = false;
    let updateCalled = false;

    (ScanModel as any).findOne = () => ({
      // findOne checks status: PROCESSING and leaseToken: staleWorkerToken
      lean: async () => null, // Scan is already COMPLETED, so query returns null
    });

    (ScanModel as any).findOneAndUpdate = async () => {
      updateCalled = true;
      return null;
    };

    (FindingModel as any).deleteMany = async () => {
      deleteCalled = true;
      return { acknowledged: true };
    };

    const worker = new ScanWorkerService('stale-late-worker');
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      ({
        ok: true,
        status: 200,
        json: async () => ({
          scanId: scanId.toString(),
          riskScore: 0,
          verdict: 'BENIGN',
          findings: [],
        }),
      } as any);

    try {
      await worker.executeJob({
        _id: scanId,
        submittedUrl: 'https://completed-integrity.com',
        normalizedDomain: 'completed-integrity.com',
        leaseToken: staleWorkerToken,
      } as any);

      // Pre-write check failed: executeJob returned early without modifying scan or deleting findings
      assert.equal(deleteCalled, false, 'Stale worker must not call deleteMany when lease check fails');
      assert.equal(updateCalled, false, 'Stale worker must not call findOneAndUpdate when lease check fails');
      assert.equal(completedScan.status, ScanStatusEnum.COMPLETED);
      assert.equal(completedScan.publishedLeaseToken, publishedToken);
    } finally {
      ScanModel.findOne = originalFindOne;
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
      FindingModel.deleteMany = originalFindingDeleteMany;
      globalThis.fetch = originalFetch;
    }
  });
});
