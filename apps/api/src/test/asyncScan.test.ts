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

describe('SENTRIX Asynchronous Background Scanning Architecture Tests', () => {
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
      assert.equal(triggerCalled, true, 'Worker trigger must be signaled upon scan creation');
    } finally {
      ScanModel.findOne = originalFindOne;
      ScanModel.create = originalCreate;
      scanWorker.trigger = originalTrigger;
      await app.close();
    }
  });

  it('POST /api/v1/scans detects active duplicate submission within window and returns existing scanId', async () => {
    const app = buildServer();
    const existingScanId = new mongoose.Types.ObjectId();
    const testUrl = 'https://active-submission.com/path';

    const originalFindOne = ScanModel.findOne;
    const originalCreate = ScanModel.create;

    let createCalled = false;
    (ScanModel as any).create = async () => {
      createCalled = true;
    };

    (ScanModel as any).findOne = () => ({
      lean: async () => ({
        _id: existingScanId,
        submittedUrl: 'https://active-submission.com/path',
        normalizedDomain: 'active-submission.com',
        status: ScanStatusEnum.PROCESSING,
        createdAt: new Date(),
      }),
    });

    try {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/scans',
        payload: { url: testUrl },
      });

      assert.equal(res.statusCode, 200);
      const body = JSON.parse(res.body);
      assert.equal(body.isDuplicate, true);
      assert.equal(body.scanId, existingScanId.toString());
      assert.equal(body.status, ScanStatusEnum.PROCESSING);
      assert.equal(createCalled, false, 'Should not create new scan record when active scan exists');
    } finally {
      ScanModel.findOne = originalFindOne;
      ScanModel.create = originalCreate;
      await app.close();
    }
  });

  it('ScanWorkerService.claimNextJob atomically claims QUEUED jobs using FIFO ordering', async () => {
    const worker = new ScanWorkerService('test-worker-alpha');
    const mockScanId = new mongoose.Types.ObjectId();

    const originalFindOneAndUpdate = ScanModel.findOneAndUpdate;
    let recordedQuery: any = null;
    let recordedUpdate: any = null;
    let recordedOpts: any = null;

    (ScanModel as any).findOneAndUpdate = async (query: any, update: any, opts: any) => {
      recordedQuery = query;
      recordedUpdate = update;
      recordedOpts = opts;
      return {
        _id: mockScanId,
        submittedUrl: 'https://test-claim.com',
        status: ScanStatusEnum.PROCESSING,
        workerId: worker.getWorkerId(),
        retryCount: 0,
      };
    };

    try {
      const claimed = await worker.claimNextJob();

      assert.notEqual(claimed, null);
      assert.equal(claimed?._id.toString(), mockScanId.toString());

      // Verify atomic FIFO claim contract
      assert.equal(recordedQuery.status, ScanStatusEnum.QUEUED);
      assert.deepEqual(recordedQuery.retryCount, { $lt: MAX_RETRIES });
      assert.equal(recordedUpdate.$set.status, ScanStatusEnum.PROCESSING);
      assert.equal(recordedUpdate.$set.workerId, 'test-worker-alpha');
      assert.ok(recordedUpdate.$set.claimedAt instanceof Date);
      assert.deepEqual(recordedOpts.sort, { createdAt: 1 }, 'Must enforce FIFO ordering');
      assert.equal(recordedOpts.new, true);
    } finally {
      ScanModel.findOneAndUpdate = originalFindOneAndUpdate;
    }
  });

  it('ScanWorkerService.executeJob performs idempotent cleanup, persists findings, and marks scan COMPLETED', async () => {
    const worker = new ScanWorkerService('test-worker-beta');
    const scanId = new mongoose.Types.ObjectId();
    const mockScanDoc: any = {
      _id: scanId,
      submittedUrl: 'https://malicious-target.com',
      normalizedDomain: 'malicious-target.com',
      retryCount: 0,
    };

    const originalFetch = globalThis.fetch;
    const originalFindingDeleteMany = FindingModel.deleteMany;
    const originalCertDeleteOne = CertificateModel.deleteOne;
    const originalFindingInsertMany = FindingModel.insertMany;
    const originalCertCreate = CertificateModel.create;
    const originalScanFindByIdAndUpdate = ScanModel.findByIdAndUpdate;

    let deletedFindingsScanId: any = null;
    let deletedCertScanId: any = null;
    let insertedFindings: any[] = [];
    let createdCert: any = null;
    let updatedScan: any = null;

    (FindingModel as any).deleteMany = async (query: any) => {
      deletedFindingsScanId = query.scanId;
      return { acknowledged: true, deletedCount: 0 };
    };

    (CertificateModel as any).deleteOne = async (query: any) => {
      deletedCertScanId = query.scanId;
      return { acknowledged: true, deletedCount: 0 };
    };

    (FindingModel as any).insertMany = async (docs: any[]) => {
      insertedFindings = docs;
      return docs;
    };

    (CertificateModel as any).create = async (doc: any) => {
      createdCert = doc;
      return doc;
    };

    (ScanModel as any).findByIdAndUpdate = async (id: any, update: any) => {
      updatedScan = { id, update };
      return { _id: id };
    };

    // Mock scanner HTTP response
    globalThis.fetch = async () => {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          scanId: scanId.toString(),
          riskScore: 88,
          verdict: 'MALICIOUS',
          confidence: 95,
          analysisStatus: 'COMPLETE',
          analysisComplete: true,
          analyzerStatuses: {
            dns: 'COMPLETED',
            tls: 'COMPLETED',
            web_security: 'COMPLETED',
            heuristic: 'COMPLETED',
            threat_intel: 'COMPLETED',
          },
          findings: [
            {
              category: 'HEURISTIC',
              severity: 'CRITICAL',
              title: 'Credential harvesting form detected',
              description: 'Forms submit to external untrusted endpoints',
              confidence: 90,
            },
          ],
          certificate: {
            issuer: 'Let Encrypt Authority',
            subject: 'malicious-target.com',
            validFrom: '2026-01-01T00:00:00Z',
            validUntil: '2026-04-01T00:00:00Z',
            fingerprint: 'sha256:abc12345',
            hostnameMatched: true,
          },
          summary: {
            threatTypes: ['PHISHING'],
            riskFactors: ['Form action mismatch'],
          },
        }),
      } as any;
    };

    try {
      await worker.executeJob(mockScanDoc);

      // 1. Verify idempotent cleanup occurred first
      assert.equal(deletedFindingsScanId.toString(), scanId.toString());
      assert.equal(deletedCertScanId.toString(), scanId.toString());

      // 2. Verify findings persisted
      assert.equal(insertedFindings.length, 1);
      assert.equal(insertedFindings[0].title, 'Credential harvesting form detected');
      assert.equal(insertedFindings[0].severity, 'CRITICAL');

      // 3. Verify certificate persisted
      assert.notEqual(createdCert, null);
      assert.equal(createdCert.issuer, 'Let Encrypt Authority');

      // 4. Verify scan marked COMPLETED
      assert.notEqual(updatedScan, null);
      assert.equal(updatedScan.update.$set.status, ScanStatusEnum.COMPLETED);
      assert.equal(updatedScan.update.$set.verdict, 'MALICIOUS');
      assert.equal(updatedScan.update.$set.riskScore, 88);
      assert.equal(updatedScan.update.$set.analysisStatus, 'COMPLETE');
      assert.ok(updatedScan.update.$set.completedAt instanceof Date);
    } finally {
      globalThis.fetch = originalFetch;
      FindingModel.deleteMany = originalFindingDeleteMany;
      CertificateModel.deleteOne = originalCertDeleteOne;
      FindingModel.insertMany = originalFindingInsertMany;
      CertificateModel.create = originalCertCreate;
      ScanModel.findByIdAndUpdate = originalScanFindByIdAndUpdate;
    }
  });

  it('ScanWorkerService differentiates permanent SSRF errors and marks FAILED without retry', async () => {
    const worker = new ScanWorkerService('test-worker-gamma');
    const scanId = new mongoose.Types.ObjectId();
    const mockScanDoc: any = {
      _id: scanId,
      submittedUrl: 'http://169.254.169.254/metadata',
      retryCount: 0,
    };

    const ssrfError = new ScannerClientError(
      'Target URL rejected due to security policy (SSRF / restricted network)',
      400
    );

    const originalScanFindByIdAndUpdate = ScanModel.findByIdAndUpdate;
    let updatedScan: any = null;

    (ScanModel as any).findByIdAndUpdate = async (id: any, update: any) => {
      updatedScan = { id, update };
      return { _id: id };
    };

    try {
      await worker.handleJobError(mockScanDoc, ssrfError);

      assert.notEqual(updatedScan, null);
      // Permanent failure must immediately transition to FAILED
      assert.equal(updatedScan.update.$set.status, ScanStatusEnum.FAILED);
      assert.match(updatedScan.update.$set.errorMessage, /SSRF/);
      assert.equal(updatedScan.update.$inc.retryCount, 0, 'Permanent errors must not increment retryCount');
    } finally {
      ScanModel.findByIdAndUpdate = originalScanFindByIdAndUpdate;
    }
  });

  it('ScanWorkerService re-queues transient errors when retryCount < MAX_RETRIES', async () => {
    const worker = new ScanWorkerService('test-worker-delta');
    const scanId = new mongoose.Types.ObjectId();
    const mockScanDoc: any = {
      _id: scanId,
      submittedUrl: 'https://transient-flake.com',
      retryCount: 1, // retry count is 1 (< 3)
    };

    const transientError = new ScannerClientError('Scanner analysis request timed out', 504);

    const originalScanFindByIdAndUpdate = ScanModel.findByIdAndUpdate;
    let updatedScan: any = null;

    (ScanModel as any).findByIdAndUpdate = async (id: any, update: any) => {
      updatedScan = { id, update };
      return { _id: id };
    };

    try {
      await worker.handleJobError(mockScanDoc, transientError);

      assert.notEqual(updatedScan, null);
      // Transient error must re-queue with QUEUED status and increment retryCount
      assert.equal(updatedScan.update.$set.status, ScanStatusEnum.QUEUED);
      assert.match(updatedScan.update.$set.lastError, /timed out/);
      assert.equal(updatedScan.update.$inc.retryCount, 1);
    } finally {
      ScanModel.findByIdAndUpdate = originalScanFindByIdAndUpdate;
    }
  });

  it('ScanWorkerService marks scan FAILED when retryCount reaches MAX_RETRIES', async () => {
    const worker = new ScanWorkerService('test-worker-epsilon');
    const scanId = new mongoose.Types.ObjectId();
    const mockScanDoc: any = {
      _id: scanId,
      submittedUrl: 'https://always-fails.com',
      retryCount: 2, // 2 + 1 = 3 >= MAX_RETRIES
    };

    const transientError = new Error('Connection reset by peer');

    const originalScanFindByIdAndUpdate = ScanModel.findByIdAndUpdate;
    let updatedScan: any = null;

    (ScanModel as any).findByIdAndUpdate = async (id: any, update: any) => {
      updatedScan = { id, update };
      return { _id: id };
    };

    try {
      await worker.handleJobError(mockScanDoc, transientError);

      assert.notEqual(updatedScan, null);
      assert.equal(updatedScan.update.$set.status, ScanStatusEnum.FAILED);
      assert.match(updatedScan.update.$set.errorMessage, /Connection reset/);
    } finally {
      ScanModel.findByIdAndUpdate = originalScanFindByIdAndUpdate;
    }
  });

  it('ScanWorkerService.recoverAbandonedJobs re-queues stale PROCESSING jobs', async () => {
    const worker = new ScanWorkerService('test-worker-reaper');
    const staleJob1 = {
      _id: new mongoose.Types.ObjectId(),
      status: ScanStatusEnum.PROCESSING,
      retryCount: 0,
      claimedAt: new Date(Date.now() - 120_000), // 2 min ago
    };
    const staleJob2 = {
      _id: new mongoose.Types.ObjectId(),
      status: ScanStatusEnum.PROCESSING,
      retryCount: 2, // 2 + 1 = 3 -> exceeds max
      claimedAt: new Date(Date.now() - 120_000),
    };

    const originalFind = ScanModel.find;
    const originalFindByIdAndUpdate = ScanModel.findByIdAndUpdate;

    (ScanModel as any).find = () => ({
      limit: async () => [staleJob1, staleJob2],
    });

    const updates: any[] = [];
    (ScanModel as any).findByIdAndUpdate = async (id: any, update: any) => {
      updates.push({ id, update });
      return { _id: id };
    };

    try {
      const recoveredCount = await worker.recoverAbandonedJobs(60_000);

      assert.equal(recoveredCount, 2);
      assert.equal(updates.length, 2);

      // Stale job 1 had retryCount 0 -> re-queued to QUEUED
      assert.equal(updates[0].id.toString(), staleJob1._id.toString());
      assert.equal(updates[0].update.$set.status, ScanStatusEnum.QUEUED);
      assert.equal(updates[0].update.$inc.retryCount, 1);

      // Stale job 2 had retryCount 2 -> marked as FAILED
      assert.equal(updates[1].id.toString(), staleJob2._id.toString());
      assert.equal(updates[1].update.$set.status, ScanStatusEnum.FAILED);
      assert.match(updates[1].update.$set.errorMessage, /timeout ceiling/);
    } finally {
      ScanModel.find = originalFind;
      ScanModel.findByIdAndUpdate = originalFindByIdAndUpdate;
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
      assert.equal(body.analyzerStatuses.dns, 'COMPLETED');
      assert.equal(body.analyzerStatuses.tls, 'IN_PROGRESS');
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
      assert.equal(body.findings[0].title, 'Malware dropper script detected');
      assert.equal(body.certificate.fingerprint, 'sha256:112233');
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
});
