import os from 'node:os';
import crypto from 'node:crypto';
import { FastifyInstance } from 'fastify';
import { ScanStatusEnum } from '@sentrix/shared';
import { ScanModel, IScanDocument } from '../models/Scan.js';
import { FindingModel } from '../models/Finding.js';
import { CertificateModel } from '../models/Certificate.js';
import { requestScannerAnalysis, ScannerClientError } from './scannerClient.js';

export const MAX_CONCURRENT_JOBS = 3;
export const MAX_RETRIES = 3;
export const JOB_TIMEOUT_MS = 60_000; // 60 seconds
export const POLL_INTERVAL_MS = 1_000; // 1 second
export const REAPER_INTERVAL_MS = 15_000; // 15 seconds

export class ScanWorkerService {
  private workerId: string;
  private isRunning = false;
  private activeJobs = 0;
  private pollTimer: NodeJS.Timeout | null = null;
  private reaperTimer: NodeJS.Timeout | null = null;
  private logger?: FastifyInstance['log'];

  constructor(workerId?: string) {
    this.workerId =
      workerId ||
      `worker_${os.hostname()}_${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
  }

  public getWorkerId(): string {
    return this.workerId;
  }

  public getActiveJobsCount(): number {
    return this.activeJobs;
  }

  public isWorkerRunning(): boolean {
    return this.isRunning;
  }

  /**
   * Starts the background queue worker and abandoned job recovery reaper.
   */
  public start(logger?: FastifyInstance['log']): void {
    if (this.isRunning) return;
    this.isRunning = true;
    this.logger = logger;

    this.logger?.info({ workerId: this.workerId }, 'Starting SENTRIX asynchronous scan worker');

    // Immediate initial tick
    this.scheduleNextTick(0);

    // Periodic stale job recovery
    this.reaperTimer = setInterval(() => {
      this.recoverAbandonedJobs().catch((err) => {
        this.logger?.error({ err }, 'Error in abandoned job reaper');
      });
    }, REAPER_INTERVAL_MS);
  }

  /**
   * Gracefully shuts down the background worker.
   */
  public async stop(): Promise<void> {
    this.isRunning = false;

    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
    if (this.reaperTimer) {
      clearInterval(this.reaperTimer);
      this.reaperTimer = null;
    }

    this.logger?.info({ workerId: this.workerId }, 'Stopping scan worker; waiting for active jobs');

    // Wait up to 5 seconds for in-flight jobs
    const start = Date.now();
    while (this.activeJobs > 0 && Date.now() - start < 5000) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  /**
   * Explicit wakeup triggered immediately upon scan creation.
   */
  public trigger(): void {
    if (this.isRunning && this.activeJobs < MAX_CONCURRENT_JOBS) {
      this.scheduleNextTick(0);
    }
  }

  private scheduleNextTick(delayMs: number = POLL_INTERVAL_MS): void {
    if (!this.isRunning) return;
    if (this.pollTimer) clearTimeout(this.pollTimer);

    this.pollTimer = setTimeout(() => {
      this.tick().catch((err) => {
        this.logger?.error({ err }, 'Unhandled error in worker tick');
      });
    }, delayMs);
  }

  private async tick(): Promise<void> {
    if (!this.isRunning) return;

    try {
      while (this.isRunning && this.activeJobs < MAX_CONCURRENT_JOBS) {
        const job = await this.claimNextJob();
        if (!job) {
          // Queue is empty, wait for next scheduled poll interval
          break;
        }

        this.activeJobs++;
        // Execute job concurrently without blocking the polling loop
        this.executeJob(job).finally(() => {
          this.activeJobs--;
          // Trigger next job check immediately if still running
          this.trigger();
        });
      }
    } finally {
      if (this.isRunning) {
        this.scheduleNextTick(POLL_INTERVAL_MS);
      }
    }
  }

  /**
   * Atomically claims the next QUEUED job from MongoDB using FIFO ordering.
   */
  public async claimNextJob(): Promise<IScanDocument | null> {
    return await ScanModel.findOneAndUpdate(
      {
        status: ScanStatusEnum.QUEUED,
        retryCount: { $lt: MAX_RETRIES },
      },
      {
        $set: {
          status: ScanStatusEnum.PROCESSING,
          workerId: this.workerId,
          claimedAt: new Date(),
        },
      },
      {
        sort: { createdAt: 1 }, // FIFO
        new: true,
      }
    );
  }

  /**
   * Executes claimed scan job against the Python security engine and persists results idempotently.
   */
  public async executeJob(scan: IScanDocument): Promise<void> {
    const scanId = scan._id.toString();
    this.logger?.info({ scanId, workerId: this.workerId, url: scan.submittedUrl }, 'Processing claimed scan');

    try {
      // 1. Invoke Python scanner through internal authenticated HTTP
      const scanResult = await requestScannerAnalysis({
        scanId,
        url: scan.submittedUrl,
        normalizedDomain: scan.normalizedDomain,
        deepScan: false,
      });

      // 2. Idempotent cleanup of existing findings / certificate for retries
      await FindingModel.deleteMany({ scanId: scan._id });
      await CertificateModel.deleteOne({ scanId: scan._id });

      // 3. Persist new findings
      if (scanResult.findings && scanResult.findings.length > 0) {
        const findingDocs = scanResult.findings.map((f) => ({
          scanId: scan._id,
          category: f.category,
          severity: f.severity,
          title: f.title,
          description: f.description,
          evidence: f.evidence || {},
          confidence: f.confidence,
        }));
        await FindingModel.insertMany(findingDocs);
      }

      // 4. Persist certificate if inspected
      if (scanResult.certificate) {
        await CertificateModel.create({
          scanId: scan._id,
          issuer: scanResult.certificate.issuer,
          subject: scanResult.certificate.subject,
          validFrom: scanResult.certificate.validFrom,
          validUntil: scanResult.certificate.validUntil,
          fingerprint: scanResult.certificate.fingerprint,
          hostnameMatched: scanResult.certificate.hostnameMatched,
          rawDetails: scanResult.certificate.rawDetails || {},
        });
      }

      // 5. Update Scan Document to COMPLETED
      await ScanModel.findByIdAndUpdate(scan._id, {
        $set: {
          status: ScanStatusEnum.COMPLETED,
          riskScore: scanResult.riskScore,
          verdict: scanResult.verdict,
          confidence: scanResult.confidence,
          analysisStatus: scanResult.analysisStatus || 'COMPLETE',
          analysisComplete:
            scanResult.analysisComplete !== undefined ? scanResult.analysisComplete : true,
          analyzerStatuses: scanResult.analyzerStatuses,
          summary: scanResult.summary,
          completedAt: new Date(),
          errorMessage: undefined,
        },
      });

      this.logger?.info(
        { scanId, verdict: scanResult.verdict, score: scanResult.riskScore },
        'Scan completed successfully'
      );
    } catch (error: any) {
      await this.handleJobError(scan, error);
    }
  }

  /**
   * Handles scan execution failures with retry vs permanent failure differentiation.
   */
  public async handleJobError(scan: IScanDocument, error: any): Promise<void> {
    const isPermanent =
      error instanceof ScannerClientError &&
      (error.statusCode === 400 || error.message.includes('SSRF') || error.message.includes('Invalid'));

    const currentRetries = scan.retryCount || 0;
    const canRetry = !isPermanent && currentRetries + 1 < MAX_RETRIES;

    if (canRetry) {
      // Transient error: Re-queue with incremented retry count
      await ScanModel.findByIdAndUpdate(scan._id, {
        $set: {
          status: ScanStatusEnum.QUEUED,
          lastError: error.message || 'Transient scanner error',
          claimedAt: undefined,
          workerId: undefined,
        },
        $inc: { retryCount: 1 },
      });

      this.logger?.warn(
        { scanId: scan._id, retryCount: currentRetries + 1, error: error.message },
        'Scan failed transiently; re-queued for retry'
      );
    } else {
      // Permanent failure or max retries exceeded: Mark as FAILED
      await ScanModel.findByIdAndUpdate(scan._id, {
        $set: {
          status: ScanStatusEnum.FAILED,
          errorMessage: error.message || 'Scan execution failed unexpectedly',
          completedAt: new Date(),
        },
        $inc: { retryCount: isPermanent ? 0 : 1 },
      });

      this.logger?.error(
        { scanId: scan._id, isPermanent, error: error.message },
        'Scan failed permanently'
      );
    }
  }

  /**
   * Recovers jobs stuck in PROCESSING longer than JOB_TIMEOUT_MS.
   */
  public async recoverAbandonedJobs(timeoutMs: number = JOB_TIMEOUT_MS): Promise<number> {
    const cutoff = new Date(Date.now() - timeoutMs);

    const abandonedJobs = await ScanModel.find({
      status: ScanStatusEnum.PROCESSING,
      claimedAt: { $lt: cutoff },
    }).limit(10);

    for (const job of abandonedJobs) {
      if ((job.retryCount || 0) + 1 < MAX_RETRIES) {
        await ScanModel.findByIdAndUpdate(job._id, {
          $set: {
            status: ScanStatusEnum.QUEUED,
            lastError: 'Job processing timed out; re-queued by recovery reaper',
            claimedAt: undefined,
            workerId: undefined,
          },
          $inc: { retryCount: 1 },
        });
        this.logger?.warn({ scanId: job._id }, 'Recovered abandoned scan job back to QUEUED');
      } else {
        await ScanModel.findByIdAndUpdate(job._id, {
          $set: {
            status: ScanStatusEnum.FAILED,
            errorMessage: 'Scan processing exceeded maximum timeout ceiling',
            completedAt: new Date(),
          },
        });
        this.logger?.error({ scanId: job._id }, 'Abandoned scan exceeded max retries; marked as FAILED');
      }
    }

    return abandonedJobs.length;
  }
}

// Global default singleton instance
export const scanWorker = new ScanWorkerService();
