import mongoose from 'mongoose';
import { FastifyInstance } from 'fastify';
import { ScanStatusEnum } from '@sentrix/shared';
import { ScanModel } from '../models/Scan.js';
import { FindingModel } from '../models/Finding.js';
import { CertificateModel } from '../models/Certificate.js';

export interface IOrphanCleanupOptions {
  batchSize?: number;
  retentionMs?: number;
  dryRun?: boolean;
}

export interface IOrphanCleanupReport {
  scannedCount: number;
  attemptsEvaluated: number;
  publishedPreserved: number;
  activePreserved: number;
  supersededDeleted: number;
  abandonedDeleted: number;
  missingScanDeleted: number;
  findingsDeleted: number;
  certificatesDeleted: number;
  skipped: boolean;
  skipReason?: string;
  errors: string[];
}

export const DEFAULT_CLEANUP_RETENTION_MS = 10 * 60 * 1000; // 10 minutes (guarantees 60s worker leases have expired)
export const DEFAULT_CLEANUP_BATCH_SIZE = 50;

export class OrphanCleanupService {
  private isRunning = false;

  public isExecutionRunning(): boolean {
    return this.isRunning;
  }

  /**
   * Identifies and purges orphaned and superseded worker-attempt artifacts while strictly
   * preserving active worker attempts, published results, and legacy records.
   */
  public async runCleanup(
    options: IOrphanCleanupOptions = {},
    logger?: FastifyInstance['log']
  ): Promise<IOrphanCleanupReport> {
    const report: IOrphanCleanupReport = {
      scannedCount: 0,
      attemptsEvaluated: 0,
      publishedPreserved: 0,
      activePreserved: 0,
      supersededDeleted: 0,
      abandonedDeleted: 0,
      missingScanDeleted: 0,
      findingsDeleted: 0,
      certificatesDeleted: 0,
      skipped: false,
      errors: [],
    };

    // Concurrency guard: prevent overlapping cleanup executions
    if (this.isRunning) {
      report.skipped = true;
      report.skipReason = 'Orphan cleanup is already running';
      logger?.debug('Orphan cleanup execution skipped: cleanup is already in progress');
      return report;
    }

    this.isRunning = true;

    try {
      const batchSize = Math.max(1, Math.min(options.batchSize ?? DEFAULT_CLEANUP_BATCH_SIZE, 500));
      const retentionMs = Math.max(0, options.retentionMs ?? DEFAULT_CLEANUP_RETENTION_MS);
      const cutoffDate = new Date(Date.now() - retentionMs);
      const isDryRun = Boolean(options.dryRun);

      logger?.info(
        { batchSize, retentionMs, cutoffDate: cutoffDate.toISOString(), dryRun: isDryRun },
        'Starting orphan-artifact cleanup execution'
      );

      // 1. Query candidate attempt-scoped artifacts older than the retention threshold
      // Strictly filter leaseToken: { $exists: true, $ne: null } to protect untagged legacy data
      const candidateFilter: any = {
        leaseToken: { $exists: true, $ne: null },
      };
      if (retentionMs > 0) {
        candidateFilter.createdAt = { $lte: cutoffDate };
      }

      const [candidateFindings, candidateCerts] = await Promise.all([
        FindingModel.find(candidateFilter)
          .select('scanId leaseToken createdAt')
          .limit(batchSize)
          .lean(),
        CertificateModel.find(candidateFilter)
          .select('scanId leaseToken createdAt')
          .limit(batchSize)
          .lean(),
      ]);

      report.scannedCount = candidateFindings.length + candidateCerts.length;

      // 2. Aggregate unique (scanId, leaseToken) attempt pairs
      const uniqueAttempts = new Map<string, { scanId: string; leaseToken: string }>();

      for (const f of candidateFindings) {
        if (f.scanId && f.leaseToken) {
          const key = `${f.scanId.toString()}:${f.leaseToken}`;
          if (!uniqueAttempts.has(key)) {
            uniqueAttempts.set(key, { scanId: f.scanId.toString(), leaseToken: f.leaseToken });
          }
        }
      }

      for (const c of candidateCerts) {
        if (c.scanId && c.leaseToken) {
          const key = `${c.scanId.toString()}:${c.leaseToken}`;
          if (!uniqueAttempts.has(key)) {
            uniqueAttempts.set(key, { scanId: c.scanId.toString(), leaseToken: c.leaseToken });
          }
        }
      }

      report.attemptsEvaluated = uniqueAttempts.size;

      // 3. Evaluate each attempt against scan ownership status
      for (const { scanId, leaseToken } of uniqueAttempts.values()) {
        try {
          if (!mongoose.Types.ObjectId.isValid(scanId)) {
            // Malformed scan ID: purge invalid attempt records safely
            if (!isDryRun) {
              const [fRes, cRes] = await Promise.all([
                FindingModel.deleteMany({ scanId, leaseToken }),
                CertificateModel.deleteMany({ scanId, leaseToken }),
              ]);
              report.missingScanDeleted++;
              report.findingsDeleted += fRes.deletedCount || 0;
              report.certificatesDeleted += cRes.deletedCount || 0;
            }
            continue;
          }

          const scan = (await ScanModel.findById(scanId).lean()) as any;

          // Rule A: Missing scan reference (deleted or purged scan)
          if (!scan) {
            if (!isDryRun) {
              const [fRes, cRes] = await Promise.all([
                FindingModel.deleteMany({ scanId, leaseToken }),
                CertificateModel.deleteMany({ scanId, leaseToken }),
              ]);
              report.missingScanDeleted++;
              report.findingsDeleted += fRes.deletedCount || 0;
              report.certificatesDeleted += cRes.deletedCount || 0;
              logger?.info({ scanId, leaseToken }, 'Purged artifacts for non-existent scan');
            } else {
              report.missingScanDeleted++;
            }
            continue;
          }

          // Rule B: Published winning lease token
          // MUST PRESERVE: this attempt represents the published results
          if (
            scan.status === ScanStatusEnum.COMPLETED &&
            scan.publishedLeaseToken === leaseToken
          ) {
            report.publishedPreserved++;
            continue;
          }

          // Rule C: Valid active worker lease
          // MUST PRESERVE: an active worker is currently executing under this lease
          if (
            scan.status === ScanStatusEnum.PROCESSING &&
            scan.leaseToken === leaseToken
          ) {
            report.activePreserved++;
            continue;
          }

          // Rule D: Superseded attempt on a COMPLETED scan
          // The scan is completed under a different winning leaseToken. Safe to purge.
          if (
            scan.status === ScanStatusEnum.COMPLETED &&
            scan.publishedLeaseToken !== leaseToken
          ) {
            if (!isDryRun) {
              const [fRes, cRes] = await Promise.all([
                FindingModel.deleteMany({ scanId, leaseToken }),
                CertificateModel.deleteMany({ scanId, leaseToken }),
              ]);
              report.supersededDeleted++;
              report.findingsDeleted += fRes.deletedCount || 0;
              report.certificatesDeleted += cRes.deletedCount || 0;
              logger?.info(
                { scanId, leaseToken, publishedLeaseToken: scan.publishedLeaseToken },
                'Purged superseded worker attempt artifacts'
              );
            } else {
              report.supersededDeleted++;
            }
            continue;
          }

          // Rule E: Abandoned attempt on a FAILED or RE-QUEUED scan
          // The scan is FAILED, or in QUEUED/PROCESSING with a different or revoked lease.
          // Since the artifact is older than retentionMs (exceeding 60s lease window), this attempt is abandoned.
          if (
            scan.status === ScanStatusEnum.FAILED ||
            (scan.status !== ScanStatusEnum.PROCESSING && scan.leaseToken !== leaseToken) ||
            (scan.status === ScanStatusEnum.PROCESSING && scan.leaseToken !== leaseToken)
          ) {
            if (!isDryRun) {
              const [fRes, cRes] = await Promise.all([
                FindingModel.deleteMany({ scanId, leaseToken }),
                CertificateModel.deleteMany({ scanId, leaseToken }),
              ]);
              report.abandonedDeleted++;
              report.findingsDeleted += fRes.deletedCount || 0;
              report.certificatesDeleted += cRes.deletedCount || 0;
              logger?.info(
                { scanId, leaseToken, scanStatus: scan.status },
                'Purged abandoned worker attempt artifacts'
              );
            } else {
              report.abandonedDeleted++;
            }
            continue;
          }
        } catch (attemptErr: any) {
          const errMsg = `Error evaluating attempt ${scanId}:${leaseToken}: ${attemptErr.message}`;
          report.errors.push(errMsg);
          logger?.warn({ scanId, leaseToken, err: attemptErr.message }, errMsg);
        }
      }

      logger?.info(
        {
          attemptsEvaluated: report.attemptsEvaluated,
          publishedPreserved: report.publishedPreserved,
          activePreserved: report.activePreserved,
          findingsDeleted: report.findingsDeleted,
          certificatesDeleted: report.certificatesDeleted,
          errorsCount: report.errors.length,
        },
        'Orphan cleanup execution completed'
      );
    } catch (globalErr: any) {
      const errMsg = `Global error during orphan cleanup: ${globalErr.message}`;
      report.errors.push(errMsg);
      logger?.error({ err: globalErr.message }, errMsg);
    } finally {
      this.isRunning = false;
    }

    return report;
  }
}

export const orphanCleanupService = new OrphanCleanupService();
