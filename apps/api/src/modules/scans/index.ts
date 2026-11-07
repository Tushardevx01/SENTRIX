import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { UrlScanRequestSchema, normalizeUrl, ScanStatusEnum } from '@sentrix/shared';
import { ScanModel, IScanDocument } from '../../models/Scan.js';
import { FindingModel } from '../../models/Finding.js';
import { CertificateModel } from '../../models/Certificate.js';
import { scanWorker } from '../../services/scanWorker.js';
import { escapeRegex, sanitizePagination } from '../../utils/sanitize.js';

export const scansRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // POST /api/v1/scans - Queue URL threat scan for asynchronous background execution
  app.post('/', async (request, reply) => {
    const parseResult = UrlScanRequestSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Invalid scan request parameters',
        details: parseResult.error.issues,
      });
    }

    const { url } = parseResult.data;
    const { normalizedUrl, normalizedDomain } = normalizeUrl(url);
    const urlHash = crypto.createHash('sha256').update(normalizedUrl).digest('hex');

    // Duplicate submission protection: reuse recently queued/processing scan
    const activeScan = (await ScanModel.findOne({
      urlHash,
      status: { $in: [ScanStatusEnum.QUEUED, ScanStatusEnum.PROCESSING] },
      createdAt: { $gte: new Date(Date.now() - 60_000) },
    }).lean()) as IScanDocument | null;

    if (activeScan) {
      return reply.status(200).send({
        scanId: activeScan._id,
        status: activeScan.status,
        submittedUrl: activeScan.submittedUrl,
        normalizedDomain: activeScan.normalizedDomain,
        createdAt: activeScan.createdAt,
        message: 'Active threat scan already queued or processing for this URL.',
        isDuplicate: true,
      });
    }

    // Create new scan record in QUEUED status with race condition resilience
    let scan: IScanDocument;
    try {
      scan = await ScanModel.create({
        submittedUrl: normalizedUrl,
        normalizedDomain,
        urlHash,
        status: ScanStatusEnum.QUEUED,
        riskScore: 0,
        verdict: 'BENIGN',
        confidence: 0,
        retryCount: 0,
      });
    } catch (err: any) {
      if (
        err?.code === 11000 ||
        (err?.name === 'MongoServerError' && err?.message?.includes('duplicate key'))
      ) {
        // Race condition: concurrent request inserted an active scan for this urlHash
        const racedScan = (await ScanModel.findOne({
          urlHash,
          status: { $in: [ScanStatusEnum.QUEUED, ScanStatusEnum.PROCESSING] },
        }).lean()) as IScanDocument | null;

        if (racedScan) {
          return reply.status(200).send({
            scanId: racedScan._id,
            status: racedScan.status,
            submittedUrl: racedScan.submittedUrl,
            normalizedDomain: racedScan.normalizedDomain,
            createdAt: racedScan.createdAt,
            message: 'Active threat scan already queued or processing for this URL.',
            isDuplicate: true,
          });
        }
      }
      throw err;
    }

    // Notify background worker to immediately pick up the job
    scanWorker.trigger();

    return reply.status(201).send({
      scanId: scan._id,
      status: scan.status,
      submittedUrl: scan.submittedUrl,
      normalizedDomain: scan.normalizedDomain,
      createdAt: scan.createdAt,
      message: 'Scan successfully queued for verification.',
    });
  });

  // GET /api/v1/scans - List recent scans
  app.get('/', async (request, reply) => {
    const { limit, skip, domain } = request.query as Record<string, string>;
    const { skip: safeSkip, limit: safeLimit } = sanitizePagination(skip, limit, 100, 20);

    const query: Record<string, any> = {};
    if (domain && typeof domain === 'string') {
      const sanitizedDomain = escapeRegex(domain.trim().slice(0, 100));
      if (sanitizedDomain) {
        query.normalizedDomain = { $regex: sanitizedDomain, $options: 'i' };
      }
    }

    const scans = await ScanModel.find(query)
      .sort({ createdAt: -1 })
      .skip(safeSkip)
      .limit(safeLimit)
      .lean();

    const total = await ScanModel.countDocuments(query);

    return reply.send({
      total,
      scans,
    });
  });

  // GET /api/v1/scans/:id - Get scan status and metadata
  app.get('/:id', async (request, reply) => {
    const { id } = request.params as { id: string };

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return reply.status(400).send({ error: 'VALIDATION_ERROR', message: 'Invalid scan ID format' });
    }

    const scan = (await ScanModel.findById(id).lean()) as IScanDocument | null;
    if (!scan) {
      return reply.status(404).send({ error: 'NOT_FOUND', message: 'Scan not found' });
    }
    return reply.send(scan);
  });

  // GET /api/v1/scans/:id/results - Fetch completed scan results (findings, cert, summary)
  app.get('/:id/results', async (request, reply) => {
    const { id } = request.params as { id: string };

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return reply.status(400).send({ error: 'VALIDATION_ERROR', message: 'Invalid scan ID format' });
    }

    const scan = (await ScanModel.findById(id).lean()) as IScanDocument | null;
    if (!scan) {
      return reply.status(404).send({ error: 'NOT_FOUND', message: 'Scan not found' });
    }

    if (scan.status === ScanStatusEnum.COMPLETED) {
      const filter: Record<string, any> = { scanId: id };
      if (scan.publishedLeaseToken) {
        filter.leaseToken = scan.publishedLeaseToken;
      } else {
        // Legacy scan fallback: match untagged records or records matching scan.leaseToken,
        // but exclude records tagged with another worker's attempt token
        filter.$or = [
          { leaseToken: { $exists: false } },
          { leaseToken: null },
          ...(scan.leaseToken ? [{ leaseToken: scan.leaseToken }] : []),
        ];
      }

      const [findings, certificate] = await Promise.all([
        FindingModel.find(filter).sort({ createdAt: -1 }).lean(),
        CertificateModel.findOne(filter).lean(),
      ]);

      return reply.send({
        scanId: scan._id,
        status: scan.status,
        submittedUrl: scan.submittedUrl,
        normalizedDomain: scan.normalizedDomain,
        verdict: scan.verdict,
        riskScore: scan.riskScore,
        confidence: scan.confidence,
        analysisStatus: scan.analysisStatus,
        analysisComplete: scan.analysisComplete,
        analyzerStatuses: scan.analyzerStatuses,
        findings,
        certificate,
        summary: scan.summary,
        completedAt: scan.completedAt,
      });
    }

    if (scan.status === ScanStatusEnum.FAILED) {
      return reply.status(200).send({
        scanId: scan._id,
        status: scan.status,
        submittedUrl: scan.submittedUrl,
        normalizedDomain: scan.normalizedDomain,
        error: scan.errorMessage || 'Scan execution failed',
        completedAt: scan.completedAt,
      });
    }

    // Scan is still QUEUED or PROCESSING
    return reply.status(200).send({
      scanId: scan._id,
      status: scan.status,
      submittedUrl: scan.submittedUrl,
      normalizedDomain: scan.normalizedDomain,
      analyzerStatuses: scan.analyzerStatuses,
      message: 'Scan is currently in progress',
      createdAt: scan.createdAt,
    });
  });
};
