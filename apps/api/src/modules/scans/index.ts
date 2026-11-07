import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { UrlScanRequestSchema, normalizeUrl, ScanStatusEnum } from '@sentrix/shared';
import { ScanModel } from '../../models/Scan.js';
import { FindingModel } from '../../models/Finding.js';
import { CertificateModel } from '../../models/Certificate.js';
import { requestScannerAnalysis, ScannerClientError } from '../../services/scannerClient.js';
import { escapeRegex, sanitizePagination } from '../../utils/sanitize.js';

export const scansRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // POST /api/v1/scans - Submit & execute URL threat scan
  app.post('/', async (request, reply) => {
    const parseResult = UrlScanRequestSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Invalid scan request parameters',
        details: parseResult.error.issues,
      });
    }

    const { url, deepScan } = parseResult.data;
    const { normalizedUrl, normalizedDomain } = normalizeUrl(url);

    // 1. Create Scan record in MongoDB
    const scan = await ScanModel.create({
      submittedUrl: normalizedUrl,
      normalizedDomain,
      status: ScanStatusEnum.IN_PROGRESS,
    });

    try {
      // 2. Delegate to internal Python Security Scanner
      const scanResult = await requestScannerAnalysis({
        scanId: scan._id.toString(),
        url: normalizedUrl,
        normalizedDomain,
        deepScan: Boolean(deepScan),
      });

      // 3. Persist Findings
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

      // 4. Persist Certificate if inspected
      if (scanResult.certificate) {
        await CertificateModel.findOneAndUpdate(
          { scanId: scan._id },
          {
            scanId: scan._id,
            issuer: scanResult.certificate.issuer,
            subject: scanResult.certificate.subject,
            validFrom: scanResult.certificate.validFrom,
            validUntil: scanResult.certificate.validUntil,
            fingerprint: scanResult.certificate.fingerprint,
            hostnameMatched: scanResult.certificate.hostnameMatched,
            rawDetails: scanResult.certificate.rawDetails || {},
          },
          { upsert: true, new: true }
        );
      }

      // 5. Update Scan Document
      scan.status = ScanStatusEnum.COMPLETED;
      scan.riskScore = scanResult.riskScore;
      scan.verdict = scanResult.verdict;
      scan.confidence = scanResult.confidence;
      scan.analysisStatus = scanResult.analysisStatus || 'COMPLETE';
      scan.analysisComplete = scanResult.analysisComplete !== undefined ? scanResult.analysisComplete : true;
      scan.analyzerStatuses = scanResult.analyzerStatuses;
      scan.summary = scanResult.summary;
      scan.completedAt = new Date();
      await scan.save();

      return reply.status(201).send({
        scanId: scan._id,
        status: scan.status,
        riskScore: scan.riskScore,
        verdict: scan.verdict,
        confidence: scan.confidence,
        analysisStatus: scan.analysisStatus,
        analysisComplete: scan.analysisComplete,
        submittedUrl: scan.submittedUrl,
        normalizedDomain: scan.normalizedDomain,
        completedAt: scan.completedAt,
        summary: scan.summary,
      });
    } catch (error: any) {
      scan.status = ScanStatusEnum.FAILED;
      scan.errorMessage = error.message || 'Unknown scanner error';
      scan.completedAt = new Date();
      await scan.save();

      if (error instanceof ScannerClientError) {
        return reply.status(error.statusCode).send({
          error: error.statusCode === 400 ? 'SSRF_VIOLATION' : 'SCAN_FAILED',
          message: error.message,
          details: error.details,
          scanId: scan._id,
        });
      }

      return reply.status(500).send({
        error: 'INTERNAL_ERROR',
        message: 'Scan execution failed unexpectedly',
        scanId: scan._id,
      });
    }
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

  // GET /api/v1/scans/:id - Get specific scan status
  app.get('/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const scan = await ScanModel.findById(id).lean();
    if (!scan) {
      return reply.status(404).send({ error: 'NOT_FOUND', message: 'Scan not found' });
    }
    return reply.send(scan);
  });
};
