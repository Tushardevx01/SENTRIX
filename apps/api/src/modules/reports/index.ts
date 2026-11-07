import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import mongoose from 'mongoose';
import { ScanModel, IScanDocument } from '../../models/Scan.js';
import { FindingModel } from '../../models/Finding.js';
import { CertificateModel } from '../../models/Certificate.js';

export const reportsRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // GET /api/v1/reports/:id - Comprehensive security report
  app.get('/:id', async (request, reply) => {
    const { id } = request.params as { id: string };

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Invalid report ID format',
      });
    }

    const scan = (await ScanModel.findById(id).lean()) as IScanDocument | null;
    if (!scan) {
      return reply.status(404).send({
        error: 'NOT_FOUND',
        message: 'Security report not found for specified ID',
      });
    }

    let findings: any[] = [];
    let certificate: any = null;

    if (scan.status === 'COMPLETED') {
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

      [findings, certificate] = await Promise.all([
        FindingModel.find(filter).sort({ createdAt: -1 }).lean(),
        CertificateModel.findOne(filter).lean(),
      ]);
    }

    return reply.send({
      scan,
      findings,
      certificate,
      summary: scan.summary || {
        threatTypes: [],
        riskFactors: [],
      },
    });
  });
};
