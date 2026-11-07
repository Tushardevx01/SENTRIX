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

    const [findings, certificate] = await Promise.all([
      FindingModel.find({ scanId: id }).sort({ createdAt: -1 }).lean(),
      CertificateModel.findOne({ scanId: id }).lean(),
    ]);

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
