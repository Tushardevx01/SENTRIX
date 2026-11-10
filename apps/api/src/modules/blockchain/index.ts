import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import {
  BlockchainRegisterRequestSchema,
  BlockchainVerifyRequestSchema,
} from '@sentrix/shared';
import { blockchainService } from '../../services/blockchainService.js';
import { sanitizePagination } from '../../utils/sanitize.js';

export const blockchainRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // POST /api/v1/blockchain/register - Register report cryptographic commitment on-chain
  app.post(
    '/register',
    {
      config: {
        rateLimit: {
          max: 20,
          timeWindow: '1 minute',
        },
      },
    },
    async (request, reply) => {
    const parseResult = BlockchainRegisterRequestSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Invalid blockchain registration payload',
        details: parseResult.error.format(),
      });
    }

    const { reportId, reportType } = parseResult.data;

    try {
      const record = await blockchainService.registerReport(reportId, reportType);
      return reply.status(201).send({
        message: 'Threat report commitment registered on blockchain',
        record,
      });
    } catch (err: any) {
      app.log.error({ err }, 'Blockchain registration failed');
      return reply.status(500).send({
        error: 'BLOCKCHAIN_ERROR',
        message: 'Failed to commit threat report to blockchain registry',
        details: err.message,
      });
    }
  });

  // GET /api/v1/blockchain/verify/:id - Independently verify report hash against on-chain state
  app.get('/verify/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const query = request.query as { hash?: string };

    try {
      const verification = await blockchainService.verifyReport(id, query.hash);
      return reply.send(verification);
    } catch (err: any) {
      return reply.status(500).send({
        error: 'VERIFICATION_ERROR',
        message: 'Failed to complete on-chain verification',
        details: err.message,
      });
    }
  });

  // POST /api/v1/blockchain/verify - Verify with optional explicit hash payload
  app.post('/verify', async (request, reply) => {
    const parseResult = BlockchainVerifyRequestSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Invalid verification request payload',
        details: parseResult.error.format(),
      });
    }

    const { reportId, reportHash } = parseResult.data;
    try {
      const verification = await blockchainService.verifyReport(reportId, reportHash);
      return reply.send(verification);
    } catch (err: any) {
      return reply.status(500).send({
        error: 'VERIFICATION_ERROR',
        message: 'Failed to complete on-chain verification',
        details: err.message,
      });
    }
  });

  // GET /api/v1/blockchain/records - List verified on-chain threat records
  app.get('/records', async (request, reply) => {
    const query = request.query as Record<string, string>;
    const { limit } = sanitizePagination(undefined, query.limit, 50, 20);
    const records = await blockchainService.getRecords(limit);
    return reply.send({ records });
  });

  // GET /api/v1/blockchain/config - Get active contract and network configuration
  app.get('/config', async (_request, reply) => {
    const config = await blockchainService.getConfig();
    return reply.send(config);
  });

  // POST /api/v1/blockchain/dispute - Submit formal dispute against registered threat record
  app.post('/dispute', async (request, reply) => {
    const body = request.body as { reportId?: string; reason?: string };
    if (!body?.reportId || !body?.reason) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Missing reportId or dispute reason',
      });
    }

    try {
      const result = await blockchainService.disputeReport(body.reportId, body.reason);
      return reply.send(result);
    } catch (err: any) {
      return reply.status(500).send({
        error: 'DISPUTE_ERROR',
        message: err.message,
      });
    }
  });

  // POST /api/v1/blockchain/revise - Revise threat record with new severity score and evidence
  app.post('/revise', async (request, reply) => {
    const body = request.body as {
      reportId?: string;
      newSeverityScore?: number;
      newEvidenceData?: Record<string, any>;
    };
    if (!body?.reportId || body?.newSeverityScore === undefined) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Missing reportId or newSeverityScore',
      });
    }

    try {
      const result = await blockchainService.reviseReport(
        body.reportId,
        body.newSeverityScore,
        body.newEvidenceData || {}
      );
      return reply.send(result);
    } catch (err: any) {
      return reply.status(500).send({
        error: 'REVISION_ERROR',
        message: err.message,
      });
    }
  });
};
