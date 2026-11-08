import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { correlationService } from '../../services/correlationService.js';
import { sanitizePagination } from '../../utils/sanitize.js';

export const correlationsRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // GET /api/v1/correlations/related/:target - Find related threat incidents and campaigns
  app.get('/related/:target', async (request, reply) => {
    const { target } = request.params as { target: string };
    if (!target || target.trim().length === 0) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Target identifier is required',
      });
    }

    const decodedTarget = decodeURIComponent(target);
    const result = await correlationService.getRelatedThreats(decodedTarget);
    return reply.send(result);
  });

  // GET /api/v1/correlations/campaigns - List active threat campaigns
  app.get('/campaigns', async (request, reply) => {
    const query = request.query as Record<string, string>;
    const { limit } = sanitizePagination(undefined, query.limit, 50, 20);
    const campaigns = await correlationService.getCampaigns(limit);
    return reply.send({ campaigns });
  });

  // GET /api/v1/correlations/campaigns/:id - Get specific campaign details
  app.get('/campaigns/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const campaign = await correlationService.getCampaignById(id);
    if (!campaign) {
      return reply.status(404).send({
        error: 'NOT_FOUND',
        message: 'Threat campaign not found',
      });
    }
    return reply.send(campaign);
  });

  // GET /api/v1/correlations/indicators - List top recurring threat indicators
  app.get('/indicators', async (request, reply) => {
    const query = request.query as Record<string, string>;
    const { limit } = sanitizePagination(undefined, query.limit, 100, 30);
    const indicators = await correlationService.getTopIndicators(limit);
    return reply.send({ indicators });
  });
};
