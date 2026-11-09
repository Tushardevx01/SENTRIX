import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { AIExplanationRequestSchema } from '@sentrix/shared';
import { aiService } from '../../services/aiService.js';

export const aiRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // POST /api/v1/ai/explain - Generate grounded cybersecurity explanations
  app.post(
    '/explain',
    {
      config: {
        rateLimit: {
          max: 30,
          timeWindow: '1 minute',
        },
      },
    },
    async (request, reply) => {
    const parseResult = AIExplanationRequestSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Invalid AI explanation request payload',
        details: parseResult.error.format(),
      });
    }

    try {
      const explanation = await aiService.explain(parseResult.data);
      return reply.send(explanation);
    } catch (err: any) {
      app.log.error({ err }, 'AI explanation failed');
      return reply.status(500).send({
        error: 'AI_ERROR',
        message: 'Failed to generate security explanation',
        details: err.message,
      });
    }
  });
};
