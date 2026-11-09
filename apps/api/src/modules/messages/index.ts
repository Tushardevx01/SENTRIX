import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import mongoose from 'mongoose';
import { MessageAnalyzeRequestSchema } from '@sentrix/shared';
import { messageAnalyzer } from '../../services/messageAnalyzer.js';
import { MessageAnalysisModel } from '../../models/MessageAnalysis.js';
import { sanitizePagination } from '../../utils/sanitize.js';

export const messagesRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  // POST /api/v1/messages/analyze - Analyze suspicious message text
  app.post(
    '/analyze',
    {
      config: {
        rateLimit: {
          max: 30,
          timeWindow: '1 minute',
        },
      },
    },
    async (request, reply) => {
    const parseResult = MessageAnalyzeRequestSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Invalid message analysis request payload',
        details: parseResult.error.format(),
      });
    }

    const { messageText, channel, senderInfo } = parseResult.data;
    const clientIp = request.ip || '127.0.0.1';

    try {
      const result = await messageAnalyzer.analyze(messageText, channel, senderInfo, clientIp);
      return reply.status(201).send(result);
    } catch (err: any) {
      app.log.error({ err }, 'Message analysis failed');
      return reply.status(500).send({
        error: 'ANALYSIS_ERROR',
        message: 'Failed to process message analysis',
        details: err.message,
      });
    }
  });

  // GET /api/v1/messages/:id - Get specific message analysis report
  app.get('/:id', async (request, reply) => {
    const { id } = request.params as { id: string };

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: 'Invalid message report ID format',
      });
    }

    const record = await MessageAnalysisModel.findById(id).lean();
    if (!record) {
      return reply.status(404).send({
        error: 'NOT_FOUND',
        message: 'Message analysis record not found',
      });
    }

    return reply.send(record);
  });

  // GET /api/v1/messages - List recent analyzed messages
  app.get('/', async (request, reply) => {
    const query = request.query as Record<string, string>;
    const { skip, limit } = sanitizePagination(query.skip, query.limit, 50, 20);
    const filter: Record<string, any> = {};

    if (query.classification) {
      filter.classification = query.classification.toUpperCase();
    }
    if (query.channel) {
      filter.channel = query.channel.toUpperCase();
    }

    const [total, records] = await Promise.all([
      MessageAnalysisModel.countDocuments(filter),
      MessageAnalysisModel.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .select('_id preview channel classification riskScore confidence detectedPatterns extractedIndicators createdAt')
        .lean(),
    ]);

    return reply.send({
      skip,
      limit,
      total,
      messages: records,
    });
  });
};
