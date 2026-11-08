import fastify, { FastifyInstance, FastifyError } from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import mongoose from 'mongoose';
import { env } from './utils/config.js';
import { initDatabase } from './plugins/db.js';
import { scansRoutes } from './modules/scans/index.js';
import { reportsRoutes } from './modules/reports/index.js';
import { threatsRoutes } from './modules/threats/index.js';
import { communityRoutes } from './modules/community/index.js';
import { dashboardRoutes } from './modules/dashboard/index.js';
import { authRoutes } from './modules/auth/index.js';
import { messagesRoutes } from './modules/messages/index.js';
import { correlationsRoutes } from './modules/correlations/index.js';
import { blockchainRoutes } from './modules/blockchain/index.js';
import { aiRoutes } from './modules/ai/index.js';
import { scanWorker } from './services/scanWorker.js';

export function buildServer(): FastifyInstance {
  const app = fastify({
    logger: {
      level: env.NODE_ENV === 'production' ? 'info' : 'debug',
      transport:
        env.NODE_ENV === 'development'
          ? {
              target: 'pino-pretty',
              options: {
                translateTime: 'HH:MM:ss Z',
                ignore: 'pid,hostname',
              },
            }
          : undefined,
    },
    trustProxy: ['127.0.0.1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '::1', 'fc00::/7'],
  });

  // CORS Configuration
  app.register(cors, {
    origin: env.CORS_ORIGIN === '*' ? true : [env.CORS_ORIGIN, 'http://localhost:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
  });

  // Rate Limiting (120 requests per minute per IP)
  app.register(rateLimit, {
    max: 120,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({
      statusCode: 429,
      error: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests. Please slow down your requests.',
    }),
  });

  // Centralized Error Handling (sanitized against information leakage)
  app.setErrorHandler((error: FastifyError, request, reply) => {
    app.log.error({ err: error, reqId: request.id }, 'Request handling error');
    const statusCode = error.statusCode || (error as any).status || 500;

    if (statusCode >= 500) {
      return reply.status(statusCode).send({
        error: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected internal server error occurred',
        statusCode,
      });
    }

    return reply.status(statusCode).send({
      error: (error as any).error || error.name || 'BAD_REQUEST',
      message: error.message || 'The request could not be processed',
      statusCode,
    });
  });

  // Health Check Endpoint
  app.get('/health', async () => {
    const dbState = mongoose.connection.readyState;
    const dbStatusMap: Record<number, string> = {
      0: 'disconnected',
      1: 'connected',
      2: 'connecting',
      3: 'disconnecting',
    };

    return {
      status: 'healthy',
      service: 'sentrix-api',
      version: '1.0.0',
      database: dbStatusMap[dbState] || 'unknown',
      timestamp: new Date().toISOString(),
    };
  });

  // API v1 Routes
  app.register(authRoutes, { prefix: '/api/v1/auth' });
  app.register(scansRoutes, { prefix: '/api/v1/scans' });
  app.register(reportsRoutes, { prefix: '/api/v1/reports' });
  app.register(threatsRoutes, { prefix: '/api/v1/threats' });
  app.register(communityRoutes, { prefix: '/api/v1/community' });
  app.register(dashboardRoutes, { prefix: '/api/v1/dashboard' });
  app.register(messagesRoutes, { prefix: '/api/v1/messages' });
  app.register(correlationsRoutes, { prefix: '/api/v1/correlations' });
  app.register(blockchainRoutes, { prefix: '/api/v1/blockchain' });
  app.register(aiRoutes, { prefix: '/api/v1/ai' });

  return app;
}

export async function startServer(): Promise<void> {
  const app = buildServer();

  try {
    await initDatabase(app);
    scanWorker.start(app.log);

    app.addHook('onClose', async () => {
      await scanWorker.stop();
    });

    const address = await app.listen({
      port: env.PORT,
      host: '0.0.0.0',
    });
    app.log.info(`SENTRIX API server listening on ${address}`);

    let isShuttingDown = false;
    const shutdown = async (signal: string) => {
      if (isShuttingDown) {
        app.log.warn({ signal }, 'Forced shutdown requested by second signal');
        process.exit(1);
      }
      isShuttingDown = true;
      app.log.info({ signal }, 'Graceful shutdown initiated');

      const forceTimer = setTimeout(() => {
        app.log.error('Graceful shutdown timed out (10s); forcing exit');
        process.exit(1);
      }, 10_000);
      forceTimer.unref();

      try {
        await app.close();
        app.log.info('Server closed successfully');
        process.exit(0);
      } catch (err) {
        app.log.error({ err }, 'Error during graceful shutdown');
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

if (process.env.NODE_ENV !== 'test') {
  startServer();
}
