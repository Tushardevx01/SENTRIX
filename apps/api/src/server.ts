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
    trustProxy: true,
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
      error: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests. Please slow down your requests.',
    }),
  });

  // Centralized Error Handling
  app.setErrorHandler((error: FastifyError, request, reply) => {
    app.log.error(error);
    const statusCode = error.statusCode || 500;
    return reply.status(statusCode).send({
      error: error.name || 'INTERNAL_SERVER_ERROR',
      message: error.message || 'An unexpected server error occurred',
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
  app.register(scansRoutes, { prefix: '/api/v1/scans' });
  app.register(reportsRoutes, { prefix: '/api/v1/reports' });
  app.register(threatsRoutes, { prefix: '/api/v1/threats' });
  app.register(communityRoutes, { prefix: '/api/v1/community' });
  app.register(dashboardRoutes, { prefix: '/api/v1/dashboard' });

  return app;
}

export async function startServer(): Promise<void> {
  const app = buildServer();

  try {
    await initDatabase(app);
    const address = await app.listen({
      port: env.PORT,
      host: '0.0.0.0',
    });
    app.log.info(`SENTRIX API server listening on ${address}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

if (process.env.NODE_ENV !== 'test') {
  startServer();
}
