import mongoose from 'mongoose';
import { FastifyInstance } from 'fastify';
import { env } from '../utils/config.js';

export async function initDatabase(app: FastifyInstance): Promise<void> {
  try {
    mongoose.set('strictQuery', true);
    await mongoose.connect(env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      autoIndex: false, // In production, indexes are managed explicitly via controlled migration CLI
    });
    app.log.info({ uri: env.MONGODB_URI.replace(/\/\/.*@/, '//***@') }, 'MongoDB connected successfully');
  } catch (error) {
    app.log.error({ err: error }, 'MongoDB connection failed');
    // Allow app to start even if DB is temporarily connecting, or fail fast
    if (env.NODE_ENV === 'production') {
      throw error;
    }
  }

  app.addHook('onClose', async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
      app.log.info('MongoDB disconnected');
    }
  });
}
