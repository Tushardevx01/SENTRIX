import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const EnvSchema = z.object({
  PORT: z.coerce.number().default(8000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  MONGODB_URI: z.string().min(1, 'MONGODB_URI is required'),
  SCANNER_INTERNAL_URL: z.string().url('SCANNER_INTERNAL_URL must be a valid URL'),
  SCANNER_API_SECRET: z.string().min(16, 'SCANNER_API_SECRET must be at least 16 characters'),
  CORS_ORIGIN: z.string().default('http://localhost:3000'),
});

const parsed = EnvSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌ Invalid backend environment configuration:', parsed.error.format());
  throw new Error('Invalid backend environment configuration');
}

export const env = parsed.data;
