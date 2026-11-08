import path from 'node:path';
import dotenv from 'dotenv';
import { z } from 'zod';

// Explicitly resolve the single root-level .env file from possible invocation roots
dotenv.config({ path: path.resolve(process.cwd(), '.env') });
dotenv.config({ path: path.resolve(process.cwd(), '../../.env') });

const EnvSchema = z
  .object({
    PORT: z.coerce.number().default(8000),
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    MONGODB_URI: z.string().min(1, 'MONGODB_URI is required'),
    SCANNER_INTERNAL_URL: z.string().url('SCANNER_INTERNAL_URL must be a valid URL'),
    SCANNER_API_SECRET: z.string().min(16, 'SCANNER_API_SECRET must be at least 16 characters'),
    CORS_ORIGIN: z.string().default('http://localhost:3000'),
    JWT_SECRET: z
      .string()
      .min(32, 'JWT_SECRET must be at least 32 characters for HMAC-SHA256')
      .default('sentrix-default-jwt-secret-key-32chars!!'),
  })
  .refine(
    (data) => {
      if (data.NODE_ENV === 'production') {
        return (
          data.JWT_SECRET !== 'sentrix-default-jwt-secret-key-32chars!!' &&
          data.JWT_SECRET.length >= 32
        );
      }
      return true;
    },
    {
      message: 'In production, JWT_SECRET must be explicitly configured with at least 32 characters.',
      path: ['JWT_SECRET'],
    }
  );

const rawConfig = {
  PORT: process.env.PORT || process.env.API_PORT || 8000,
  NODE_ENV: process.env.NODE_ENV,
  MONGODB_URI: process.env.MONGODB_URI,
  SCANNER_INTERNAL_URL: process.env.SCANNER_INTERNAL_URL,
  SCANNER_API_SECRET: process.env.SCANNER_API_SECRET,
  CORS_ORIGIN: process.env.CORS_ORIGIN,
  JWT_SECRET: process.env.JWT_SECRET || process.env.SCANNER_API_SECRET || 'sentrix-default-jwt-secret-key-32chars!!',
};

const parsed = EnvSchema.safeParse(rawConfig);

if (!parsed.success) {
  console.error('❌ Invalid backend environment configuration:', parsed.error.format());
  throw new Error('Invalid backend environment configuration');
}

export const env = parsed.data;
export type AppConfig = z.infer<typeof EnvSchema>;
