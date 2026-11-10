import path from 'node:path';
import dotenv from 'dotenv';
import { z } from 'zod';

// Explicitly resolve the single root-level .env file from possible invocation roots
dotenv.config({ path: path.resolve(process.cwd(), '.env') });
dotenv.config({ path: path.resolve(process.cwd(), '../../.env') });

const isTestEnv = process.env.NODE_ENV === 'test';

const EnvSchema = z
  .object({
    PORT: z.coerce.number().default(8000),
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    MONGODB_URI: z
      .string()
      .min(1, 'MONGODB_URI is required')
      .default(isTestEnv ? 'mongodb://127.0.0.1:27017/sentrix_test' : (undefined as any)),
    SCANNER_INTERNAL_URL: z
      .string()
      .url('SCANNER_INTERNAL_URL must be a valid URL')
      .default(isTestEnv ? 'http://127.0.0.1:8001' : (undefined as any)),
    SCANNER_API_SECRET: z
      .string()
      .min(16, 'SCANNER_API_SECRET must be at least 16 characters')
      .default(isTestEnv ? 'sentrix-test-scanner-secret-min16chars!' : (undefined as any)),
    CORS_ORIGIN: z.string().default('http://localhost:3000'),
    JWT_SECRET: z
      .string()
      .min(32, 'JWT_SECRET must be at least 32 characters for HMAC-SHA256')
      .default('sentrix-default-jwt-secret-key-32chars!!'),
    LLM_API_KEY: z.string().optional(),
    BLOCKCHAIN_ENABLED: z.coerce.boolean().default(true),
    BLOCKCHAIN_RPC_URL: z.string().optional(),
    ETHEREUM_RPC_URL: z.string().optional(),
    BLOCKCHAIN_PRIVATE_KEY: z.string().optional(),
    ETHEREUM_PRIVATE_KEY: z.string().optional(),
    THREAT_REGISTRY_CONTRACT_ADDRESS: z.string().optional(),
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
  PORT: process.env.API_PORT || (process.env.PORT && process.env.PORT !== '3000' ? process.env.PORT : 8000),
  NODE_ENV: process.env.NODE_ENV,
  MONGODB_URI:
    process.env.TEST_MONGODB_URI ||
    process.env.MONGODB_URI ||
    (isTestEnv ? 'mongodb://127.0.0.1:27017/sentrix_test' : undefined),
  SCANNER_INTERNAL_URL:
    process.env.SCANNER_INTERNAL_URL || (isTestEnv ? 'http://127.0.0.1:8001' : undefined),
  SCANNER_API_SECRET:
    process.env.SCANNER_API_SECRET ||
    (isTestEnv ? 'sentrix-test-scanner-secret-min16chars!' : undefined),
  CORS_ORIGIN: process.env.CORS_ORIGIN,
  JWT_SECRET: process.env.JWT_SECRET || process.env.SCANNER_API_SECRET || 'sentrix-default-jwt-secret-key-32chars!!',
  LLM_API_KEY: process.env.LLM_API_KEY,
  BLOCKCHAIN_ENABLED: process.env.BLOCKCHAIN_ENABLED,
  BLOCKCHAIN_RPC_URL: process.env.BLOCKCHAIN_RPC_URL || process.env.ETHEREUM_RPC_URL,
  ETHEREUM_RPC_URL: process.env.ETHEREUM_RPC_URL || process.env.BLOCKCHAIN_RPC_URL,
  BLOCKCHAIN_PRIVATE_KEY: process.env.BLOCKCHAIN_PRIVATE_KEY || process.env.ETHEREUM_PRIVATE_KEY,
  ETHEREUM_PRIVATE_KEY: process.env.ETHEREUM_PRIVATE_KEY || process.env.BLOCKCHAIN_PRIVATE_KEY,
  THREAT_REGISTRY_CONTRACT_ADDRESS: process.env.THREAT_REGISTRY_CONTRACT_ADDRESS,
};

const parsed = EnvSchema.safeParse(rawConfig);

if (!parsed.success) {
  console.error('❌ Invalid backend environment configuration:', parsed.error.format());
  throw new Error('Invalid backend environment configuration');
}

export const env = parsed.data;
export type AppConfig = z.infer<typeof EnvSchema>;
