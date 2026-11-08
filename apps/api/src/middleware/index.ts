/**
 * Centralized Fastify Middleware & Authentication Hooks
 */
export {
  authenticate,
  optionalAuthenticate,
  requireRole,
} from '../modules/auth/middleware.js';
export type { TokenPayload } from '../utils/auth.js';
