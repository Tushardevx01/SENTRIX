import { FastifyRequest, FastifyReply } from 'fastify';
import { verifyToken, TokenPayload } from '../../utils/auth.js';

declare module 'fastify' {
  interface FastifyRequest {
    user?: TokenPayload;
  }
}

/**
 * Strict authentication preHandler hook requiring a valid Bearer token.
 */
export async function authenticate(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return reply.status(401).send({
      error: 'UNAUTHORIZED',
      message: 'Missing or malformed Authorization header. Expected Bearer token.',
    });
  }

  const token = authHeader.substring(7).trim();
  try {
    const payload = verifyToken(token);
    request.user = payload;
  } catch (err: any) {
    return reply.status(401).send({
      error: 'UNAUTHORIZED',
      message: err.message || 'Invalid authentication token',
    });
  }
}

/**
 * Optional authentication hook: sets request.user if valid token provided, continues if absent.
 */
export async function optionalAuthenticate(request: FastifyRequest, _reply: FastifyReply): Promise<void> {
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return;
  }

  const token = authHeader.substring(7).trim();
  try {
    const payload = verifyToken(token);
    request.user = payload;
  } catch {
    // Continue unauthenticated
  }
}

/**
 * Role-Based Access Control (RBAC) guard.
 */
export function requireRole(allowedRoles: Array<'user' | 'analyst' | 'admin'>) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!request.user) {
      return reply.status(401).send({
        error: 'UNAUTHORIZED',
        message: 'Authentication required for this resource.',
      });
    }

    if (!allowedRoles.includes(request.user.role)) {
      return reply.status(403).send({
        error: 'FORBIDDEN',
        message: `Access denied. Requires one of the following roles: ${allowedRoles.join(', ')}.`,
      });
    }
  };
}

