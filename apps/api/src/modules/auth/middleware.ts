import { FastifyRequest, FastifyReply } from 'fastify';
import { verifyToken, TokenPayload } from '../../utils/auth.js';
import { UserModel } from '../../models/User.js';

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
 * Validates role claims and checks role revocation against the persistent user store.
 */
export function requireRole(allowedRoles: Array<'user' | 'analyst' | 'admin'>) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!request.user) {
      return reply.status(401).send({
        error: 'UNAUTHORIZED',
        message: 'Authentication required for this resource.',
      });
    }

    // Role-revocation enforcement: verify user still exists and roleVersion matches database
    try {
      const user = await UserModel.findById(request.user.sub).select('role roleVersion').lean();
      if (!user) {
        return reply.status(401).send({
          error: 'UNAUTHORIZED',
          message: 'User account no longer exists.',
        });
      }

      const dbRoleVersion = (user as any).roleVersion ?? 1;
      const tokenRoleVersion = request.user.roleVersion ?? 1;

      if ((user as any).role !== request.user.role || dbRoleVersion !== tokenRoleVersion) {
        return reply.status(401).send({
          error: 'UNAUTHORIZED',
          message: 'User privileges or credentials have been revoked. Please re-authenticate.',
        });
      }
    } catch (err: any) {
      // If DB check fails, fail-closed
      return reply.status(500).send({
        error: 'INTERNAL_ERROR',
        message: 'Failed to verify authorization state.',
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
