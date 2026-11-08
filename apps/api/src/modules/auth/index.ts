import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import mongoose from 'mongoose';
import { UserRegisterSchema, UserLoginSchema, UserRoleUpdateSchema } from '@sentrix/shared';
import { UserModel, IUserDocument } from '../../models/User.js';
import {
  hashPassword,
  verifyPassword,
  dummyVerifyPassword,
  createToken,
} from '../../utils/auth.js';
import { authenticate, requireRole } from './middleware.js';

/**
 * Executes an administrative role mutation under a distributed atomic lock in MongoDB.
 * Serializes concurrent administrative role modifications, preventing race conditions (write skew)
 * where two concurrent requests could demote the last two administrators simultaneously.
 */
export async function executeWithAdminRoleLock<T>(
  operatorId: string,
  action: () => Promise<T>
): Promise<T> {
  const db = mongoose.connection.db;
  if (!db) {
    // Unit/mocked test fallback when database is not connected
    return await action();
  }

  const locksColl = db.collection<{ _id: string; [key: string]: any }>('_auth_locks');
  const lockKey = 'admin_role_mutation';
  const lockTimeoutMs = 5000;
  const maxRetries = 25;
  const retryDelayMs = 80;

  let acquired = false;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const lockCutoff = new Date(Date.now() - lockTimeoutMs);
    try {
      const res = await locksColl.findOneAndUpdate(
        {
          _id: lockKey,
          $or: [
            { locked: false },
            { lockedAt: { $lt: lockCutoff } },
            { lockedAt: { $exists: false } },
          ],
        },
        {
          $set: {
            locked: true,
            lockedAt: new Date(),
            lockHolder: operatorId,
            updatedAt: new Date(),
          },
        },
        { upsert: true, returnDocument: 'after' }
      );

      if (res) {
        acquired = true;
        break;
      }
    } catch (err: any) {
      if (err.code !== 11000) {
        throw err;
      }
    }

    await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
  }

  if (!acquired) {
    throw new Error('Administrative operation timeout: unable to acquire mutual exclusion lock.');
  }

  try {
    return await action();
  } finally {
    try {
      await locksColl.updateOne(
        { _id: lockKey, lockHolder: operatorId },
        {
          $set: {
            locked: false,
            releasedAt: new Date(),
            updatedAt: new Date(),
          },
        }
      );
    } catch {
      // Best-effort release; cutoff timer clears stale locks if this fails
    }
  }
}

export const authRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  /**
   * POST /api/v1/auth/register
   * Registers a new user account with secure password hashing.
   * Security Invariant: Public registration strictly creates accounts with role: 'user'.
   * Client-supplied role parameters are strictly ignored and prohibited.
   */
  app.post(
    '/register',
    {
      config: {
        rateLimit: {
          max: 10,
          timeWindow: '1 minute',
        },
      },
    },
    async (request, reply) => {
      const parseResult = UserRegisterSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          error: 'VALIDATION_ERROR',
          message: parseResult.error.errors[0]?.message || 'Invalid registration payload',
          details: parseResult.error.format(),
        });
      }

      const { email, password } = parseResult.data;
      const normalizedEmail = email.toLowerCase().trim();

      // Check if user already exists
      const existing = await UserModel.findOne({ email: normalizedEmail }).lean();
      if (existing) {
        return reply.status(409).send({
          error: 'CONFLICT',
          message: 'A user with this email address already exists.',
        });
      }

      const passwordHash = await hashPassword(password);
      const user = await UserModel.create({
        email: normalizedEmail,
        passwordHash,
        role: 'user', // Hardcoded security invariant: public registration ALWAYS creates role 'user'
        roleVersion: 1,
      });

      const token = createToken({
        sub: user._id.toString(),
        email: user.email,
        role: 'user',
        roleVersion: 1,
      });

      return reply.status(201).send({
        token,
        user: {
          _id: user._id.toString(),
          email: user.email,
          role: 'user',
          createdAt: user.createdAt,
        },
      });
    }
  );

  /**
   * POST /api/v1/auth/login
   * Authenticates user credentials with timing-safe verification and issues a JWT token.
   */
  app.post(
    '/login',
    {
      config: {
        rateLimit: {
          max: 10,
          timeWindow: '1 minute',
        },
      },
    },
    async (request, reply) => {
      const parseResult = UserLoginSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          error: 'VALIDATION_ERROR',
          message: parseResult.error.errors[0]?.message || 'Invalid login payload',
        });
      }

      const { email, password } = parseResult.data;
      const normalizedEmail = email.toLowerCase().trim();

      // Explicitly select passwordHash which is hidden by default
      const user = await UserModel.findOne({ email: normalizedEmail }).select('+passwordHash');
      if (!user || !user.passwordHash) {
        // Run dummy verification to neutralize timing side-channels and prevent account enumeration
        await dummyVerifyPassword(password);
        return reply.status(401).send({
          error: 'INVALID_CREDENTIALS',
          message: 'Invalid email address or password.',
        });
      }

      const isValid = await verifyPassword(password, user.passwordHash);
      if (!isValid) {
        return reply.status(401).send({
          error: 'INVALID_CREDENTIALS',
          message: 'Invalid email address or password.',
        });
      }

      const token = createToken({
        sub: user._id.toString(),
        email: user.email,
        role: user.role,
        roleVersion: user.roleVersion ?? 1,
      });

      return reply.status(200).send({
        token,
        user: {
          _id: user._id.toString(),
          email: user.email,
          role: user.role,
          createdAt: user.createdAt,
        },
      });
    }
  );

  /**
   * GET /api/v1/auth/me
   * Retrieves profile details for the currently authenticated user.
   */
  app.get('/me', { preHandler: [authenticate] }, async (request, reply) => {
    const userId = request.user?.sub;
    const user = await UserModel.findById(userId);

    if (!user) {
      return reply.status(404).send({
        error: 'NOT_FOUND',
        message: 'User account not found.',
      });
    }

    return reply.status(200).send({
      user: {
        _id: user._id.toString(),
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
      },
    });
  });

  /**
   * PATCH /api/v1/auth/users/:id/role
   * Updates an existing user's role. Restricted to administrators only.
   * Increments user's roleVersion to immediately revoke stale issued tokens.
   */
  app.patch(
    '/users/:id/role',
    {
      preHandler: [authenticate, requireRole(['admin'])],
    },
    async (request, reply) => {
      const { id } = request.params as { id: string };

      const parseResult = UserRoleUpdateSchema.safeParse(request.body);
      if (!parseResult.success) {
        return reply.status(400).send({
          error: 'VALIDATION_ERROR',
          message: parseResult.error.errors[0]?.message || 'Invalid role update payload',
        });
      }

      const { role: newRole } = parseResult.data;
      const targetUser = await UserModel.findById(id);

      if (!targetUser) {
        return reply.status(404).send({
          error: 'NOT_FOUND',
          message: 'Target user account not found.',
        });
      }

      // Safeguard against demoting the sole remaining administrator.
      // Uses atomic distributed locking and conditional updates to eliminate concurrency race conditions (write skew).
      let updatedUser: IUserDocument | null = null;
      if (targetUser.role === 'admin' && newRole !== 'admin') {
        const updateResult = await executeWithAdminRoleLock(
          request.user?.sub || 'system',
          async () => {
            const totalAdmins = await UserModel.countDocuments({ role: 'admin' });
            if (totalAdmins <= 1) {
              return {
                status: 400,
                error: 'INVALID_OPERATION',
                message: 'Cannot demote the last remaining administrator account.',
              };
            }

            // Atomic update strictly requiring role: 'admin' so roleVersion only increments upon actual match
            const res = await UserModel.findOneAndUpdate(
              { _id: targetUser._id, role: 'admin' },
              {
                $set: { role: newRole },
                $inc: { roleVersion: 1 },
              },
              { new: true }
            );

            if (!res) {
              return {
                status: 404,
                error: 'NOT_FOUND',
                message: 'Administrator account was already modified or demoted.',
              };
            }

            return { status: 200, user: res };
          }
        );

        if (updateResult.status !== 200 || !updateResult.user) {
          return reply.status(updateResult.status).send({
            error: updateResult.error,
            message: updateResult.message,
          });
        }

        updatedUser = updateResult.user;
      } else {
        // Non-demoting role update (e.g. user -> analyst, user -> admin, analyst -> admin)
        updatedUser = await UserModel.findOneAndUpdate(
          { _id: targetUser._id },
          {
            $set: { role: newRole },
            $inc: { roleVersion: 1 },
          },
          { new: true }
        );

        if (!updatedUser) {
          return reply.status(404).send({
            error: 'NOT_FOUND',
            message: 'Target user account not found.',
          });
        }
      }

      if (!updatedUser) {
        return reply.status(500).send({
          error: 'INTERNAL_ERROR',
          message: 'Failed to update user role.',
        });
      }

      app.log.info(
        {
          operatorId: request.user?.sub,
          targetUserId: updatedUser._id.toString(),
          targetEmail: updatedUser.email,
          newRole,
          roleVersion: updatedUser.roleVersion,
        },
        'User role updated by administrator'
      );

      return reply.status(200).send({
        user: {
          _id: updatedUser._id.toString(),
          email: updatedUser.email,
          role: updatedUser.role,
          roleVersion: updatedUser.roleVersion,
          updatedAt: updatedUser.updatedAt,
        },
      });
    }
  );
};
