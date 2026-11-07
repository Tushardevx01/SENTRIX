import { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { UserRegisterSchema, UserLoginSchema } from '@sentrix/shared';
import { UserModel } from '../../models/User.js';
import { hashPassword, verifyPassword, createToken } from '../../utils/auth.js';
import { authenticate } from './middleware.js';

export const authRoutes: FastifyPluginAsync = async (app: FastifyInstance) => {
  /**
   * POST /api/v1/auth/register
   * Registers a new user account with secure password hashing.
   */
  app.post('/register', async (request, reply) => {
    const parseResult = UserRegisterSchema.safeParse(request.body);
    if (!parseResult.success) {
      return reply.status(400).send({
        error: 'VALIDATION_ERROR',
        message: parseResult.error.errors[0]?.message || 'Invalid registration payload',
        details: parseResult.error.format(),
      });
    }

    const { email, password, role } = parseResult.data;
    const normalizedEmail = email.toLowerCase().trim();

    // Check if user already exists
    const existing = await UserModel.findOne({ email: normalizedEmail }).lean();
    if (existing) {
      return reply.status(409).send({
        error: 'CONFLICT',
        message: 'A user with this email address already exists.',
      });
    }

    const passwordHash = hashPassword(password);
    const user = await UserModel.create({
      email: normalizedEmail,
      passwordHash,
      role: role || 'user',
    });

    const token = createToken({
      sub: user._id.toString(),
      email: user.email,
      role: user.role,
    });

    return reply.status(201).send({
      token,
      user: {
        _id: user._id.toString(),
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
      },
    });
  });

  /**
   * POST /api/v1/auth/login
   * Authenticates user credentials and issues a JWT token.
   */
  app.post('/login', async (request, reply) => {
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
      return reply.status(401).send({
        error: 'INVALID_CREDENTIALS',
        message: 'Invalid email address or password.',
      });
    }

    const isValid = verifyPassword(password, user.passwordHash);
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
  });

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
};
