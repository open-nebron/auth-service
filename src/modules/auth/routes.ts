import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Redis } from 'ioredis';
import { AuthService } from './service.js';
import { KeyManager } from '../keys/key-manager.js';
import { Database } from '../../lib/db.js';
import { RedisClientManager } from '../../lib/redis.js';
import { Config } from '../../lib/config.js';
import { createEmailRateLimiter } from '../../plugins/security.js';
import {
  registerSchema,
  loginSchema,
  refreshSchema,
  logoutSchema,
} from './schemas.js';
import { ValidationError, UnauthorizedError, MissingRefreshTokenError, TokenRevokedError } from '../../lib/errors.js';

export function registerAuthRoutes(
  app: FastifyInstance,
  options: {
    authService: AuthService;
    keyManager: KeyManager;
    db: Database;
    redisManager: RedisClientManager;
    redisClient: Redis;
    config: Config;
  }
): void {
  const { authService, keyManager, db, redisManager, redisClient, config } = options;
  const emailLimiter = createEmailRateLimiter(redisClient);

  const getCookieOptions = () => ({
    path: config.COOKIE_PATH,
    httpOnly: true,
    secure: config.COOKIE_SECURE,
    sameSite: config.COOKIE_SAME_SITE,
    domain: config.COOKIE_DOMAIN,
    maxAge: config.REFRESH_TOKEN_TTL_DAYS * 86400,
  });

  const getClearCookieOptions = () => ({
    path: config.COOKIE_PATH,
    httpOnly: true,
    secure: config.COOKIE_SECURE,
    sameSite: config.COOKIE_SAME_SITE,
    domain: config.COOKIE_DOMAIN,
    maxAge: 0,
  });

  // POST /auth/register
  app.post(
    '/auth/register',
    {
      config: {
        rateLimit: {
          max: 5,
          timeWindow: 60 * 60 * 1000, // 5 per hour per IP
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = registerSchema.safeParse(request.body);
      if (!parsed.success) {
        const msg = parsed.error.issues.map((i) => i.message).join('; ');
        throw new ValidationError(msg);
      }

      const result = await authService.register(parsed.data);
      return reply.status(200).send(result);
    }
  );

  // POST /auth/login
  app.post(
    '/auth/login',
    {
      config: {
        rateLimit: {
          max: 10,
          timeWindow: 60 * 1000, // 10 per minute per IP
        },
      },
      preHandler: [emailLimiter],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = loginSchema.safeParse(request.body);
      if (!parsed.success) {
        const msg = parsed.error.issues.map((i) => i.message).join('; ');
        throw new ValidationError(msg);
      }

      const userAgent = request.headers['user-agent'] as string | undefined;
      const ip = request.ip;

      const result = await authService.login(parsed.data, { userAgent, ip });
      return reply.status(200).send(result);
    }
  );

  // POST /auth/login/cookie
  app.post(
    '/auth/login/cookie',
    {
      config: {
        rateLimit: {
          max: 10,
          timeWindow: 60 * 1000, // 10 per minute per IP
        },
      },
      preHandler: [emailLimiter],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = loginSchema.safeParse(request.body);
      if (!parsed.success) {
        const msg = parsed.error.issues.map((i) => i.message).join('; ');
        throw new ValidationError(msg);
      }

      const userAgent = request.headers['user-agent'] as string | undefined;
      const ip = request.ip;

      const result = await authService.login(parsed.data, { userAgent, ip });

      reply.setCookie('refresh_token', result.refreshToken, getCookieOptions());

      return reply.status(200).send({
        accessToken: result.accessToken,
        expiresIn: result.expiresIn,
      });
    }
  );

  // POST /auth/refresh
  app.post(
    '/auth/refresh',
    {
      config: {
        rateLimit: {
          max: 30,
          timeWindow: 60 * 1000, // 30 per minute per IP
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = refreshSchema.safeParse(request.body);
      if (!parsed.success) {
        const msg = parsed.error.issues.map((i) => i.message).join('; ');
        throw new ValidationError(msg);
      }

      const userAgent = request.headers['user-agent'] as string | undefined;
      const ip = request.ip;

      const result = await authService.refresh(parsed.data, { userAgent, ip });
      return reply.status(200).send(result);
    }
  );

  // POST /auth/refresh/cookie
  app.post(
    '/auth/refresh/cookie',
    {
      config: {
        rateLimit: {
          max: 30,
          timeWindow: 60 * 1000, // 30 per minute per IP
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const refreshToken = request.cookies?.refresh_token;
      if (!refreshToken) {
        throw new MissingRefreshTokenError('Missing refresh token cookie');
      }

      const userAgent = request.headers['user-agent'] as string | undefined;
      const ip = request.ip;

      try {
        const result = await authService.refresh({ refreshToken }, { userAgent, ip });

        reply.setCookie('refresh_token', result.refreshToken, getCookieOptions());

        return reply.status(200).send({
          accessToken: result.accessToken,
          expiresIn: result.expiresIn,
        });
      } catch (err) {
        if (err instanceof TokenRevokedError) {
          reply.clearCookie('refresh_token', getClearCookieOptions());
        }
        throw err;
      }
    }
  );

  // POST /auth/logout
  app.post(
    '/auth/logout',
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = logoutSchema.safeParse(request.body);
      if (!parsed.success) {
        const msg = parsed.error.issues.map((i) => i.message).join('; ');
        throw new ValidationError(msg);
      }

      await authService.logout(parsed.data);
      return reply.status(204).send();
    }
  );

  // POST /auth/logout/cookie
  app.post(
    '/auth/logout/cookie',
    {
      config: {
        rateLimit: {
          max: 30,
          timeWindow: 60 * 1000, // 30 per minute per IP
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const refreshToken = request.cookies?.refresh_token;
      if (refreshToken) {
        await authService.logout({ refreshToken });
      }

      reply.clearCookie('refresh_token', getClearCookieOptions());

      return reply.status(204).send();
    }
  );

  // GET /auth/me
  app.get(
    '/auth/me',
    async (request: FastifyRequest, reply: FastifyReply) => {
      const authHeader = request.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new UnauthorizedError('Missing or invalid Authorization header');
      }

      const token = authHeader.slice(7).trim();
      if (!token) {
        throw new UnauthorizedError('Missing access token');
      }

      const result = await authService.me(token);
      return reply.status(200).send(result);
    }
  );

  // GET /.well-known/jwks.json
  app.get(
    '/.well-known/jwks.json',
    async (_request: FastifyRequest, reply: FastifyReply) => {
      reply.header('Cache-Control', 'public, max-age=3600');
      return reply.status(200).send(keyManager.getJwks());
    }
  );

  // GET /health
  app.get(
    '/health',
    async (_request: FastifyRequest, reply: FastifyReply) => {
      const [dbOk, redisOk] = await Promise.all([
        db.ping(),
        redisManager.ping(),
      ]);

      const isHealthy = dbOk && redisOk;
      const statusCode = isHealthy ? 200 : 503;

      return reply.status(statusCode).send({
        status: isHealthy ? 'ok' : 'error',
        db: dbOk ? 'ok' : 'error',
        redis: redisOk ? 'ok' : 'error',
      });
    }
  );
}
