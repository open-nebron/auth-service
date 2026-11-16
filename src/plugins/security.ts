import { FastifyInstance, FastifyRequest } from 'fastify';
import fastifyHelmet from '@fastify/helmet';
import fastifyCors from '@fastify/cors';
import fastifyRateLimit from '@fastify/rate-limit';
import { Redis } from 'ioredis';
import { Config } from '../lib/config.js';
import { RateLimitError } from '../lib/errors.js';

export async function registerSecurityPlugins(
  app: FastifyInstance,
  config: Config,
  redisClient: Redis
): Promise<void> {
  // Helmet-style security headers
  await app.register(fastifyHelmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'validator.swagger.io'],
      },
    },
    crossOriginEmbedderPolicy: false,
  });

  // CORS configuration
  const allowedOrigins = config.ALLOWED_ORIGINS.split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  await app.register(fastifyCors, {
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl)
      if (!origin) {
        callback(null, true);
        return;
      }
      if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
        callback(null, true);
        return;
      }
      callback(new Error('Not allowed by CORS'), false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  // Rate limiting backed by Redis
  await app.register(fastifyRateLimit, {
    global: false, // Per-route rate limiting
    redis: redisClient,
    errorResponseBuilder: () => ({
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests, please try again later',
      },
    }),
  });
}

/**
 * PreHandler hook for /auth/login to enforce 5 requests per minute per email.
 */
export function createEmailRateLimiter(redis: Redis) {
  return async (request: FastifyRequest): Promise<void> => {
    const body = request.body as { email?: unknown } | undefined;
    if (body && typeof body.email === 'string') {
      const normalizedEmail = body.email.trim().toLowerCase();
      if (normalizedEmail) {
        const key = `ratelimit:login:email:${normalizedEmail}`;
        const count = await redis.incr(key);
        if (count === 1) {
          await redis.expire(key, 60);
        }
        if (count > 5) {
          throw new RateLimitError('Too many login attempts for this email, please try again later');
        }
      }
    }
  };
}
