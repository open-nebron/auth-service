import fastify, { FastifyInstance } from 'fastify';
import { Config } from './lib/config.js';
import { Database } from './lib/db.js';
import { RedisClientManager } from './lib/redis.js';
import { KeyManager } from './modules/keys/key-manager.js';
import { EventPublisher } from './modules/events/publisher.js';
import { AuthService } from './modules/auth/service.js';
import { registerAuthRoutes } from './modules/auth/routes.js';
import { registerSecurityPlugins } from './plugins/security.js';
import { registerDocs } from './plugins/docs.js';
import { registerErrorHandler } from './plugins/error-handler.js';

export interface AppDependencies {
  config: Config;
  db: Database;
  redisManager: RedisClientManager;
  keyManager: KeyManager;
  publisher: EventPublisher;
  openApiPath?: string;
}

export async function buildApp(deps: AppDependencies): Promise<FastifyInstance> {
  const { config, db, redisManager, keyManager, publisher, openApiPath } = deps;
  const redisClient = redisManager.getClient();

  const isTest = config.NODE_ENV === 'test';

  const app = fastify({
    logger: isTest
      ? false
      : {
          level: config.LOG_LEVEL,
          redact: {
            paths: [
              'req.body.password',
              'req.body.refreshToken',
              'req.headers.authorization',
              'password',
              'passwordHash',
              'refreshToken',
              'refreshTokenHash',
            ],
            censor: '[REDACTED]',
          },
        },
    trustProxy: true,
    bodyLimit: 16384, // 16kb
  });

  // Global Error Handler & 404
  registerErrorHandler(app);

  // Security Plugins (Helmet, CORS, Rate Limit)
  await registerSecurityPlugins(app, config, redisClient);

  // OpenAPI & Swagger UI
  await registerDocs(app, openApiPath);

  // Business Service
  const authService = new AuthService({
    db,
    keyManager,
    publisher,
    accessTokenTtlSeconds: config.ACCESS_TOKEN_TTL_SECONDS,
    refreshTokenTtlDays: config.REFRESH_TOKEN_TTL_DAYS,
  });

  // Auth Routes
  registerAuthRoutes(app, {
    authService,
    keyManager,
    db,
    redisManager,
    redisClient,
  });

  return app;
}
