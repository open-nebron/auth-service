import { loadConfig } from './lib/config.js';
import { Database } from './lib/db.js';
import { RedisClientManager } from './lib/redis.js';
import { KeyManager } from './modules/keys/key-manager.js';
import { RedisStreamsEventPublisher } from './modules/events/publisher.js';
import { getDummyPasswordHash } from './lib/crypto.js';
import { buildApp } from './app.js';

async function startServer(): Promise<void> {
  const config = loadConfig();

  // Pre-warm dummy password hash for constant-time comparisons
  await getDummyPasswordHash();

  // Connect to MongoDB
  const db = new Database(config.MONGO_URL);
  await db.connect();

  // Connect to Redis
  const redisManager = new RedisClientManager(config.REDIS_URL);
  await redisManager.connect();

  // Initialize Key Manager (loads or generates RSA keypair, JWKS)
  const keyManager = new KeyManager({
    privateKeyPath: config.JWT_PRIVATE_KEY_PATH,
    publicKeyPath: config.JWT_PUBLIC_KEY_PATH,
    currentKid: config.JWT_CURRENT_KID,
    isProduction: config.NODE_ENV === 'production',
  });
  await keyManager.initialize();

  // Event Publisher
  const publisher = new RedisStreamsEventPublisher(redisManager.getClient());

  // Build Fastify App
  const app = await buildApp({
    config,
    db,
    redisManager,
    keyManager,
    publisher,
  });

  // Graceful shutdown
  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM'];
  for (const signal of signals) {
    process.on(signal, async () => {
      app.log.info(`Received ${signal}, initiating graceful shutdown...`);
      try {
        await app.close();
        await redisManager.disconnect();
        await db.disconnect();
        app.log.info('Graceful shutdown completed.');
        process.exit(0);
      } catch (err) {
        app.log.error({ err }, 'Error during shutdown');
        process.exit(1);
      }
    });
  }

  try {
    const address = await app.listen({
      port: config.PORT,
      host: '0.0.0.0',
    });
    app.log.info(`Zenuxs Auth Service running at ${address}`);
    app.log.info(`OpenAPI docs available at ${address}/docs`);
  } catch (err) {
    app.log.error({ err }, 'Failed to start server');
    process.exit(1);
  }
}

startServer().catch((err) => {
  console.error('Fatal boot error:', err);
  process.exit(1);
});
