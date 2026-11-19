import { MongoMemoryServer } from 'mongodb-memory-server';
import RedisMock from 'ioredis-mock';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { FastifyInstance } from 'fastify';
import { Database } from '../src/lib/db.js';
import { RedisClientManager } from '../src/lib/redis.js';
import { KeyManager } from '../src/modules/keys/key-manager.js';
import { RedisStreamsEventPublisher } from '../src/modules/events/publisher.js';
import { buildApp } from '../src/app.js';
import { Config } from '../src/lib/config.js';
import { Redis } from 'ioredis';

export interface TestContext {
  app: FastifyInstance;
  db: Database;
  redis: Redis;
  keyManager: KeyManager;
  publisher: RedisStreamsEventPublisher;
  cleanup: () => Promise<void>;
  resetData: () => Promise<void>;
}

export async function createTestContext(): Promise<TestContext> {
  const mongod = await MongoMemoryServer.create();
  const mongoUri = mongod.getUri();

  const redis = new RedisMock() as unknown as Redis;
  const redisManager = new RedisClientManager(redis);

  const tempSecretsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nebron-auth-keys-'));
  const privKeyPath = path.join(tempSecretsDir, 'jwt_private.pem');
  const pubKeyPath = path.join(tempSecretsDir, 'jwt_public.pem');

  const config: Config = {
    PORT: 4001,
    MONGO_URL: mongoUri,
    REDIS_URL: 'redis://localhost:6379',
    JWT_PRIVATE_KEY_PATH: privKeyPath,
    JWT_PUBLIC_KEY_PATH: pubKeyPath,
    JWT_CURRENT_KID: 'test-kid-1',
    ACCESS_TOKEN_TTL_SECONDS: 900,
    REFRESH_TOKEN_TTL_DAYS: 30,
    ALLOWED_ORIGINS: 'http://localhost:3000,http://localhost:8081',
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
  };

  const db = new Database(mongoUri);
  await db.connect();

  const keyManager = new KeyManager({
    privateKeyPath: privKeyPath,
    publicKeyPath: pubKeyPath,
    currentKid: config.JWT_CURRENT_KID,
    isProduction: false,
  });
  await keyManager.initialize();

  const publisher = new RedisStreamsEventPublisher(redis);

  const openApiPath = path.resolve(process.cwd(), 'openapi.yaml');

  const app = await buildApp({
    config,
    db,
    redisManager,
    keyManager,
    publisher,
    openApiPath,
  });

  await app.ready();

  const resetData = async () => {
    await db.users.deleteMany({});
    await db.sessions.deleteMany({});
    await redis.flushall();
  };

  const cleanup = async () => {
    await app.close();
    await db.disconnect();
    await mongod.stop();
    if (fs.existsSync(tempSecretsDir)) {
      fs.rmSync(tempSecretsDir, { recursive: true, force: true });
    }
  };

  return {
    app,
    db,
    redis,
    keyManager,
    publisher,
    cleanup,
    resetData,
  };
}
