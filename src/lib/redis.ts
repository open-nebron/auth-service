import { Redis } from 'ioredis';

export class RedisClientManager {
  private client: Redis;

  constructor(target: string | Redis) {
    if (typeof target === 'string') {
      this.client = new Redis(target, {
        maxRetriesPerRequest: 3,
        lazyConnect: true,
        enableReadyCheck: true,
      });
    } else {
      this.client = target;
    }
  }

  async connect(): Promise<Redis> {
    if (this.client.status === 'wait') {
      await this.client.connect();
    }
    return this.client;
  }

  getClient(): Redis {
    return this.client;
  }

  async ping(): Promise<boolean> {
    try {
      const res = await this.client.ping();
      return res === 'PONG';
    } catch {
      return false;
    }
  }

  async disconnect(): Promise<void> {
    if (this.client.status !== 'end' && typeof this.client.quit === 'function') {
      await this.client.quit();
    }
  }
}
