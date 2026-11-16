import { Redis } from 'ioredis';

export interface UserRegisteredPayload {
  userId: string;
  email: string;
  createdAt: string | Date;
}

export interface SessionRevokedPayload {
  userId: string;
  sessionId: string;
  reason: string;
}

export interface EventPublisher {
  publishUserRegistered(data: UserRegisteredPayload): Promise<void>;
  publishSessionRevoked(data: SessionRevokedPayload): Promise<void>;
}

export class RedisStreamsEventPublisher implements EventPublisher {
  private redis: Redis;
  private readonly streamKey = 'zenuxs.events';

  constructor(redis: Redis) {
    this.redis = redis;
  }

  async publishUserRegistered(data: UserRegisteredPayload): Promise<void> {
    const payload = {
      userId: data.userId,
      email: data.email,
      createdAt: data.createdAt instanceof Date ? data.createdAt.toISOString() : data.createdAt,
    };
    await this.redis.xadd(
      this.streamKey,
      '*',
      'type',
      'auth.user.registered',
      'payload',
      JSON.stringify(payload)
    );
  }

  async publishSessionRevoked(data: SessionRevokedPayload): Promise<void> {
    const payload = {
      userId: data.userId,
      sessionId: data.sessionId,
      reason: data.reason,
    };
    await this.redis.xadd(
      this.streamKey,
      '*',
      'type',
      'auth.session.revoked',
      'payload',
      JSON.stringify(payload)
    );
  }
}
