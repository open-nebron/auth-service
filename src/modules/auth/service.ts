import { ObjectId } from 'mongodb';
import { Redis } from 'ioredis';
import { UAParser } from 'ua-parser-js';
import { Database, UserDocument, SessionDocument } from '../../lib/db.js';
import { KeyManager } from '../keys/key-manager.js';
import { EventPublisher } from '../events/publisher.js';
import { capture } from '../../lib/analytics.js';
import {
  generateOpaqueToken,
  hashSha256,
  hashPassword,
  verifyPassword,
  verifyDummyPassword,
} from '../../lib/crypto.js';
import {
  EmailConflictError,
  InvalidCredentialsError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  TokenExpiredError,
  TokenRevokedError,
} from '../../lib/errors.js';
import { RegisterInput, LoginInput, RefreshInput, LogoutInput } from './schemas.js';

export interface TokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface UserMeResponse {
  userId: string;
  email: string;
  sessionId: string;
}

export interface SessionItem {
  sessionId: string;
  userAgent: {
    browser: string;
    os: string;
    deviceType: string;
    deviceName: string;
  };
  ip: string;
  lastActiveAt: string;
  createdAt: string;
  isCurrent: boolean;
  isActive: boolean;
}

function parseUserAgent(uaString: string | null) {
  if (!uaString) {
    return {
      browser: 'Unknown Browser',
      os: 'Unknown OS',
      deviceType: 'desktop',
      deviceName: 'Unknown Device',
    };
  }
  const parser = new UAParser(uaString);
  const browserData = parser.getBrowser();
  const osData = parser.getOS();
  const deviceData = parser.getDevice();

  const browser = [browserData.name, browserData.major].filter(Boolean).join(' ') || 'Unknown Browser';
  const os = [osData.name, osData.version].filter(Boolean).join(' ') || 'Unknown OS';
  const deviceType = deviceData.type || 'desktop';
  const deviceName =
    deviceData.model ||
    (deviceData.vendor ? `${deviceData.vendor} ${deviceData.model || ''}`.trim() : osData.name || 'Unknown Device');

  return {
    browser,
    os,
    deviceType,
    deviceName,
  };
}

export class AuthService {
  private db: Database;
  private keyManager: KeyManager;
  private publisher: EventPublisher;
  private redisClient?: Redis;
  private accessTokenTtlSeconds: number;
  private refreshTokenTtlDays: number;

  constructor(options: {
    db: Database;
    keyManager: KeyManager;
    publisher: EventPublisher;
    redisClient?: Redis;
    accessTokenTtlSeconds: number;
    refreshTokenTtlDays: number;
  }) {
    this.db = options.db;
    this.keyManager = options.keyManager;
    this.publisher = options.publisher;
    this.redisClient = options.redisClient;
    this.accessTokenTtlSeconds = options.accessTokenTtlSeconds;
    this.refreshTokenTtlDays = options.refreshTokenTtlDays;
  }

  async register(input: RegisterInput): Promise<{ userId: string }> {
    const normalizedEmail = input.email.trim().toLowerCase();

    // Check if user already exists
    const existing = await this.db.users.findOne({ email: normalizedEmail });
    if (existing) {
      // Dummy verification to mitigate timing attack
      await verifyDummyPassword(input.password);
      throw new EmailConflictError('Email is already registered');
    }

    const passwordHash = await hashPassword(input.password);
    const now = new Date();
    const newUser: UserDocument = {
      _id: new ObjectId(),
      email: normalizedEmail,
      passwordHash,
      emailVerified: false,
      status: 'active',
      createdAt: now,
      updatedAt: now,
      lastLoginAt: null,
    };

    try {
      await this.db.users.insertOne(newUser);
    } catch (err: unknown) {
      // In case of unique index race condition
      if (typeof err === 'object' && err !== null && 'code' in err && (err as { code: number }).code === 11000) {
        await verifyDummyPassword(input.password);
        throw new EmailConflictError('Email is already registered');
      }
      throw err;
    }

    const userIdStr = newUser._id.toString();

    // Publish event
    await this.publisher.publishUserRegistered({
      userId: userIdStr,
      email: newUser.email,
      createdAt: now,
    });

    if (this.redisClient) {
      try {
        const nowMs = now.getTime();
        await this.redisClient.zadd('live:signups_last_hour', nowMs, userIdStr);
        await this.redisClient.zremrangebyscore('live:signups_last_hour', 0, nowMs - 3_600_000);
        await this.redisClient.expire('live:signups_last_hour', 7200);
      } catch {
        // Best-effort live signup counter (approximate)
      }
    }

    capture(userIdStr, 'user_registered', { email: newUser.email });

    return { userId: userIdStr };
  }

  async login(
    input: LoginInput,
    meta: { userAgent?: string; ip?: string }
  ): Promise<TokenResponse> {
    const normalizedEmail = input.email.trim().toLowerCase();

    const user = await this.db.users.findOne({ email: normalizedEmail });
    if (!user) {
      await verifyDummyPassword(input.password);
      throw new InvalidCredentialsError('Invalid email or password');
    }

    const isValid = await verifyPassword(user.passwordHash, input.password);
    if (!isValid) {
      throw new InvalidCredentialsError('Invalid email or password');
    }

    if (user.status !== 'active') {
      throw new UnauthorizedError('Account is disabled');
    }

    const now = new Date();
    await this.db.users.updateOne(
      { _id: user._id },
      { $set: { lastLoginAt: now, updatedAt: now } }
    );

    const refreshToken = generateOpaqueToken(32);
    const refreshTokenHash = hashSha256(refreshToken);
    const expiresAt = new Date(Date.now() + this.refreshTokenTtlDays * 24 * 60 * 60 * 1000);

    const sessionId = new ObjectId();
    const session: SessionDocument = {
      _id: sessionId,
      userId: user._id,
      familyId: sessionId,
      refreshTokenHash,
      userAgent: meta.userAgent || null,
      ip: meta.ip || null,
      expiresAt,
      createdAt: now,
      lastActiveAt: now,
      revokedAt: null,
    };

    await this.db.sessions.insertOne(session);

    capture(user._id.toString(), 'user_logged_in', { method: 'password' });

    const accessToken = await this.keyManager.signAccessToken(
      {
        userId: user._id.toString(),
        email: user.email,
        sessionId: sessionId.toString(),
      },
      this.accessTokenTtlSeconds
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: this.accessTokenTtlSeconds,
    };
  }

  async refresh(
    input: RefreshInput,
    meta: { userAgent?: string; ip?: string }
  ): Promise<TokenResponse> {
    const refreshTokenHash = hashSha256(input.refreshToken);
    const session = await this.db.sessions.findOne({ refreshTokenHash });

    if (!session) {
      throw new UnauthorizedError('Invalid refresh token');
    }

    // Reuse detection: if presented token is already revoked -> revoke entire session chain, return 401
    if (session.revokedAt !== null) {
      const familyId = session.familyId || session._id;
      await this.db.sessions.updateMany(
        { $or: [{ familyId }, { userId: session.userId }], revokedAt: null },
        { $set: { revokedAt: new Date() } }
      );

      await this.publisher.publishSessionRevoked({
        userId: session.userId.toString(),
        sessionId: session._id.toString(),
        reason: 'reuse_detected',
      });

      throw new TokenRevokedError('Refresh token has been revoked');
    }

    if (session.expiresAt.getTime() <= Date.now()) {
      throw new TokenExpiredError('Refresh token has expired');
    }

    const user = await this.db.users.findOne({ _id: session.userId });
    if (!user || user.status !== 'active') {
      throw new UnauthorizedError('Account is inactive or not found');
    }

    const now = new Date();

    // Revoke old session token
    await this.db.sessions.updateOne(
      { _id: session._id },
      { $set: { revokedAt: now } }
    );

    // Issue new refresh token
    const newRefreshToken = generateOpaqueToken(32);
    const newRefreshTokenHash = hashSha256(newRefreshToken);
    const newExpiresAt = new Date(Date.now() + this.refreshTokenTtlDays * 24 * 60 * 60 * 1000);

    const newSessionId = new ObjectId();
    const newSession: SessionDocument = {
      _id: newSessionId,
      userId: session.userId,
      familyId: session.familyId || session._id,
      refreshTokenHash: newRefreshTokenHash,
      userAgent: meta.userAgent || session.userAgent,
      ip: meta.ip || session.ip,
      expiresAt: newExpiresAt,
      createdAt: now,
      lastActiveAt: now,
      revokedAt: null,
    };

    await this.db.sessions.insertOne(newSession);

    capture(user._id.toString(), 'session_refreshed', { sessionId: newSessionId.toString() });

    const accessToken = await this.keyManager.signAccessToken(
      {
        userId: user._id.toString(),
        email: user.email,
        sessionId: newSessionId.toString(),
      },
      this.accessTokenTtlSeconds
    );

    return {
      accessToken,
      refreshToken: newRefreshToken,
      expiresIn: this.accessTokenTtlSeconds,
    };
  }

  async logout(input: LogoutInput): Promise<void> {
    const refreshTokenHash = hashSha256(input.refreshToken);
    const session = await this.db.sessions.findOne({ refreshTokenHash });

    if (session && session.revokedAt === null) {
      const now = new Date();
      await this.db.sessions.updateOne(
        { _id: session._id },
        { $set: { revokedAt: now } }
      );

      await this.publisher.publishSessionRevoked({
        userId: session.userId.toString(),
        sessionId: session._id.toString(),
        reason: 'user_logout',
      });

      capture(session.userId.toString(), 'user_logged_out', { reason: 'user_logout' });
    }

    // Idempotent: always succeed
  }

  async revokeAllUserSessions(userId: string, reason = 'admin_action'): Promise<number> {
    const userObjId = ObjectId.isValid(userId) ? new ObjectId(userId) : null;
    if (!userObjId) return 0;
    const now = new Date();
    const res = await this.db.sessions.updateMany(
      { userId: userObjId, revokedAt: null },
      { $set: { revokedAt: now } }
    );
    await this.publisher.publishSessionRevoked({
      userId,
      sessionId: 'all',
      reason,
    });
    return res.modifiedCount;
  }

  async getSessions(userId: string, currentSessionId: string): Promise<{ sessions: SessionItem[] }> {
    const userObjId = ObjectId.isValid(userId) ? new ObjectId(userId) : null;
    if (!userObjId) return { sessions: [] };

    const now = new Date();
    const sessions = await this.db.sessions
      .find({
        userId: userObjId,
        revokedAt: null,
        expiresAt: { $gt: now },
      })
      .toArray();

    const thirtyMinutesAgo = Date.now() - 30 * 60 * 1000;

    const sessionItems: SessionItem[] = await Promise.all(
      sessions.map(async (sess) => {
        const sid = sess._id.toString();
        const isCurrent = sid === currentSessionId;
        let lastActiveMs = sess.lastActiveAt ? sess.lastActiveAt.getTime() : sess.createdAt.getTime();

        if (this.redisClient) {
          try {
            const redisLastActive = await this.redisClient.get(`session:last_active:${sid}`);
            if (redisLastActive) {
              const redisMs = new Date(redisLastActive).getTime();
              if (!isNaN(redisMs) && redisMs > lastActiveMs) {
                lastActiveMs = redisMs;
              }
            }
          } catch {
            // Redis error fallback
          }
        }

        if (isCurrent) {
          lastActiveMs = Math.max(lastActiveMs, Date.now());
        }

        const isActive = lastActiveMs >= thirtyMinutesAgo;

        return {
          sessionId: sid,
          userAgent: parseUserAgent(sess.userAgent),
          ip: sess.ip || 'Unknown',
          lastActiveAt: new Date(lastActiveMs).toISOString(),
          createdAt: sess.createdAt.toISOString(),
          isCurrent,
          isActive,
        };
      })
    );

    // Sort by lastActiveAt DESC
    sessionItems.sort((a, b) => new Date(b.lastActiveAt).getTime() - new Date(a.lastActiveAt).getTime());

    return { sessions: sessionItems };
  }

  async revokeSession(
    userId: string,
    targetSessionId: string,
    currentSessionId: string
  ): Promise<{ isCurrent: boolean }> {
    if (!ObjectId.isValid(targetSessionId)) {
      throw new NotFoundError('Session not found');
    }
    const session = await this.db.sessions.findOne({ _id: new ObjectId(targetSessionId) });
    if (!session) {
      throw new NotFoundError('Session not found');
    }
    if (session.userId.toString() !== userId) {
      throw new ForbiddenError('Cannot revoke another user session');
    }

    const now = new Date();
    await this.db.sessions.updateOne(
      { _id: session._id },
      { $set: { revokedAt: now } }
    );

    await this.publisher.publishSessionRevokedDevice({
      userId,
      sessionId: targetSessionId,
      reason: 'user_revoked_device',
      at: now,
    });

    return { isCurrent: targetSessionId === currentSessionId };
  }

  async revokeOtherSessions(
    userId: string,
    currentSessionId: string
  ): Promise<{ revokedCount: number }> {
    const userObjId = ObjectId.isValid(userId) ? new ObjectId(userId) : null;
    if (!userObjId) return { revokedCount: 0 };

    const currentObjId = ObjectId.isValid(currentSessionId) ? new ObjectId(currentSessionId) : null;
    const filter: Record<string, unknown> = {
      userId: userObjId,
      revokedAt: null,
    };
    if (currentObjId) {
      filter._id = { $ne: currentObjId };
    }

    const sessionsToRevoke = await this.db.sessions.find(filter).toArray();
    const now = new Date();
    const result = await this.db.sessions.updateMany(filter, { $set: { revokedAt: now } });

    for (const sess of sessionsToRevoke) {
      await this.publisher.publishSessionRevokedDevice({
        userId,
        sessionId: sess._id.toString(),
        reason: 'user_revoked_device',
        at: now,
      });
    }

    return { revokedCount: result.modifiedCount };
  }

  async me(accessToken: string): Promise<UserMeResponse> {
    const payload = await this.keyManager.verifyAccessToken(accessToken);
    return {
      userId: payload.sub,
      email: payload.email,
      sessionId: payload.sid,
    };
  }
}
