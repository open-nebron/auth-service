import { ObjectId } from 'mongodb';
import { Database, UserDocument, SessionDocument } from '../../lib/db.js';
import { KeyManager } from '../keys/key-manager.js';
import { EventPublisher } from '../events/publisher.js';
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

export class AuthService {
  private db: Database;
  private keyManager: KeyManager;
  private publisher: EventPublisher;
  private accessTokenTtlSeconds: number;
  private refreshTokenTtlDays: number;

  constructor(options: {
    db: Database;
    keyManager: KeyManager;
    publisher: EventPublisher;
    accessTokenTtlSeconds: number;
    refreshTokenTtlDays: number;
  }) {
    this.db = options.db;
    this.keyManager = options.keyManager;
    this.publisher = options.publisher;
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
      revokedAt: null,
    };

    await this.db.sessions.insertOne(session);

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
      revokedAt: null,
    };

    await this.db.sessions.insertOne(newSession);

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

  async me(accessToken: string): Promise<UserMeResponse> {
    const payload = await this.keyManager.verifyAccessToken(accessToken);
    return {
      userId: payload.sub,
      email: payload.email,
      sessionId: payload.sid,
    };
  }
}
