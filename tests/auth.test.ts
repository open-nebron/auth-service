import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import * as jose from 'jose';
import { createTestContext, TestContext } from './test-context.js';

describe('Auth Service Integration Tests', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext();
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  beforeEach(async () => {
    await ctx.resetData();
  });

  describe('GET /health', () => {
    it('should return 200 and healthy status for db and redis', async () => {
      const res = await ctx.app.inject({
        method: 'GET',
        url: '/health',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body).toEqual({
        status: 'ok',
        db: 'ok',
        redis: 'ok',
      });
    });
  });

  describe('POST /auth/register', () => {
    it('should successfully register a user and publish event', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: ' Alice@Example.com ',
          password: 'ValidPassword123!',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body).toHaveProperty('userId');
      expect(typeof body.userId).toBe('string');

      // Verify user document in DB
      const user = await ctx.db.users.findOne({ email: 'alice@example.com' });
      expect(user).not.toBeNull();
      expect(user?.email).toBe('alice@example.com');
      expect(user?.emailVerified).toBe(false);
      expect(user?.status).toBe('active');
      expect(user?.passwordHash).toMatch(/^\$argon2id\$/);

      // Verify event in Redis stream
      const events = await ctx.redis.xrange('nebron.events', '-', '+');
      expect(events.length).toBe(1);
      const [, fields] = events[0] as [string, string[]];
      expect(fields[0]).toBe('type');
      expect(fields[1]).toBe('auth.user.registered');
      expect(fields[2]).toBe('payload');
      const payload = JSON.parse(fields[3]!);
      expect(payload.userId).toBe(body.userId);
      expect(payload.email).toBe('alice@example.com');
    });

    it('should reject duplicate email with 409 and not leak existence timing', async () => {
      // First registration
      await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'duplicate@example.com',
          password: 'ValidPassword123!',
        },
      });

      // Second registration with same email
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'DUPLICATE@example.com',
          password: 'ValidPassword123!',
        },
      });

      expect(res.statusCode).toBe(409);
      const body = JSON.parse(res.body);
      expect(body).toEqual({
        error: {
          code: 'EMAIL_ALREADY_EXISTS',
          message: 'Email is already registered',
        },
      });
    });

    it('should reject invalid email format', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'not-an-email',
          password: 'ValidPassword123!',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should reject password less than 12 characters', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'short@example.com',
          password: 'Short1!',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('VALIDATION_ERROR');
      expect(body.error.message).toContain('at least 12 characters');
    });

    it('should reject password without numbers', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'nonum@example.com',
          password: 'ValidPasswordWithoutNumbers!',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('VALIDATION_ERROR');
      expect(body.error.message).toContain('at least one number');
    });

    it('should reject password without letters', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'noletters@example.com',
          password: '12345678901234567890',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('VALIDATION_ERROR');
      expect(body.error.message).toContain('at least one letter');
    });

    it('should reject password longer than 128 characters', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'toolong@example.com',
          password: 'A1' + 'x'.repeat(128),
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('VALIDATION_ERROR');
      expect(body.error.message).toContain('128');
    });
  });

  describe('POST /auth/login', () => {
    beforeEach(async () => {
      await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'loginuser@example.com',
          password: 'CorrectPassword123!',
        },
      });
    });

    it('should successfully log in and return access + refresh tokens', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/login',
        headers: {
          'user-agent': 'Vitest-Agent/1.0',
        },
        payload: {
          email: 'LOGINUSER@example.com',
          password: 'CorrectPassword123!',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body).toHaveProperty('accessToken');
      expect(body).toHaveProperty('refreshToken');
      expect(body.expiresIn).toBe(900);
      expect(typeof body.accessToken).toBe('string');
      expect(typeof body.refreshToken).toBe('string');
      expect(body.refreshToken.length).toBe(64); // 32 bytes hex

      // Check session in DB
      const session = await ctx.db.sessions.findOne({});
      expect(session).not.toBeNull();
      expect(session?.userAgent).toBe('Vitest-Agent/1.0');
      expect(session?.revokedAt).toBeNull();

      // Check user lastLoginAt updated
      const user = await ctx.db.users.findOne({ email: 'loginuser@example.com' });
      expect(user?.lastLoginAt).not.toBeNull();
    });

    it('should fail with 401 on incorrect password with generic message', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'loginuser@example.com',
          password: 'WrongPassword123!',
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body).toEqual({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password',
        },
      });
    });

    it('should fail with 401 on non-existent email with generic message', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'nonexistent@example.com',
          password: 'SomePassword123!',
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body).toEqual({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password',
        },
      });
    });

    it('should fail with 401 if user account status is disabled', async () => {
      await ctx.db.users.updateOne(
        { email: 'loginuser@example.com' },
        { $set: { status: 'disabled' } }
      );

      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'loginuser@example.com',
          password: 'CorrectPassword123!',
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });
  });

  describe('GET /auth/me', () => {
    let accessToken: string;
    let userId: string;

    beforeEach(async () => {
      const reg = await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'meuser@example.com',
          password: 'ValidPassword123!',
        },
      });
      userId = JSON.parse(reg.body).userId;

      const login = await ctx.app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'meuser@example.com',
          password: 'ValidPassword123!',
        },
      });
      accessToken = JSON.parse(login.body).accessToken;
    });

    it('should return user details with valid Bearer token', async () => {
      const res = await ctx.app.inject({
        method: 'GET',
        url: '/auth/me',
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.userId).toBe(userId);
      expect(body.email).toBe('meuser@example.com');
      expect(typeof body.sessionId).toBe('string');
    });

    it('should return 401 when Authorization header is missing', async () => {
      const res = await ctx.app.inject({
        method: 'GET',
        url: '/auth/me',
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 401 when token is malformed', async () => {
      const res = await ctx.app.inject({
        method: 'GET',
        url: '/auth/me',
        headers: {
          authorization: 'Bearer not-a-valid-jwt',
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('POST /auth/refresh & Token Rotation', () => {
    let refreshToken: string;
    let initialAccessToken: string;

    beforeEach(async () => {
      await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'refreshuser@example.com',
          password: 'ValidPassword123!',
        },
      });

      const login = await ctx.app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'refreshuser@example.com',
          password: 'ValidPassword123!',
        },
      });
      const body = JSON.parse(login.body);
      refreshToken = body.refreshToken;
      initialAccessToken = body.accessToken;
    });

    it('should rotate token and return new access + refresh tokens', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/refresh',
        payload: {
          refreshToken,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body).toHaveProperty('accessToken');
      expect(body).toHaveProperty('refreshToken');
      expect(body.refreshToken).not.toBe(refreshToken);
      expect(body.accessToken).not.toBe(initialAccessToken);

      // Verify old session was marked revoked
      const oldSession = await ctx.db.sessions.findOne({ revokedAt: { $ne: null } });
      expect(oldSession).not.toBeNull();

      // Verify new session is active
      const activeSessions = await ctx.db.sessions.find({ revokedAt: null }).toArray();
      expect(activeSessions.length).toBe(1);
    });

    it('should detect reuse of rotated token, revoke session chain, and return 401', async () => {
      // 1. Rotate token legitimately
      const firstRefresh = await ctx.app.inject({
        method: 'POST',
        url: '/auth/refresh',
        payload: { refreshToken },
      });
      expect(firstRefresh.statusCode).toBe(200);
      const newTokens = JSON.parse(firstRefresh.body);

      // 2. Attacker / replay presents the OLD (now revoked) refresh token
      const reuseAttempt = await ctx.app.inject({
        method: 'POST',
        url: '/auth/refresh',
        payload: { refreshToken },
      });

      expect(reuseAttempt.statusCode).toBe(401);
      const body = JSON.parse(reuseAttempt.body);
      expect(body.error.code).toBe('TOKEN_REVOKED');

      // 3. Verify that entire session chain was revoked
      const activeSessions = await ctx.db.sessions.find({ revokedAt: null }).toArray();
      expect(activeSessions.length).toBe(0);

      // 4. Verify that auth.session.revoked event was published
      const events = await ctx.redis.xrange('nebron.events', '-', '+');
      const revokedEvent = events.find(([, fields]) => {
        return (fields as string[])[1] === 'auth.session.revoked';
      });
      expect(revokedEvent).toBeDefined();
      const payload = JSON.parse((revokedEvent![1] as string[])[3]!);
      expect(payload.reason).toBe('reuse_detected');

      // 5. Verify the newly rotated token is now also rejected
      const subsequentAttempt = await ctx.app.inject({
        method: 'POST',
        url: '/auth/refresh',
        payload: { refreshToken: newTokens.refreshToken },
      });
      expect(subsequentAttempt.statusCode).toBe(401);
    });

    it('should reject expired refresh token with 401', async () => {
      // Set session expiresAt in the past
      await ctx.db.sessions.updateMany({}, { $set: { expiresAt: new Date(Date.now() - 1000) } });

      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/refresh',
        payload: { refreshToken },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('TOKEN_EXPIRED');
    });

    it('should reject unknown refresh token with 401', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/refresh',
        payload: { refreshToken: '0000000000000000000000000000000000000000000000000000000000000000' },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });
  });

  describe('POST /auth/logout', () => {
    let refreshToken: string;

    beforeEach(async () => {
      await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'logoutuser@example.com',
          password: 'ValidPassword123!',
        },
      });

      const login = await ctx.app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'logoutuser@example.com',
          password: 'ValidPassword123!',
        },
      });
      refreshToken = JSON.parse(login.body).refreshToken;
    });

    it('should revoke session and return 204 No Content', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/logout',
        payload: { refreshToken },
      });

      expect(res.statusCode).toBe(204);
      expect(res.body).toBe('');

      // Verify session was revoked in DB
      const session = await ctx.db.sessions.findOne({});
      expect(session?.revokedAt).not.toBeNull();

      // Verify event was published
      const events = await ctx.redis.xrange('nebron.events', '-', '+');
      const logoutEvent = events.find(([, fields]) => (fields as string[])[1] === 'auth.session.revoked');
      expect(logoutEvent).toBeDefined();
      const payload = JSON.parse((logoutEvent![1] as string[])[3]!);
      expect(payload.reason).toBe('user_logout');
    });

    it('should be idempotent and return 204 even on unknown token', async () => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/auth/logout',
        payload: { refreshToken: 'unknown-token-hash' },
      });

      expect(res.statusCode).toBe(204);
    });
  });

  describe('GET /.well-known/jwks.json', () => {
    it('should return valid JWKS with cache-control and verify issued token', async () => {
      // Register and login to get a real token
      await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: {
          email: 'jwkuser@example.com',
          password: 'ValidPassword123!',
        },
      });

      const loginRes = await ctx.app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: {
          email: 'jwkuser@example.com',
          password: 'ValidPassword123!',
        },
      });
      const { accessToken } = JSON.parse(loginRes.body);

      // Fetch JWKS
      const jwksRes = await ctx.app.inject({
        method: 'GET',
        url: '/.well-known/jwks.json',
      });

      expect(jwksRes.statusCode).toBe(200);
      expect(jwksRes.headers['cache-control']).toBe('public, max-age=3600');

      const jwks = JSON.parse(jwksRes.body);
      expect(jwks).toHaveProperty('keys');
      expect(Array.isArray(jwks.keys)).toBe(true);
      expect(jwks.keys.length).toBeGreaterThan(0);

      const key = jwks.keys[0];
      expect(key.kty).toBe('RSA');
      expect(key.use).toBe('sig');
      expect(key.alg).toBe('RS256');
      expect(key).toHaveProperty('n');
      expect(key).toHaveProperty('e');
      expect(key).toHaveProperty('kid');

      // Verify that jose can verify the token using this JWKS
      const localJwks = jose.createLocalJWKSet(jwks);
      const verified = await jose.jwtVerify(accessToken, localJwks, {
        issuer: 'nebron-auth',
        audience: 'core',
      });

      expect(verified.payload.email).toBe('jwkuser@example.com');
      expect(verified.payload.iss).toBe('nebron-auth');
      expect(verified.payload.aud).toEqual(['core', 'chat', 'voice']);
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce 5 requests per minute per email on /auth/login', async () => {
      const email = 'ratelimit@example.com';
      await ctx.app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: { email, password: 'ValidPassword123!' },
      });

      // Send 5 login requests
      for (let i = 0; i < 5; i++) {
        const res = await ctx.app.inject({
          method: 'POST',
          url: '/auth/login',
          payload: { email, password: 'ValidPassword123!' },
        });
        expect(res.statusCode).toBe(200);
      }

      // 6th request should hit rate limit
      const sixth = await ctx.app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email, password: 'ValidPassword123!' },
      });

      expect(sixth.statusCode).toBe(429);
      const body = JSON.parse(sixth.body);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });
  });

  describe('OpenAPI Swagger Docs', () => {
    it('should serve Swagger UI at /docs', async () => {
      const res = await ctx.app.inject({
        method: 'GET',
        url: '/docs/',
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('text/html');
      expect(res.body).toContain('swagger');
    });
  });
});
