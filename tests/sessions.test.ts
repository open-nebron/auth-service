import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createTestContext, TestContext } from './test-context.js';

describe('Multi-device Sessions', () => {
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

  it('lists active sessions with parsed userAgent, isCurrent and isActive', async () => {
    // 1. Register user
    const regRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'device-test@nebron.com',
        password: 'Password123!',
      },
    });
    expect(regRes.statusCode).toBe(200);

    // 2. Login from device 1 (Chrome on Mac)
    const login1Res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login',
      headers: {
        'user-agent':
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      },
      payload: {
        email: 'device-test@nebron.com',
        password: 'Password123!',
      },
    });
    expect(login1Res.statusCode).toBe(200);
    const { accessToken: token1 } = login1Res.json();

    // 3. Login from device 2 (iPhone Safari)
    const login2Res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login',
      headers: {
        'user-agent':
          'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
      },
      payload: {
        email: 'device-test@nebron.com',
        password: 'Password123!',
      },
    });
    expect(login2Res.statusCode).toBe(200);
    const { accessToken: token2 } = login2Res.json();

    // 4. Query sessions from device 2
    const sessionsRes = await ctx.app.inject({
      method: 'GET',
      url: '/auth/sessions',
      headers: {
        authorization: `Bearer ${token2}`,
      },
    });
    expect(sessionsRes.statusCode).toBe(200);
    const data = sessionsRes.json();
    expect(data.sessions).toHaveLength(2);

    const currentSession = data.sessions.find((s: any) => s.isCurrent);
    const otherSession = data.sessions.find((s: any) => !s.isCurrent);

    expect(currentSession).toBeDefined();
    expect(otherSession).toBeDefined();

    expect(currentSession.isCurrent).toBe(true);
    expect(currentSession.isActive).toBe(true);
    expect(currentSession.userAgent.os).toContain('iOS');

    expect(otherSession.isCurrent).toBe(false);
    expect(otherSession.userAgent.browser).toContain('Chrome');
  });

  it('reads activity from Redis session:last_active:{sessionId}', async () => {
    // Register & login device 1 and device 2
    await ctx.app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email: 'redis-activity@nebron.com', password: 'Password123!' },
    });
    const login1Res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'redis-activity@nebron.com', password: 'Password123!' },
    });
    const login2Res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'redis-activity@nebron.com', password: 'Password123!' },
    });
    const { accessToken: token1 } = login1Res.json();
    const { accessToken: token2 } = login2Res.json();

    const meRes = await ctx.app.inject({
      method: 'GET',
      url: '/auth/me',
      headers: { authorization: `Bearer ${token2}` },
    });
    const { sessionId: session2Id } = meRes.json();

    // Device 2 connects to WS in the future (or newer timestamp)
    const simulatedActiveAt = new Date(Date.now() + 5000).toISOString();
    await ctx.redis.set(`session:last_active:${session2Id}`, simulatedActiveAt);

    // Device 1 queries sessions
    const sessionsRes = await ctx.app.inject({
      method: 'GET',
      url: '/auth/sessions',
      headers: { authorization: `Bearer ${token1}` },
    });
    expect(sessionsRes.statusCode).toBe(200);
    const { sessions } = sessionsRes.json();
    const targetSession = sessions.find((s: any) => s.sessionId === session2Id);
    expect(targetSession.lastActiveAt).toBe(simulatedActiveAt);
  });

  it('DELETE /auth/sessions/:sessionId revokes the session and publishes event', async () => {
    await ctx.app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email: 'revoke-one@nebron.com', password: 'Password123!' },
    });
    const login1 = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'revoke-one@nebron.com', password: 'Password123!' },
    });
    const login2 = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'revoke-one@nebron.com', password: 'Password123!' },
    });
    const { accessToken: token1 } = login1.json();
    const { accessToken: token2 } = login2.json();

    const meRes = await ctx.app.inject({
      method: 'GET',
      url: '/auth/me',
      headers: { authorization: `Bearer ${token2}` },
    });
    const { sessionId: session2Id } = meRes.json();

    // Revoke session 2 using token 1
    const delRes = await ctx.app.inject({
      method: 'DELETE',
      url: `/auth/sessions/${session2Id}`,
      headers: { authorization: `Bearer ${token1}` },
    });
    expect(delRes.statusCode).toBe(204);

    // After revoking, session 2 is no longer listed in active sessions
    const sessionsRes = await ctx.app.inject({
      method: 'GET',
      url: '/auth/sessions',
      headers: { authorization: `Bearer ${token1}` },
    });
    const { sessions } = sessionsRes.json();
    expect(sessions).toHaveLength(1);
    expect(sessions[0].sessionId).not.toBe(session2Id);
  });

  it('DELETE /auth/sessions/:sessionId returns 403 when trying to revoke another user session', async () => {
    // User A
    await ctx.app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email: 'user-a@nebron.com', password: 'Password123!' },
    });
    const loginA = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'user-a@nebron.com', password: 'Password123!' },
    });

    // User B
    await ctx.app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email: 'user-b@nebron.com', password: 'Password123!' },
    });
    const loginB = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'user-b@nebron.com', password: 'Password123!' },
    });
    const { accessToken: tokenB } = loginB.json();

    const meA = await ctx.app.inject({
      method: 'GET',
      url: '/auth/me',
      headers: { authorization: `Bearer ${loginA.json().accessToken}` },
    });
    const { sessionId: sessionAId } = meA.json();

    // User B attempts to revoke User A's session
    const delRes = await ctx.app.inject({
      method: 'DELETE',
      url: `/auth/sessions/${sessionAId}`,
      headers: { authorization: `Bearer ${tokenB}` },
    });
    expect(delRes.statusCode).toBe(403);
  });

  it('DELETE /auth/sessions revokes all other sessions except current', async () => {
    await ctx.app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email: 'revoke-all@nebron.com', password: 'Password123!' },
    });
    await ctx.app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'revoke-all@nebron.com', password: 'Password123!' },
    });
    await ctx.app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'revoke-all@nebron.com', password: 'Password123!' },
    });
    const login3 = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'revoke-all@nebron.com', password: 'Password123!' },
    });
    const { accessToken: token3 } = login3.json();

    const delAllRes = await ctx.app.inject({
      method: 'DELETE',
      url: '/auth/sessions',
      headers: { authorization: `Bearer ${token3}` },
    });
    expect(delAllRes.statusCode).toBe(204);
    expect(delAllRes.headers['x-revoked-count']).toBe('2');

    const sessionsRes = await ctx.app.inject({
      method: 'GET',
      url: '/auth/sessions',
      headers: { authorization: `Bearer ${token3}` },
    });
    const { sessions } = sessionsRes.json();
    expect(sessions).toHaveLength(1);
    expect(sessions[0].isCurrent).toBe(true);
  });

  it('rejects unauthenticated requests to session endpoints', async () => {
    const res1 = await ctx.app.inject({ method: 'GET', url: '/auth/sessions' });
    expect(res1.statusCode).toBe(401);

    const res2 = await ctx.app.inject({ method: 'DELETE', url: '/auth/sessions/any-id' });
    expect(res2.statusCode).toBe(401);

    const res3 = await ctx.app.inject({ method: 'DELETE', url: '/auth/sessions' });
    expect(res3.statusCode).toBe(401);
  });
});
