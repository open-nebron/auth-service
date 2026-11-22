import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createTestContext, TestContext } from './test-context.js';

describe('Auth Cookie Integration Flow Tests', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext();
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  beforeEach(async () => {
    await ctx.resetData();
    // Register user for full flow test
    await ctx.app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'jaruser@nebron.com',
        password: 'ValidPassword123!',
      },
    });
  });

  function extractToken(setCookieHeader: string | string[] | undefined): string {
    if (!setCookieHeader) return '';
    const header = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader;
    const match = header?.match(/^refresh_token=([^;]+)/);
    return match ? match[1]! : '';
  }

  // 1. Full flow with cookie jar: login -> refresh -> refresh -> logout, verify access token changes on each refresh
  it('1. Full flow with cookie jar: login -> refresh -> refresh -> logout verifies access tokens change on each refresh', async () => {
    // Step 1: Login
    const loginRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login/cookie',
      payload: {
        email: 'jaruser@nebron.com',
        password: 'ValidPassword123!',
      },
    });

    expect(loginRes.statusCode).toBe(200);
    const token1 = extractToken(loginRes.headers['set-cookie']);
    expect(token1).toBeTruthy();
    const access1 = JSON.parse(loginRes.body).accessToken;
    expect(access1).toBeTruthy();

    // Verify /auth/me works with access1
    const me1 = await ctx.app.inject({
      method: 'GET',
      url: '/auth/me',
      headers: { authorization: `Bearer ${access1}` },
    });
    expect(me1.statusCode).toBe(200);
    expect(JSON.parse(me1.body).email).toBe('jaruser@nebron.com');

    // Step 2: First Refresh
    const refresh1Res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/refresh/cookie',
      headers: { cookie: `refresh_token=${token1}` },
    });

    expect(refresh1Res.statusCode).toBe(200);
    const token2 = extractToken(refresh1Res.headers['set-cookie']);
    expect(token2).toBeTruthy();
    expect(token2).not.toBe(token1);
    const access2 = JSON.parse(refresh1Res.body).accessToken;
    expect(access2).toBeTruthy();
    expect(access2).not.toBe(access1);

    // Verify /auth/me works with access2
    const me2 = await ctx.app.inject({
      method: 'GET',
      url: '/auth/me',
      headers: { authorization: `Bearer ${access2}` },
    });
    expect(me2.statusCode).toBe(200);

    // Step 3: Second Refresh
    const refresh2Res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/refresh/cookie',
      headers: { cookie: `refresh_token=${token2}` },
    });

    expect(refresh2Res.statusCode).toBe(200);
    const token3 = extractToken(refresh2Res.headers['set-cookie']);
    expect(token3).toBeTruthy();
    expect(token3).not.toBe(token2);
    const access3 = JSON.parse(refresh2Res.body).accessToken;
    expect(access3).toBeTruthy();
    expect(access3).not.toBe(access2);

    // Step 4: Logout
    const logoutRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/logout/cookie',
      headers: { cookie: `refresh_token=${token3}` },
    });

    expect(logoutRes.statusCode).toBe(204);
    const clearCookie = logoutRes.headers['set-cookie'] as string;
    expect(clearCookie).toContain('Max-Age=0');

    // Subsequent refresh with token3 should fail because it was revoked
    const postLogoutRefresh = await ctx.app.inject({
      method: 'POST',
      url: '/auth/refresh/cookie',
      headers: { cookie: `refresh_token=${token3}` },
    });
    expect(postLogoutRefresh.statusCode).toBe(401);
  });

  // 2. Reuse detection: login, refresh (get new cookie), try old cookie -> 401, session revoked, all cookies cleared
  it('2. Reuse detection: login, refresh, presenting old cookie returns 401, revokes session chain, and clears cookies', async () => {
    // Login
    const loginRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login/cookie',
      payload: {
        email: 'jaruser@nebron.com',
        password: 'ValidPassword123!',
      },
    });
    const oldCookieToken = extractToken(loginRes.headers['set-cookie']);

    // Legitimate refresh -> issues newCookieToken, revokes oldCookieToken
    const refreshRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/refresh/cookie',
      headers: { cookie: `refresh_token=${oldCookieToken}` },
    });
    expect(refreshRes.statusCode).toBe(200);
    const newCookieToken = extractToken(refreshRes.headers['set-cookie']);
    expect(newCookieToken).not.toBe(oldCookieToken);

    // Replay attack with oldCookieToken -> reuse detection triggered
    const replayRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/refresh/cookie',
      headers: { cookie: `refresh_token=${oldCookieToken}` },
    });

    expect(replayRes.statusCode).toBe(401);
    expect(JSON.parse(replayRes.body).error.code).toBe('TOKEN_REVOKED');
    expect(replayRes.headers['set-cookie']).toContain('Max-Age=0');

    // Verify all active sessions in the chain are revoked
    const activeSessions = await ctx.db.sessions.find({ revokedAt: null }).toArray();
    expect(activeSessions.length).toBe(0);

    // Subsequent refresh attempt with the newCookieToken is also rejected
    const newCookieAttempt = await ctx.app.inject({
      method: 'POST',
      url: '/auth/refresh/cookie',
      headers: { cookie: `refresh_token=${newCookieToken}` },
    });
    expect(newCookieAttempt.statusCode).toBe(401);
    expect(JSON.parse(newCookieAttempt.body).error.code).toBe('TOKEN_REVOKED');
  });
});
