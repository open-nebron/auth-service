import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createTestContext, TestContext } from './test-context.js';

describe('Auth Cookie Endpoints Unit/Component Tests', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext();
  });

  afterAll(async () => {
    await ctx.cleanup();
  });

  beforeEach(async () => {
    await ctx.resetData();
    // Pre-register user for cookie tests
    await ctx.app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: {
        email: 'webuser@nebron.com',
        password: 'ValidPassword123!',
      },
    });
  });

  // 1. POST /auth/login/cookie with valid credentials -> 200, body has accessToken, NO refreshToken, Set-Cookie header present with HttpOnly, SameSite=Lax, Path=/auth
  it('1. POST /auth/login/cookie with valid credentials returns 200, accessToken, no refreshToken, and Set-Cookie with HttpOnly, SameSite=Lax, Path=/auth', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login/cookie',
      payload: {
        email: 'webuser@nebron.com',
        password: 'ValidPassword123!',
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body).toHaveProperty('accessToken');
    expect(body).toHaveProperty('expiresIn');
    expect(body).not.toHaveProperty('refreshToken');

    const setCookie = res.headers['set-cookie'];
    expect(setCookie).toBeDefined();
    const cookieHeader = Array.isArray(setCookie) ? setCookie[0] : setCookie;
    expect(cookieHeader).toContain('refresh_token=');
    expect(cookieHeader).toContain('HttpOnly');
    expect(cookieHeader).toContain('SameSite=Lax');
    expect(cookieHeader).toContain('Path=/auth');
  });

  // 2. POST /auth/login/cookie with wrong password -> 401, no Set-Cookie
  it('2. POST /auth/login/cookie with wrong password returns 401 and no Set-Cookie', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login/cookie',
      payload: {
        email: 'webuser@nebron.com',
        password: 'WrongPassword123!',
      },
    });

    expect(res.statusCode).toBe(401);
    expect(res.headers['set-cookie']).toBeUndefined();
    const body = JSON.parse(res.body);
    expect(body.error.code).toBe('INVALID_CREDENTIALS');
  });

  // 3. POST /auth/refresh/cookie with valid cookie -> 200, body has new accessToken, Set-Cookie header present (rotated token differs)
  it('3. POST /auth/refresh/cookie with valid cookie returns 200, new accessToken, and rotated Set-Cookie', async () => {
    const loginRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login/cookie',
      payload: {
        email: 'webuser@nebron.com',
        password: 'ValidPassword123!',
      },
    });

    const loginSetCookie = loginRes.headers['set-cookie'] as string;
    const initialRefreshToken = loginSetCookie.split(';')[0]?.split('=')[1];
    const initialAccessToken = JSON.parse(loginRes.body).accessToken;

    const refreshRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/refresh/cookie',
      headers: {
        cookie: `refresh_token=${initialRefreshToken}`,
      },
    });

    expect(refreshRes.statusCode).toBe(200);
    const body = JSON.parse(refreshRes.body);
    expect(body).toHaveProperty('accessToken');
    expect(body).toHaveProperty('expiresIn');
    expect(body).not.toHaveProperty('refreshToken');
    expect(body.accessToken).not.toBe(initialAccessToken);

    const refreshSetCookie = refreshRes.headers['set-cookie'] as string;
    expect(refreshSetCookie).toBeDefined();
    const rotatedRefreshToken = refreshSetCookie.split(';')[0]?.split('=')[1];
    expect(rotatedRefreshToken).toBeDefined();
    expect(rotatedRefreshToken).not.toBe(initialRefreshToken);
    expect(refreshSetCookie).toContain('HttpOnly');
    expect(refreshSetCookie).toContain('SameSite=Lax');
    expect(refreshSetCookie).toContain('Path=/auth');
  });

  // 4. POST /auth/refresh/cookie with missing cookie -> 401
  it('4. POST /auth/refresh/cookie with missing cookie returns 401', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/refresh/cookie',
    });

    expect(res.statusCode).toBe(401);
    const body = JSON.parse(res.body);
    expect(body.error.code).toBe('missing_refresh_token');
  });

  // 5. POST /auth/refresh/cookie with revoked cookie (reuse detection) -> 401, cookie cleared in response
  it('5. POST /auth/refresh/cookie with revoked cookie triggers reuse detection, returns 401, and clears cookie', async () => {
    const loginRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login/cookie',
      payload: {
        email: 'webuser@nebron.com',
        password: 'ValidPassword123!',
      },
    });

    const initialToken = (loginRes.headers['set-cookie'] as string).split(';')[0]?.split('=')[1];

    // First refresh: rotates token and revokes initialToken
    const firstRefresh = await ctx.app.inject({
      method: 'POST',
      url: '/auth/refresh/cookie',
      headers: {
        cookie: `refresh_token=${initialToken}`,
      },
    });
    expect(firstRefresh.statusCode).toBe(200);

    // Reuse attempt: present the already-revoked initialToken
    const reuseRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/refresh/cookie',
      headers: {
        cookie: `refresh_token=${initialToken}`,
      },
    });

    expect(reuseRes.statusCode).toBe(401);
    const body = JSON.parse(reuseRes.body);
    expect(body.error.code).toBe('TOKEN_REVOKED');

    const clearCookieHeader = reuseRes.headers['set-cookie'] as string;
    expect(clearCookieHeader).toBeDefined();
    expect(clearCookieHeader).toContain('Max-Age=0');
  });

  // 6. POST /auth/logout/cookie with valid cookie -> 204, session revoked, Set-Cookie clears (Max-Age=0)
  it('6. POST /auth/logout/cookie with valid cookie returns 204, revokes session, and clears cookie (Max-Age=0)', async () => {
    const loginRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/login/cookie',
      payload: {
        email: 'webuser@nebron.com',
        password: 'ValidPassword123!',
      },
    });

    const token = (loginRes.headers['set-cookie'] as string).split(';')[0]?.split('=')[1];

    const logoutRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/logout/cookie',
      headers: {
        cookie: `refresh_token=${token}`,
      },
    });

    expect(logoutRes.statusCode).toBe(204);
    const clearCookieHeader = logoutRes.headers['set-cookie'] as string;
    expect(clearCookieHeader).toBeDefined();
    expect(clearCookieHeader).toContain('Max-Age=0');
    expect(clearCookieHeader).toContain('Path=/auth');

    // Verify session revoked in database
    const session = await ctx.db.sessions.findOne({});
    expect(session?.revokedAt).not.toBeNull();
  });
});
