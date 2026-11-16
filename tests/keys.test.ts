import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import * as jose from 'jose';
import { KeyManager } from '../src/modules/keys/key-manager.js';

describe('KeyManager Tests', () => {
  let tempDir: string;
  let privPath: string;
  let pubPath: string;
  let extraKeysDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zenuxs-key-test-'));
    privPath = path.join(tempDir, 'jwt_private.pem');
    pubPath = path.join(tempDir, 'jwt_public.pem');
    extraKeysDir = path.join(tempDir, 'keys');
    fs.mkdirSync(extraKeysDir, { recursive: true });
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('should auto-generate and persist 2048-bit RSA keys in development', async () => {
    const km = new KeyManager({
      privateKeyPath: privPath,
      publicKeyPath: pubPath,
      currentKid: 'dev-1',
      isProduction: false,
      extraKeysDir,
    });

    await km.initialize();

    expect(fs.existsSync(privPath)).toBe(true);
    expect(fs.existsSync(pubPath)).toBe(true);

    const privPem = fs.readFileSync(privPath, 'utf-8');
    const pubPem = fs.readFileSync(pubPath, 'utf-8');

    expect(privPem).toContain('BEGIN PRIVATE KEY');
    expect(pubPem).toContain('BEGIN PUBLIC KEY');

    expect(km.getActiveKid()).toBe('dev-1');
    const jwks = km.getJwks();
    expect(jwks.keys.length).toBe(1);
    expect(jwks.keys[0]?.kid).toBe('dev-1');
    expect(jwks.keys[0]?.kty).toBe('RSA');
  });

  it('should fail fast in production if keys are missing', async () => {
    const km = new KeyManager({
      privateKeyPath: privPath,
      publicKeyPath: pubPath,
      currentKid: 'prod-1',
      isProduction: true,
      extraKeysDir,
    });

    await expect(km.initialize()).rejects.toThrow(/Production RSA keypair missing.*Failing fast/);
  });

  it('should load rotated keys from keys directory and verify tokens signed with older keys', async () => {
    // Generate an older keypair in extraKeysDir
    const oldKeypair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const oldPubPath = path.join(extraKeysDir, 'old-key-1.pem');
    fs.writeFileSync(oldPubPath, oldKeypair.publicKey);

    // Initialize KeyManager with active key
    const km = new KeyManager({
      privateKeyPath: privPath,
      publicKeyPath: pubPath,
      currentKid: 'active-key',
      isProduction: false,
      extraKeysDir,
    });
    await km.initialize();

    const jwks = km.getJwks();
    // Should have active key + rotated key
    expect(jwks.keys.length).toBe(2);
    const kids = jwks.keys.map((k) => k.kid);
    expect(kids).toContain('active-key');
    expect(kids).toContain('old-key-1');

    // Sign a token using the old private key
    const oldPrivKey = await jose.importPKCS8(oldKeypair.privateKey, 'RS256');
    const oldToken = await new jose.SignJWT({
      sub: 'user-rotated',
      email: 'user@zenuxs.com',
      sid: 'sess-rotated',
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'old-key-1' })
      .setIssuer('zenuxs-auth')
      .setAudience(['core', 'chat', 'voice'])
      .setIssuedAt()
      .setExpirationTime('15m')
      .sign(oldPrivKey);

    // KeyManager should verify this token because the old public key is in the JWKS!
    const verified = await km.verifyAccessToken(oldToken);
    expect(verified.sub).toBe('user-rotated');
    expect(verified.email).toBe('user@zenuxs.com');
  });
});
