import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import * as jose from 'jose';
import { InvalidTokenError, TokenExpiredError } from '../../lib/errors.js';

export interface AccessTokenPayload {
  sub: string;
  email: string;
  sid: string;
  iat?: number;
  exp?: number;
  iss?: string;
  aud?: string | string[];
}

export interface JWKEntry extends jose.JWK {
  kid: string;
  use: string;
  alg: string;
}

export interface JWKSResponse {
  keys: JWKEntry[];
}

type ImportedKey = Awaited<ReturnType<typeof jose.importPKCS8>>;

export class KeyManager {
  private privateKeyPath: string;
  private publicKeyPath: string;
  private currentKid: string;
  private isProduction: boolean;
  private extraKeysDir: string;

  private activePrivateKey!: ImportedKey;
  private activePublicKey!: ImportedKey;
  private activeKid!: string;
  private jwks: JWKSResponse = { keys: [] };
  private localKeySet!: ReturnType<typeof jose.createLocalJWKSet>;

  constructor(options: {
    privateKeyPath: string;
    publicKeyPath: string;
    currentKid: string;
    isProduction: boolean;
    extraKeysDir?: string;
  }) {
    this.privateKeyPath = options.privateKeyPath;
    this.publicKeyPath = options.publicKeyPath;
    this.currentKid = options.currentKid;
    this.isProduction = options.isProduction;
    this.extraKeysDir = options.extraKeysDir || path.join(path.dirname(options.privateKeyPath), 'keys');
  }

  async initialize(): Promise<void> {
    const privExists = fs.existsSync(this.privateKeyPath);
    const pubExists = fs.existsSync(this.publicKeyPath);

    if (!privExists || !pubExists) {
      if (this.isProduction) {
        throw new Error(
          `Production RSA keypair missing. Looked for private: ${this.privateKeyPath}, public: ${this.publicKeyPath}. Failing fast.`
        );
      }
      this.generateAndPersistDevKeys();
    }

    const privatePem = fs.readFileSync(this.privateKeyPath, 'utf-8');
    const publicPem = fs.readFileSync(this.publicKeyPath, 'utf-8');

    this.activePrivateKey = await jose.importPKCS8(privatePem, 'RS256');
    this.activePublicKey = await jose.importSPKI(publicPem, 'RS256');

    // Compute public key sha256 fingerprint
    const pubDer = crypto.createPublicKey(publicPem).export({ type: 'spki', format: 'der' });
    const fingerprint = crypto.createHash('sha256').update(pubDer).digest('hex');

    // Key ID (kid) is either currentKid from env or sha256 fingerprint
    this.activeKid = this.currentKid || fingerprint;

    const jwkMap = new Map<string, JWKEntry>();

    const activeJwk = (await jose.exportJWK(this.activePublicKey)) as JWKEntry;
    activeJwk.kid = this.activeKid;
    activeJwk.use = 'sig';
    activeJwk.alg = 'RS256';
    jwkMap.set(this.activeKid, activeJwk);

    // Support rotation: load all keys in ./secrets/keys/
    if (fs.existsSync(this.extraKeysDir)) {
      const files = fs.readdirSync(this.extraKeysDir);
      for (const file of files) {
        const fullPath = path.join(this.extraKeysDir, file);
        try {
          const stat = fs.statSync(fullPath);
          if (stat.isFile() && (file.endsWith('.pem') || file.endsWith('.pub') || file.endsWith('.key'))) {
            const extraPem = fs.readFileSync(fullPath, 'utf-8');
            if (extraPem.includes('PUBLIC KEY')) {
              const extraPubKey = await jose.importSPKI(extraPem, 'RS256');
              const extraDer = crypto.createPublicKey(extraPem).export({ type: 'spki', format: 'der' });
              const extraFp = crypto.createHash('sha256').update(extraDer).digest('hex');
              const extraKid = path.parse(file).name || extraFp;

              const extraJwk = (await jose.exportJWK(extraPubKey)) as JWKEntry;
              extraJwk.kid = extraKid;
              extraJwk.use = 'sig';
              extraJwk.alg = 'RS256';
              if (!jwkMap.has(extraKid)) {
                jwkMap.set(extraKid, extraJwk);
              }
            }
          }
        } catch {
          // Skip invalid key files in extraKeysDir
        }
      }
    }

    this.jwks = {
      keys: Array.from(jwkMap.values()),
    };

    this.localKeySet = jose.createLocalJWKSet(this.jwks);
  }

  private generateAndPersistDevKeys(): void {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const privDir = path.dirname(this.privateKeyPath);
    if (!fs.existsSync(privDir)) {
      fs.mkdirSync(privDir, { recursive: true });
    }

    const pubDir = path.dirname(this.publicKeyPath);
    if (!fs.existsSync(pubDir)) {
      fs.mkdirSync(pubDir, { recursive: true });
    }

    fs.writeFileSync(this.privateKeyPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(this.publicKeyPath, publicKey, { mode: 0o644 });
  }

  getActiveKid(): string {
    return this.activeKid;
  }

  getJwks(): JWKSResponse {
    return this.jwks;
  }

  async signAccessToken(
    claims: { userId: string; email: string; sessionId: string },
    expiresInSeconds: number = 900
  ): Promise<string> {
    return await new jose.SignJWT({
      sub: claims.userId,
      email: claims.email,
      sid: claims.sessionId,
    })
      .setProtectedHeader({ alg: 'RS256', kid: this.activeKid })
      .setIssuer('nebron-auth')
      .setAudience(['core', 'chat', 'voice'])
      .setIssuedAt()
      .setExpirationTime(`${expiresInSeconds}s`)
      .sign(this.activePrivateKey);
  }

  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    try {
      const { payload } = await jose.jwtVerify(token, this.localKeySet, {
        issuer: 'nebron-auth',
        algorithms: ['RS256'],
      });

      if (!payload.sub || typeof payload.sub !== 'string') {
        throw new InvalidTokenError('Token missing sub claim');
      }
      if (!payload.email || typeof payload.email !== 'string') {
        throw new InvalidTokenError('Token missing email claim');
      }
      if (!payload.sid || typeof payload.sid !== 'string') {
        throw new InvalidTokenError('Token missing sid claim');
      }

      return {
        sub: payload.sub,
        email: payload.email,
        sid: payload.sid,
        iat: payload.iat,
        exp: payload.exp,
        iss: payload.iss,
        aud: payload.aud,
      };
    } catch (err: unknown) {
      if (err instanceof InvalidTokenError) {
        throw err;
      }
      if (err instanceof jose.errors.JWTExpired) {
        throw new TokenExpiredError('Access token has expired');
      }
      throw new InvalidTokenError('Invalid or malformed token');
    }
  }
}
