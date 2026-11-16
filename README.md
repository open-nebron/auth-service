# auth-service

Production-grade authentication microservice for the **Zenuxs** polyrepo ecosystem.

`auth-service` serves as the **sole token issuer** in the ecosystem. All other services (`core-api`, `chat-service`, `voice-service`) verify access tokens independently via asymmetric cryptography using this service's JSON Web Key Set (JWKS).

---

## Architecture & System Boundaries

```
                    +--------------------+
                    |    auth-service    |
                    | (Sole Token Issuer)|
                    +---------+----------+
                              |
       +----------------------+----------------------+
       |                      |                      |
JWKS (RS256)           JWKS (RS256)           JWKS (RS256)
       v                      v                      v
+--------------+      +---------------+      +---------------+
|   core-api   |      |  chat-service |      | voice-service |
| (Own MongoDB)|      |  (ScyllaDB)   |      | (LiveKit CP)  |
+--------------+      +---------------+      +---------------+
       ^                      ^                      ^
       |                      |                      |
       +----------------------+----------------------+
                              |
              Async Events: Redis Stream (`zenuxs.events`)
              - auth.user.registered
              - auth.session.revoked
```

- **Database Ownership**: Owns the `zenuxs_auth` database in MongoDB. No other service reads or writes to this database directly.
- **Sole Token Issuer**: Asymmetrically issues RS256 JWT access tokens.
- **Token Verification**: Sibling services verify access tokens via `GET /.well-known/jwks.json`. Sibling services never call `auth-service` synchronously for verification.
- **Decoupled Asynchronous Events**: Publishes lifecycle events (`auth.user.registered`, `auth.session.revoked`) to Redis Streams (`zenuxs.events`).
- **No Synchronous Coupling**: Does not proxy other services or synchronously call `core-api`.

---

## Tech Stack

- **Runtime & Language**: Node.js 20, TypeScript in strict mode
- **Web Framework**: Fastify v5 (lightweight, high throughput)
- **Database**: MongoDB 7 via the official `mongodb` driver (no ORM)
- **Cache & Storage**: Redis 7 via `ioredis` (session refresh token hashes, rate limiting, and event stream)
- **Password Hashing**: Argon2id via `argon2` with constant-time verification & dummy hashing
- **JWT & Cryptography**: `jose` (RS256 asymmetric signatures, JWKS export and validation)
- **Request Validation**: `zod`
- **Logging**: `pino` with automatic redaction of passwords, tokens, and hashes
- **Testing**: `vitest` (in-memory MongoDB & Redis for deterministic integration tests)
- **API Documentation**: OpenAPI 3.1 served via Swagger UI at `/docs`

---

## Data Model (MongoDB, db: `zenuxs_auth`)

### Collection: `users`
```typescript
interface UserDocument {
  _id: ObjectId;
  email: string;            // unique, lowercased, trimmed
  passwordHash: string;     // argon2id
  emailVerified: boolean;   // default: false
  status: 'active' | 'disabled';
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
}
```

### Collection: `sessions`
```typescript
interface SessionDocument {
  _id: ObjectId;
  userId: ObjectId;
  familyId: ObjectId;       // session chain family for reuse detection
  refreshTokenHash: string; // sha256 hash of opaque token
  userAgent: string | null;
  ip: string | null;
  expiresAt: Date;          // TTL index (expireAfterSeconds: 0)
  createdAt: Date;
  revokedAt: Date | null;
}
```

### Indexes
- `users.email`: unique index
- `sessions.refreshTokenHash`: unique index
- `sessions.expiresAt`: TTL index (`expireAfterSeconds: 0`)
- `sessions.userId`: standard index
- `sessions.familyId`: standard index

---

## Security Features

1. **Argon2id Hashing & Timing Protection**:
   - Password hashes use Argon2id.
   - When a user is not found during login or registration, a pre-warmed dummy hash is verified in constant time to prevent timing enumeration attacks.
2. **Password Policy**:
   - Minimum 12 characters, maximum 128 characters (DoS protection).
   - Must contain at least one letter and at least one number.
3. **Session Token Rotation & Reuse Detection**:
   - Refresh tokens are 32-byte opaque random hex strings.
   - Only SHA-256 hashes are stored in the database.
   - On every refresh, the presented token is revoked and a new pair is issued.
   - **Reuse Detection**: If an already-revoked refresh token is presented, the entire session chain is immediately revoked and an `auth.session.revoked` (`reason: "reuse_detected"`) event is published.
4. **Rate Limiting (backed by Redis)**:
   - `POST /auth/login`: 10 requests/min per IP **and** 5 requests/min per email (whichever threshold hits first).
   - `POST /auth/register`: 5 requests/hour per IP.
   - `POST /auth/refresh`: 30 requests/min per IP.
5. **Security Headers & Boundaries**:
   - Helmet headers via `@fastify/helmet`.
   - Strict CORS origin whitelisting via `@fastify/cors`.
   - Body limit enforced at 16 KB.
   - Proxy trust enabled (`trustProxy: true`) for accurate `X-Forwarded-For` rate limiting.
   - Zero sensitive logging: passwords, tokens, and hashes are redacted from Pino logs.
   - Standardized error format: `{ error: { code, message } }` with no stack traces or PII.

---

## Asynchronous Events (Redis Streams)

Stream Key: `zenuxs.events`

### 1. `auth.user.registered`
Published upon successful user registration.
```json
{
  "type": "auth.user.registered",
  "payload": {
    "userId": "67389a0123456789abcdef01",
    "email": "user@zenuxs.com",
    "createdAt": "2026-11-16T18:00:00.000Z"
  }
}
```

### 2. `auth.session.revoked`
Published when a session is revoked (user logout or reuse detection).
```json
{
  "type": "auth.session.revoked",
  "payload": {
    "userId": "67389a0123456789abcdef01",
    "sessionId": "67389a0123456789abcdef02",
    "reason": "user_logout" // or "reuse_detected"
  }
}
```

---

## Configuration Reference

All settings are configured via environment variables and validated at startup using Zod:

| Variable | Type | Default | Description |
|---|---|---|---|
| `PORT` | number | `4001` | HTTP port to listen on |
| `NODE_ENV` | string | `development` | Environment (`development`, `production`, `test`) |
| `LOG_LEVEL` | string | `info` | Pino logging level (`trace`, `debug`, `info`, `warn`, `error`) |
| `MONGO_URL` | string | `mongodb://mongo:27017/zenuxs_auth` | MongoDB connection URI |
| `REDIS_URL` | string | `redis://redis:6379` | Redis connection URI |
| `JWT_PRIVATE_KEY_PATH` | string | `./secrets/jwt_private.pem` | Path to RSA private key (PEM PKCS#8) |
| `JWT_PUBLIC_KEY_PATH` | string | `./secrets/jwt_public.pem` | Path to RSA public key (PEM SPKI) |
| `JWT_CURRENT_KID` | string | `dev-1` | Active Key ID (`kid`) in JWT header |
| `ACCESS_TOKEN_TTL_SECONDS` | number | `900` | Access token lifespan (15 minutes) |
| `REFRESH_TOKEN_TTL_DAYS` | number | `30` | Refresh token lifespan (30 days) |
| `ALLOWED_ORIGINS` | string | `http://localhost:3000,http://localhost:8081` | Comma-delimited list of allowed CORS origins |

> [!NOTE]
> In `development` mode, if RSA keys are missing from `JWT_PRIVATE_KEY_PATH` and `JWT_PUBLIC_KEY_PATH`, a 2048-bit RSA keypair will be automatically generated and persisted to disk. In `production`, the service fails fast if keys are not present. Key rotation is supported by placing older public keys in `./secrets/keys/`.

---

## Getting Started

### Prerequisites
- Node.js 20+
- Docker & Docker Compose

### 1. Local Development
```bash
# Install dependencies
npm install

# Start development server with live reload
make dev
```

### 2. Run Tests
```bash
# Run Vitest integration test suite
make test
```

### 3. Build Production Artifacts
```bash
# Compile TypeScript to dist/
make build
```

### 4. Run with Docker Compose
```bash
# Start MongoDB, Redis, and auth-service
make docker-up
# Or directly:
docker compose up -d

# Check health
curl http://localhost:4001/health
```

---

## API Endpoints & Curl Examples

### 1. Health Check
```bash
curl -i http://localhost:4001/health
```
**Response (200 OK):**
```json
{
  "status": "ok",
  "db": "ok",
  "redis": "ok"
}
```

---

### 2. Register User
Registers a new user account. No tokens are issued at registration.

```bash
curl -i -X POST http://localhost:4001/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "developer@zenuxs.com",
    "password": "SuperSecretPassword123!"
  }'
```
**Response (200 OK):**
```json
{
  "userId": "67389a0123456789abcdef01"
}
```

---

### 3. Login
Authenticates credentials, creates a session, and issues tokens.

```bash
curl -i -X POST http://localhost:4001/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "developer@zenuxs.com",
    "password": "SuperSecretPassword123!"
  }'
```
**Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRldi0xIn0...",
  "refreshToken": "3a7b9c1d2e3f405162738495a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f",
  "expiresIn": 900
}
```

---

### 4. Get Current User (`/auth/me`)
Retrieves the authenticated user claims from the RS256 Bearer access token.

```bash
curl -i http://localhost:4001/auth/me \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```
**Response (200 OK):**
```json
{
  "userId": "67389a0123456789abcdef01",
  "email": "developer@zenuxs.com",
  "sessionId": "67389a0123456789abcdef02"
}
```

---

### 5. Refresh Access Token
Rotates the refresh token and issues a new access token.

```bash
curl -i -X POST http://localhost:4001/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "3a7b9c1d2e3f405162738495a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f"
  }'
```
**Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRldi0xIn0...",
  "refreshToken": "8f7e6d5c4b3a201918273645a4b3c2d1e0f9a8b7c6d5e4f302192a3b4c5d6e7f",
  "expiresIn": 900
}
```

---

### 6. Logout
Revokes the session associated with the provided refresh token.

```bash
curl -i -X POST http://localhost:4001/auth/logout \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "8f7e6d5c4b3a201918273645a4b3c2d1e0f9a8b7c6d5e4f302192a3b4c5d6e7f"
  }'
```
**Response (204 No Content):**
```
HTTP/1.1 204 No Content
```

---

### 7. Get JWKS (`/.well-known/jwks.json`)
Public JSON Web Key Set used by verifier microservices (`core-api`, `chat-service`, `voice-service`).

```bash
curl -i http://localhost:4001/.well-known/jwks.json
```
**Response (200 OK):**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "n": "u1wE7...",
      "e": "AQAB",
      "kid": "dev-1",
      "use": "sig",
      "alg": "RS256"
    }
  ]
}
```

---

### 8. Swagger UI Documentation
Open `http://localhost:4001/docs` in your browser to interact with the OpenAPI 3.1 specification.

---

## Verifying Tokens in Sibling Services (`core-api`, `chat-service`, `voice-service`)

Sibling services should not query `auth-service` synchronously to verify tokens. Instead, verify tokens using `jose` with remote JWKS caching:

```typescript
import * as jose from 'jose';

// Create a cached remote JWKS instance (refreshes automatically)
const JWKS = jose.createRemoteJWKSet(
  new URL('http://auth-service:4001/.well-known/jwks.json')
);

export async function verifyToken(jwt: string) {
  const { payload } = await jose.jwtVerify(jwt, JWKS, {
    issuer: 'zenuxs-auth',
    audience: 'core', // 'chat' or 'voice'
    algorithms: ['RS256'],
  });

  return {
    userId: payload.sub,
    email: payload.email,
    sessionId: payload.sid,
  };
}
```

---

## License
MIT
