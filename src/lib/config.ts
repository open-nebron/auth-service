import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
  PORT: z.coerce.number().int().positive().default(4001),
  MONGO_URL: z.string().min(1, 'MONGO_URL is required'),
  REDIS_URL: z.string().min(1, 'REDIS_URL is required'),
  JWT_PRIVATE_KEY_PATH: z.string().default('./secrets/jwt_private.pem'),
  JWT_PUBLIC_KEY_PATH: z.string().default('./secrets/jwt_public.pem'),
  JWT_CURRENT_KID: z.string().default('dev-1'),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(900),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().positive().default(30),
  ALLOWED_ORIGINS: z.string().default('http://localhost:3000,http://localhost:8081'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  LOG_LEVEL: z.string().default('info'),
});

export type Config = z.infer<typeof envSchema>;

export function loadConfig(overrides?: Partial<Record<string, unknown>>): Config {
  const envData = { ...process.env, ...overrides };
  const result = envSchema.safeParse(envData);
  if (!result.success) {
    const errorDetails = result.error.issues
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join(', ');
    throw new Error(`Invalid configuration: ${errorDetails}`);
  }
  return result.data;
}
